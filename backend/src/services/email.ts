import { db } from '../db/index.js'
import { users } from '../db/schema.js'
import { eq } from 'drizzle-orm'
import { env } from '../lib/env.js'
import { getConfig } from '../lib/config.js'
import { emitToAdmins } from '../socket/index.js'
import { retryWithBackoff, escapeHtml } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { CircuitBreaker } from '../lib/circuitBreaker.js'

// ─── Header helpers ───────────────────────────────────────────────────────────

function encodeHeaderValue(str: string): string {
  const sanitized = str.replace(/[\x00-\x1F\x7F\r\n]/g, '')
  if (/^[\x20-\x7E]*$/.test(sanitized)) return sanitized
  return `=?UTF-8?B?${Buffer.from(sanitized, 'utf-8').toString('base64')}?=`
}

function sanitizeDisplayName(name: string): string {
  return name.replace(/[\r\n\x00]/g, '').replace(/[<>"]/g, '').trim().slice(0, 100)
}

function formatEmailAddress(email: string, name: string): string {
  const sanitized = sanitizeDisplayName(name)
  if (!sanitized) return email
  return `"${encodeHeaderValue(sanitized)}" <${email}>`
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EmailParams {
  type: 'accountApproved' | 'accountRejected' | 'accountSuspended' | 'newMessage' | 'passwordReset' | 'passwordResetAdmin' | 'conversationClosed'
  userId: string
  reason?: string
  messageCount?: number
  resetToken?: string
  tempPassword?: string
  closingNote?: string
}

type EmailProvider = 'brevo' | 'mailpit'

// ─── Circuit breaker — lazy init so getConfig() is never called at import time ─

let _brevoCircuitBreaker: CircuitBreaker | null = null

function getBrevoCircuitBreaker(): CircuitBreaker {
  if (!_brevoCircuitBreaker) {
    const cb = getConfig().storage.circuitBreaker
    _brevoCircuitBreaker = new CircuitBreaker({
      name: 'Email-Brevo',
      failureThreshold: cb.failureThreshold,
      recoveryTimeoutMs: cb.recoveryTimeoutMs,
      onStateChange: (state, failures) => {
        if (state === 'OPEN') {
          emitToAdmins('email:circuit_opened', {
            provider: 'brevo' as EmailProvider,
            state,
            failures,
            timestamp: Date.now()
          })
        }
      }
    })
  }
  return _brevoCircuitBreaker
}

// ─── Public entry point ───────────────────────────────────────────────────────

/**
 * Send a transactional email immediately.
 * Queuing / debouncing / retries are handled by emailQueue.ts — do not add
 * another queue layer here.
 *
 * Routing:
 *   Development  →  Mailpit (local SMTP catch-all, port 1025)
 *   Production   →  Brevo REST API
 */
export async function sendEmail(params: EmailParams): Promise<void> {
  return sendEmailInternal(params)
}

// ─── Email content builder ────────────────────────────────────────────────────

async function sendEmailInternal(params: EmailParams): Promise<void> {
  const user = await db.query.users.findFirst({
    where: eq(users.id, params.userId),
    columns: { email: true, name: true }
  })

  if (!user) throw new Error(`User not found: ${params.userId}`)

  const appUrl  = env.appUrl
  const appName = env.appName

  let subject: string
  let htmlContent: string

  switch (params.type) {
    case 'accountApproved':
      subject = `Welcome to ${appName} - Account Approved`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">Your account has been approved!</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>Great news! Your account has been approved and you can now start using ${escapeHtml(appName)}.</p>
          <p style="margin: 30px 0;">
            <a href="${appUrl}/login" style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Login Now</a>
          </p>
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    case 'accountRejected':
      subject = `${appName} - Account Application Update`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">Account Application Update</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>We're unable to approve your account at this time.</p>
          ${params.reason ? `<p><strong>Reason:</strong> ${escapeHtml(params.reason)}</p>` : ''}
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    case 'accountSuspended':
      subject = `${appName} - Account Suspended`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #dc2626;">Account Suspended</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>Your account has been suspended.</p>
          ${params.reason ? `<p><strong>Reason:</strong> ${escapeHtml(params.reason)}</p>` : ''}
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    case 'conversationClosed':
      subject = `${appName} - Your support conversation has been closed`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">Your conversation has been closed</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>The support team has closed your conversation.</p>
          ${params.closingNote ? `
          <div style="background: #f9fafb; border-left: 4px solid #d1d5db; padding: 12px 16px; margin: 16px 0; border-radius: 4px;">
            <p style="margin: 0; color: #374151;"><strong>Note from the team:</strong><br>${escapeHtml(params.closingNote)}</p>
          </div>` : ''}
          <p style="margin: 30px 0;">
            <a href="${appUrl}/home/chat" style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Go to Chat</a>
          </p>
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    case 'newMessage': {
      const messageText = params.messageCount === 1
        ? 'You have 1 new message'
        : `You have ${params.messageCount} new messages`

      subject = `New message from ${appName}`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">${messageText}</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>${messageText} waiting for you.</p>
          <p style="margin: 30px 0;">
            <a href="${appUrl}/messages" style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">View Messages</a>
          </p>
          <hr style="margin: 24px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #666; font-size: 12px;">
            Don't want these emails?
            <a href="${appUrl}/settings" style="color: #666;">Update your preferences</a>
          </p>
        </div>
      `
      break
    }

    case 'passwordReset':
      if (!params.resetToken) throw new Error('Reset token missing')
      subject = `${appName} - Reset Your Password`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">Reset your password</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>We received a request to reset your password.</p>
          <p style="margin: 30px 0;">
            <a href="${appUrl}/reset-password?token=${encodeURIComponent(params.resetToken)}" style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
          </p>
          <p>If you did not request this, you can safely ignore this email.</p>
          <p>This link will expire in 30 minutes.</p>
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    case 'passwordResetAdmin':
      if (!params.tempPassword) throw new Error('Temporary password missing')
      subject = `${appName} - Temporary Password`
      htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #1a1a1a;">Your temporary password</h2>
          <p>Hi ${escapeHtml(user.name)},</p>
          <p>An administrator has reset your password. Your temporary password:</p>
          <div style="background: #f5f5f5; padding: 16px; border-radius: 6px; margin: 20px 0; font-family: monospace; font-size: 18px; letter-spacing: 1px; text-align: center;">
            ${escapeHtml(params.tempPassword)}
          </div>
          <p style="margin: 30px 0;">
            <a href="${appUrl}/login" style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Login Now</a>
          </p>
          <p><strong>Important:</strong> Please change your password immediately after logging in.</p>
          <p>Best regards,<br>${escapeHtml(appName)} Team</p>
        </div>
      `
      break

    default:
      throw new Error(`Unknown email type: ${(params as EmailParams).type}`)
  }

  if (env.isProd) {
    await sendWithBrevo(user.email, user.name, subject!, htmlContent!)
  } else {
    await sendWithMailpit(user.email, user.name, subject!, htmlContent!)
  }
}

// ─── Brevo (production) ───────────────────────────────────────────────────────

async function sendWithBrevo(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  // Both are validated as required in env.ts for production, but guard here
  // to satisfy TypeScript and catch any misconfiguration at runtime.
  const apiKey      = env.brevoApiKey
  const senderEmail = env.brevoSenderEmail
  if (!apiKey || !senderEmail) {
    throw new Error(
      'Brevo is not configured: BREVO_API_KEY and BREVO_SENDER_EMAIL are required in production'
    )
  }

  const timeoutMs = getConfig().email.queue?.sendTimeoutMs ?? 8000

  try {
    await getBrevoCircuitBreaker().execute(() =>
      retryWithBackoff(async () => {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), timeoutMs)

        try {
          const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            signal: controller.signal,
            headers: {
              'accept': 'application/json',
              'api-key': apiKey,
              'content-type': 'application/json'
            },
            body: JSON.stringify({
              sender: { name: env.brevoSenderName || env.appName, email: senderEmail },
              to: [{ email, name }],
              subject,
              htmlContent
            })
          })

          if (!response.ok) {
            const body = await response.text()
            throw new Error(`Brevo API error ${response.status}: ${body}`)
          }
        } finally {
          clearTimeout(timer)
        }
      }, 3, 1000)
    )

    logger.info({ provider: 'brevo', recipient: email }, 'Email sent via Brevo')
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error'
    logger.error({ provider: 'brevo', recipient: email, error: errorMsg }, 'Brevo email failed')

    emitToAdmins('email:send_failed', {
      provider: 'brevo' as EmailProvider,
      recipient: email,
      error: errorMsg,
      timestamp: Date.now()
    })

    throw new Error(`Failed to send email via Brevo to ${email}: ${errorMsg}`)
  }
}

// ─── Mailpit (development) ────────────────────────────────────────────────────

interface SmtpTransporter { sendMail: (opts: Record<string, unknown>) => Promise<unknown> }
let _mailpitTransporter: SmtpTransporter | null = null

async function getMailpitTransporter(): Promise<SmtpTransporter> {
  if (_mailpitTransporter) return _mailpitTransporter
  // Dynamic import keeps nodemailer out of the production bundle
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodemailer = await import('nodemailer')
  const transporter = nodemailer.createTransport({
    host: env.mailpitHost,
    port: env.mailpitPort,
    secure: false,    // Mailpit never uses TLS
    auth: undefined,  // Mailpit requires no credentials
    connectionTimeout: 5000,
    socketTimeout: 5000
  }) as unknown as SmtpTransporter
  _mailpitTransporter = transporter
  return transporter
}

async function sendWithMailpit(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  try {
    const transporter = await getMailpitTransporter()
    const hostname   = new URL(env.appUrl).hostname
    const from = formatEmailAddress(`noreply@${hostname}`, env.appName)
    const to   = formatEmailAddress(email, name)

    await transporter.sendMail({ from, to, subject, html: htmlContent })

    logger.info(
      { provider: 'mailpit', host: env.mailpitHost, port: env.mailpitPort, recipient: email },
      'Email sent via Mailpit — view at http://localhost:8025'
    )
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error'
    logger.error(
      { provider: 'mailpit', recipient: email, error: errorMsg },
      'Mailpit email failed — is Mailpit running? docker run -p 1025:1025 -p 8025:8025 axllent/mailpit'
    )
    throw error
  }
}
