import { db } from '../db/index.js'
import { users } from '../db/schema.js'
import { eq } from 'drizzle-orm'
import { env } from '../lib/env.js'
import { getConfig, getBrand } from '../lib/config.js'
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

function formatAddress(email: string, name: string): string {
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

export type EmailProvider = 'brevo' | 'gmail'

// ─── Circuit breakers — lazy init, one per provider ───────────────────────────

let _brevoCircuitBreaker: CircuitBreaker | null = null
let _gmailCircuitBreaker: CircuitBreaker | null = null

function getBrevoCircuitBreaker(): CircuitBreaker {
  if (!_brevoCircuitBreaker) {
    const cb = getConfig().storage.circuitBreaker
    _brevoCircuitBreaker = new CircuitBreaker({
      name: 'Email-Brevo',
      failureThreshold: cb.failureThreshold,
      recoveryTimeoutMs: cb.recoveryTimeoutMs,
      onStateChange: (state, failures) => {
        if (state === 'OPEN') emitToAdmins('email:circuit_opened', { provider: 'brevo', state, failures, timestamp: Date.now() })
      }
    })
  }
  return _brevoCircuitBreaker
}

function getGmailCircuitBreaker(): CircuitBreaker {
  if (!_gmailCircuitBreaker) {
    const cb = getConfig().storage.circuitBreaker
    _gmailCircuitBreaker = new CircuitBreaker({
      name: 'Email-Gmail',
      failureThreshold: cb.failureThreshold,
      recoveryTimeoutMs: cb.recoveryTimeoutMs,
      onStateChange: (state, failures) => {
        if (state === 'OPEN') emitToAdmins('email:circuit_opened', { provider: 'gmail', state, failures, timestamp: Date.now() })
      }
    })
  }
  return _gmailCircuitBreaker
}

// ─── Gmail SMTP transporter — singleton, lazy init ────────────────────────────

interface SmtpTransporter { sendMail: (opts: Record<string, unknown>) => Promise<unknown> }
let _gmailTransporter: SmtpTransporter | null = null

async function getGmailTransporter(): Promise<SmtpTransporter> {
  if (_gmailTransporter) return _gmailTransporter
  // Dynamic import keeps nodemailer tree-shaken from any bundle that doesn't need it
  const nodemailer = await import('nodemailer')
  _gmailTransporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,   // STARTTLS upgrade after connect
    auth: { user: env.gmailUser, pass: env.gmailAppPassword?.replace(/\s/g, '') },
    connectionTimeout: 5000,
    socketTimeout: 10000,
  }) as unknown as SmtpTransporter
  return _gmailTransporter
}

// ─── Provider list — parsed once per process ──────────────────────────────────

let _providers: EmailProvider[] | null = null

function getProviders(): EmailProvider[] {
  if (_providers) return _providers
  const raw = env.emailProvider.trim().toLowerCase()
  if (raw === 'none') { _providers = []; return _providers }
  _providers = raw.split(',').map(p => p.trim()).filter((p): p is EmailProvider => p === 'brevo' || p === 'gmail')
  return _providers
}

// ─── Public entry point ───────────────────────────────────────────────────────

export async function sendEmail(params: EmailParams): Promise<void> {
  return sendEmailInternal(params)
}

function buildEmailTemplate(title: string, userGreeting: string, bodyHtml: string) {
  const brand = getBrand()
  const appUrl = env.appUrl
  const logoUrl = brand.logoUrl
  
  // Clean, high-contrast text header fallback that won't break in Outlook/Gmail
  const headerContent = logoUrl 
    ? `<img src="${escapeHtml(logoUrl)}" alt="${escapeHtml(brand.siteName)}" style="height: 48px; display: block; margin: 0 auto;">`
    : `<span style="font-size: 28px; font-weight: 800; color: #008069; letter-spacing: -0.5px;">${escapeHtml(brand.siteName)}</span>`

  const year = new Date().getFullYear()
  const companyName = escapeHtml(brand.company || brand.siteName)

  // #f5f7fa is a very subtle icy white-blue background
  // The card has a firm 4px #008069 border top to give it a premium branded feel
  return `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="x-apple-disable-message-reformatting">
  <!--[if mso]>
    <xml>
      <o:OfficeDocumentSettings>
        <o:PixelsPerInch>96</o:PixelsPerInch>
      </o:OfficeDocumentSettings>
    </xml>
  <![endif]-->
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    body, table, td, p, a, h1, h2, h3, h4, h5, h6, span {
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f7fa; -webkit-font-smoothing: antialiased;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f7fa; margin: 0; padding: 40px 20px;">
    <tr>
      <td align="center">
        <!-- Main Card -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 580px; background-color: #ffffff; border-radius: 12px; border-top: 4px solid #008069; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.05); margin: 0 auto;">
          
          <!-- Header -->
          <tr>
            <td style="padding: 40px 40px 20px; text-align: center; background: #ffffff;">
              ${headerContent}
            </td>
          </tr>
          
          <!-- Body -->
          <tr>
            <td style="padding: 20px 40px 40px;">
              <h2 style="color: #0f172a; font-size: 22px; font-weight: 700; margin: 0 0 24px 0; letter-spacing: -0.3px;">${title}</h2>
              <p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6; font-weight: 400;">Hi ${escapeHtml(userGreeting)},</p>
              ${bodyHtml}
            </td>
          </tr>
          
        </table>
        
        <!-- Outer Footer -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 580px; margin: 0 auto;">
          <tr>
            <td style="padding: 30px 20px; text-align: center;">
              <p style="margin: 0 0 12px 0; font-size: 13px; color: #64748b; font-weight: 400;">&copy; ${year} ${companyName}. All rights reserved.</p>
              <p style="margin: 0; font-size: 13px;">
                <a href="${appUrl}/settings" style="color: #008069; text-decoration: none; font-weight: 500;">Update email preferences</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
}

async function sendEmailInternal(params: EmailParams): Promise<void> {
  const providers = getProviders()

  if (providers.length === 0) {
    logger.debug({ type: params.type }, 'EMAIL_PROVIDER=none — skipping send')
    return
  }

  const user = await db.query.users.findFirst({
    where: eq(users.id, params.userId),
    columns: { email: true, name: true }
  })
  if (!user) throw new Error(`User not found: ${params.userId}`)

  const appUrl  = env.appUrl
  const appName = env.appName
  // Robust, fully-supported button technique mimicking a premium pill style with the EXACT WhatsApp Green
  const primaryBtn = `display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px; text-align: center;`

  let subject: string
  let htmlContent: string

  switch (params.type) {
    case 'accountApproved':
      subject = `Welcome to ${appName} - Account Approved`
      htmlContent = buildEmailTemplate(
        `Your account has been approved! 🎉`,
        user.name,
        `<p style="margin: 0 0 32px 0; font-size: 16px; color: #334155; line-height: 1.6;">Great news! Your account has been securely verified and approved. You can now access your dashboard and start using ${escapeHtml(appName)}.</p>
        <div style="text-align: left; margin: 32px 0;">
          <a href="${appUrl}/login" style="${primaryBtn}">Go to Dashboard</a>
        </div>
        <p style="margin: 0; font-size: 15px; color: #64748b; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #475569;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'accountRejected':
      subject = `${appName} - Account Application Update`
      htmlContent = buildEmailTemplate(
        `Account Application Update`,
        user.name,
        `<p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6;">We have reviewed your application, but unfortunately, we are unable to approve your account at this time.</p>
        ${params.reason ? `<div style="background: #fff1f2; border: 1px solid #fda4af; padding: 20px; border-radius: 8px; margin: 24px 0;"><p style="margin: 0; color: #e11d48; font-size: 15px; font-weight: 600;">Message from reviewer:<br><span style="display:inline-block; margin-top: 6px; font-weight: 400; color: #be123c;">${escapeHtml(params.reason)}</span></p></div>` : ''}
        <p style="margin: 32px 0 0; font-size: 15px; color: #64748b; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #475569;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'accountSuspended':
      subject = `${appName} - Account Suspended`
      htmlContent = buildEmailTemplate(
        `<span style="color: #e11d48;">Account Suspended</span>`,
        user.name,
        `<p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6;">Your account access has been temporarily restricted to protect our community and ensure compliance with our platform policies.</p>
        ${params.reason ? `<div style="background: #fff1f2; border: 1px solid #fda4af; padding: 20px; border-radius: 8px; margin: 24px 0;"><p style="margin: 0; color: #e11d48; font-size: 15px; font-weight: 600;">Reason for suspension:<br><span style="display:inline-block; margin-top: 6px; font-weight: 400; color: #be123c;">${escapeHtml(params.reason)}</span></p></div>` : ''}
        <p style="margin: 32px 0 0; font-size: 15px; color: #64748b; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #475569;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'conversationClosed':
      subject = `${appName} - Your support conversation has been closed`
      htmlContent = buildEmailTemplate(
        `Your conversation has been closed`,
        user.name,
        `<p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6;">Our support team has successfully resolved and closed your recent conversation.</p>
        ${params.closingNote ? `<div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin: 24px 0;"><p style="margin: 0; color: #475569; font-size: 15px; font-weight: 600;">Note from the team:<br><span style="display:inline-block; margin-top: 6px; font-weight: 400; color: #334155;">${escapeHtml(params.closingNote)}</span></p></div>` : ''}
        <div style="text-align: left; margin: 32px 0;">
          <a href="${appUrl}/home/chat" style="${primaryBtn}">Return to Chat</a>
        </div>
        <p style="margin: 0; font-size: 15px; color: #64748b; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #475569;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'newMessage': {
      const messageText = params.messageCount === 1
        ? 'You have 1 new message'
        : `You have ${params.messageCount} new messages`
      subject = `New message from ${appName}`
      htmlContent = buildEmailTemplate(
        messageText,
        user.name,
        `<p style="margin: 0 0 32px 0; font-size: 16px; color: #334155; line-height: 1.6;">You have ${params.messageCount === 1 ? 'a new message' : 'new messages'} waiting for you in your dashboard.</p>
        <div style="text-align: left; margin: 32px 0;">
          <a href="${appUrl}/messages" style="${primaryBtn}">View Message Securely</a>
        </div>
        <p style="margin: 0; font-size: 15px; color: #64748b; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #475569;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break
    }

    case 'passwordReset':
      if (!params.resetToken) throw new Error('Reset token missing')
      subject = `${appName} - Reset Your Password`
      htmlContent = buildEmailTemplate(
        `Reset your password`,
        user.name,
        `<p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6;">We received a security request to reset your password. If you initiated this request, please click the secure link below to choose a new password.</p>
        <div style="text-align: left; margin: 32px 0;">
          <a href="${appUrl}/reset-password?token=${encodeURIComponent(params.resetToken)}" style="${primaryBtn}">Reset Password</a>
        </div>
        <div style="margin: 32px 0 0; border-top: 1px solid #e2e8f0; padding-top: 24px;">
          <p style="margin: 0 0 8px 0; font-size: 14px; color: #64748b; font-weight: 500;">If you did not request this, you can safely ignore this email. Your account remains secure.</p>
          <p style="margin: 0; font-size: 14px; color: #94a3b8;">For your safety, this link will expire in 30 minutes.</p>
        </div>`
      )
      break

    case 'passwordResetAdmin':
      if (!params.tempPassword) throw new Error('Temporary password missing')
      subject = `${appName} - Temporary Password`
      htmlContent = buildEmailTemplate(
        `Your temporary password`,
        user.name,
        `<p style="margin: 0 0 24px 0; font-size: 16px; color: #334155; line-height: 1.6;">An administrator has securely reset your password. Please use the temporary credentials below to log in.</p>
        <div style="background-color: #f8fafc; padding: 24px; border-radius: 8px; margin: 32px 0; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 24px; font-weight: 700; letter-spacing: 4px; text-align: center; color: #0f172a; border: 1px dashed #cbd5e1;">
          ${escapeHtml(params.tempPassword)}
        </div>
        <div style="text-align: left; margin: 32px 0;">
          <a href="${appUrl}/login" style="${primaryBtn}">Login Now</a>
        </div>
        <div style="background: #fff1f2; padding: 16px; border-radius: 8px; border-left: 4px solid #e11d48; margin-top: 32px;">
          <p style="margin: 0; font-size: 14px; color: #be123c; font-weight: 600;">Security Notice: Please immediately change your password in the Settings area upon successfully logging in.</p>
        </div>`
      )
      break

    default:
      throw new Error(`Unknown email type: ${(params as EmailParams).type}`)
  }

  // Try each configured provider in order. First success wins.
  let lastError: Error | null = null
  for (const provider of providers) {
    try {
      if (provider === 'brevo') {
        await sendWithBrevo(user.email, user.name, subject!, htmlContent!)
      } else {
        await sendWithGmail(user.email, user.name, subject!, htmlContent!)
      }
      return
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err))
      if (providers.length > 1) {
        logger.warn({ provider, error: lastError.message }, 'Email provider failed — trying next')
      }
    }
  }

  throw lastError ?? new Error('All configured email providers failed')
}

// ─── Brevo REST API ───────────────────────────────────────────────────────────

async function sendWithBrevo(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  const apiKey      = env.brevoApiKey!
  const senderEmail = env.brevoSenderEmail!
  const senderName  = env.brevoSenderName || env.appName
  const timeoutMs   = getConfig().email.queue?.sendTimeoutMs ?? 8000

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
              sender: { name: senderName, email: senderEmail },
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
    emitToAdmins('email:send_failed', { provider: 'brevo', recipient: email, error: errorMsg, timestamp: Date.now() })
    throw new Error(`Brevo failed: ${errorMsg}`)
  }
}

// ─── Gmail SMTP ───────────────────────────────────────────────────────────────

async function sendWithGmail(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  const senderName = env.brevoSenderName || env.appName  // same display name across providers

  try {
    await getGmailCircuitBreaker().execute(() =>
      retryWithBackoff(async () => {
        const transporter = await getGmailTransporter()
        await transporter.sendMail({
          from: formatAddress(env.gmailUser!, senderName),
          to: formatAddress(email, name),
          subject,
          html: htmlContent,
        })
      }, 3, 1000)
    )

    logger.info({ provider: 'gmail', recipient: email }, 'Email sent via Gmail SMTP')
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error'
    logger.error({ provider: 'gmail', recipient: email, error: errorMsg }, 'Gmail SMTP email failed')
    emitToAdmins('email:send_failed', { provider: 'gmail', recipient: email, error: errorMsg, timestamp: Date.now() })
    throw new Error(`Gmail failed: ${errorMsg}`)
  }
}

// ─── Health export ────────────────────────────────────────────────────────────

export function getEmailProviderStatus(): { providers: EmailProvider[]; brevo: string; gmail: string } {
  return {
    providers: getProviders(),
    brevo: _brevoCircuitBreaker?.getState().state ?? 'unconfigured',
    gmail: _gmailCircuitBreaker?.getState().state ?? 'unconfigured',
  }
}
