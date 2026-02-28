import { db } from '../db/index.js'
import { users } from '../db/schema.js'
import { eq } from 'drizzle-orm'
import { env } from '../lib/env.js'
import { getConfig } from '../lib/config.js'
import { emitToAdmins } from '../socket/index.js'
import { retryWithBackoff, escapeHtml } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { CircuitBreaker } from '../lib/circuitBreaker.js'

interface EmailParams {
  type: 'accountApproved' | 'accountRejected' | 'accountSuspended' | 'newMessage' | 'passwordReset'
  userId: string
  reason?: string
  messageCount?: number
  resetToken?: string
}

type EmailProvider = 'brevo' | 'smtp' | 'resend'

interface EmailResult {
  success: boolean
  provider: EmailProvider
  error?: string
}

const DEFAULT_MAX_QUEUE_SIZE = 1000
/** Email timeout capped at 8 seconds to prevent long hangs */
const EMAIL_TIMEOUT_MS = 8000

const emailQueue: Array<{ params: EmailParams; resolve: () => void; reject: (err: Error) => void }> = []
let isProcessingQueue = false

const providerCircuitBreakers: Record<EmailProvider, CircuitBreaker> = {
  brevo: new CircuitBreaker({
    name: 'Email-Brevo',
    failureThreshold: getConfig().storage.circuitBreaker.failureThreshold,
    recoveryTimeoutMs: getConfig().storage.circuitBreaker.recoveryTimeoutMs,
    onStateChange: (state, failures) => {
      if (state === 'OPEN') {
        emitToAdmins('email:provider_circuit_opened', {
          provider: 'brevo',
          state,
          failures,
          timestamp: Date.now()
        })
      }
    }
  }),
  smtp: new CircuitBreaker({
    name: 'Email-SMTP',
    failureThreshold: getConfig().storage.circuitBreaker.failureThreshold,
    recoveryTimeoutMs: getConfig().storage.circuitBreaker.recoveryTimeoutMs,
    onStateChange: (state, failures) => {
      if (state === 'OPEN') {
        emitToAdmins('email:provider_circuit_opened', {
          provider: 'smtp',
          state,
          failures,
          timestamp: Date.now()
        })
      }
    }
  }),
  resend: new CircuitBreaker({
    name: 'Email-Resend',
    failureThreshold: getConfig().storage.circuitBreaker.failureThreshold,
    recoveryTimeoutMs: getConfig().storage.circuitBreaker.recoveryTimeoutMs,
    onStateChange: (state, failures) => {
      if (state === 'OPEN') {
        emitToAdmins('email:provider_circuit_opened', {
          provider: 'resend',
          state,
          failures,
          timestamp: Date.now()
        })
      }
    }
  })
}

async function withProviderCircuitBreaker<T>(provider: EmailProvider, operation: () => Promise<T>): Promise<T> {
  return providerCircuitBreakers[provider].execute(operation)
}

function getMaxQueueSize(): number {
  return getConfig().cache?.maxEmailQueueSize ?? DEFAULT_MAX_QUEUE_SIZE
}

function queueEmail(params: EmailParams): Promise<void> {
  return new Promise((resolve, reject) => {
    const maxQueueSize = getMaxQueueSize()
    if (emailQueue.length >= maxQueueSize) {
      logger.warn({ queueSize: emailQueue.length, maxQueueSize }, 'Email queue full, rejecting')
      reject(new Error('Email queue is full'))
      return
    }
    emailQueue.push({ params, resolve, reject })
    processQueue()
  })
}

async function processQueue(): Promise<void> {
  if (isProcessingQueue || emailQueue.length === 0) return

  isProcessingQueue = true

  try {
    while (emailQueue.length > 0) {
      const item = emailQueue.shift()
      if (!item) break

      try {
        await sendEmailInternal(item.params)
        item.resolve()
      } catch (error) {
        item.reject(error instanceof Error ? error : new Error('Email failed'))
      }
    }
  } finally {
    isProcessingQueue = false
  }
}

export async function sendEmail(params: EmailParams): Promise<void> {
  if (env.isDev && !env.smtpHost) {
    logger.info({ type: params.type, userId: params.userId }, 'Email skipped (dev mode)')
    return
  }

  return queueEmail(params)
}

async function sendEmailInternal(params: EmailParams): Promise<void> {
  const user = await db.query.users.findFirst({
    where: eq(users.id, params.userId),
    columns: { email: true, name: true }
  })

  if (!user) {
    throw new Error('User not found')
  }

  const appUrl = env.appUrl
  const appName = env.appName

  let subject: string
  let htmlContent: string

  // ─── Shared email shell ───────────────────────────────────────────────────
  // Inline-only CSS: required for Gmail, Outlook, and Apple Mail compatibility.
  // Brand palette: primary #008069 (WhatsApp green), bg #f0f2f5, text #1a1a2e
  const emailShell = (accentColor: string, iconHtml: string, heading: string, bodyHtml: string, footerHtml = '') => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>${escapeHtml(appName)}</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased;">
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color:#f0f2f5;padding:40px 16px;">
    <tr>
      <td align="center">
        <!-- Card -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="max-width:560px;">

          <!-- Logo header -->
          <tr>
            <td style="background-color:${accentColor};border-radius:12px 12px 0 0;padding:28px 36px;text-align:center;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center">
                <tr>
                  <td style="vertical-align:middle;padding-right:10px;">${iconHtml}</td>
                  <td style="vertical-align:middle;">
                    <span style="font-size:20px;font-weight:700;color:#ffffff;letter-spacing:-0.3px;">${escapeHtml(appName)}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body card -->
          <tr>
            <td style="background-color:#ffffff;border-radius:0 0 12px 12px;padding:36px 40px 32px;border:1px solid #e4e7eb;border-top:none;">
              <h1 style="margin:0 0 20px;font-size:22px;font-weight:700;color:#111827;line-height:1.3;">${heading}</h1>
              ${bodyHtml}
              ${footerHtml ? `<hr style="margin:28px 0;border:none;border-top:1px solid #e4e7eb;">
              <p style="margin:0;font-size:12px;color:#9ca3af;line-height:1.6;">${footerHtml}</p>` : ''}
            </td>
          </tr>

          <!-- Bottom spacer + legal -->
          <tr>
            <td style="padding:20px 0 0;text-align:center;">
              <p style="margin:0;font-size:12px;color:#9ca3af;">© ${new Date().getFullYear()} ${escapeHtml(appName)}. All rights reserved.</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`

  const ctaButton = (href: string, label: string, color = '#008069') =>
    `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0;">
      <tr>
        <td style="border-radius:8px;background-color:${color};">
          <a href="${href}" target="_blank" style="display:inline-block;padding:13px 28px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px;letter-spacing:0.1px;">${label}</a>
        </td>
      </tr>
    </table>`

  const bodyText = (text: string) =>
    `<p style="margin:0 0 14px;font-size:15px;color:#374151;line-height:1.7;">${text}</p>`

  const reasonPill = (reason: string, color: string) =>
    `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:16px 0;">
      <tr>
        <td style="background-color:${color}14;border-left:3px solid ${color};border-radius:0 6px 6px 0;padding:12px 16px;">
          <p style="margin:0;font-size:14px;color:#374151;line-height:1.6;"><strong style="color:${color};">Reason:</strong> ${escapeHtml(reason)}</p>
        </td>
      </tr>
    </table>`

  // Real app logo — exact paths from LeafLogo.tsx, inlined for email client compatibility
  const leafIcon = (color = '#ffffff') =>
    `<svg viewBox="1 1 21 32" width="36" height="36" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg" aria-label="EV Leaf Logo">
      <path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z" />
      <path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12" />
      <text x="11.5" y="32" text-anchor="middle" font-size="10" font-weight="900" fill="${color}" stroke="none">EV</text>
    </svg>`

  // ── 1. Account Approved ───────────────────────────────────────────────────
  switch (params.type) {
    case 'accountApproved':
      subject = `Welcome to ${appName} — Your account is approved!`
      htmlContent = emailShell(
        '#008069',
        leafIcon(),
        `Welcome aboard, ${escapeHtml(user.name)}! 🎉`,
        bodyText(`Your account has been reviewed and <strong>approved</strong>. You're all set to start using ${escapeHtml(appName)} — log in now to get started.`) +
        ctaButton(`${appUrl}/login`, 'Log In to Your Account') +
        bodyText(`If you have any questions, feel free to reach out to our support team. We're happy to help.`),
        `You're receiving this email because you registered for ${escapeHtml(appName)}.`
      )
      break

    // ── 2. Account Rejected ───────────────────────────────────────────────
    case 'accountRejected':
      subject = `${appName} — Account Application Update`
      htmlContent = emailShell(
        '#dc2626',
        `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" stroke="#ffffff" stroke-width="2"/><path d="M12 8v4M12 16h.01" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/></svg>`,
        'Application Update',
        bodyText(`Hi ${escapeHtml(user.name)},`) +
        bodyText(`Thank you for your interest in ${escapeHtml(appName)}. After reviewing your application, we're unable to approve your account at this time.`) +
        (params.reason ? reasonPill(params.reason, '#dc2626') : '') +
        bodyText(`If you believe this decision was made in error or have additional questions, please don't hesitate to contact us — we'll be happy to discuss further.`),
        `You're receiving this email because you applied for an account on ${escapeHtml(appName)}.`
      )
      break

    // ── 3. Account Suspended ──────────────────────────────────────────────
    case 'accountSuspended':
      subject = `${appName} — Account Suspended`
      htmlContent = emailShell(
        '#b45309',
        `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 9v4M12 17h.01" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/></svg>`,
        'Your account has been suspended',
        bodyText(`Hi ${escapeHtml(user.name)},`) +
        bodyText(`We're writing to let you know that your ${escapeHtml(appName)} account has been temporarily suspended.`) +
        (params.reason ? reasonPill(params.reason, '#b45309') : '') +
        bodyText(`If you believe this was a mistake or would like to appeal this decision, please contact our support team and we'll review your case.`),
        `You're receiving this email because you have an account on ${escapeHtml(appName)}.`
      )
      break

    // ── 4. New Message ────────────────────────────────────────────────────
    case 'newMessage': {
      const count = params.messageCount ?? 1
      const messageText = count === 1 ? 'You have 1 new message' : `You have ${count} new messages`
      subject = `${messageText} on ${appName}`
      htmlContent = emailShell(
        '#008069',
        `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
        messageText,
        bodyText(`Hi ${escapeHtml(user.name)},`) +
        bodyText(`You ${count === 1 ? 'have a new message' : `have ${count} unread messages`} waiting for you on ${escapeHtml(appName)}. Click below to view and reply.`) +
        ctaButton(`${appUrl}/messages`, count === 1 ? 'View Message' : `View ${count} Messages`) +
        bodyText(`Stay on top of your conversations and respond promptly — we're here for you.`),
        `Don't want these notifications? <a href="${appUrl}/settings" style="color:#008069;text-decoration:underline;">Update your preferences</a> to manage your email settings.`
      )
      break
    }

    // ── 5. Password Reset ─────────────────────────────────────────────────
    case 'passwordReset':
      if (!params.resetToken) {
        throw new Error('Reset token missing')
      }
      subject = `${appName} — Reset Your Password`
      htmlContent = emailShell(
        '#1d4ed8',
        `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="#ffffff" stroke-width="2"/><path d="M7 11V7a5 5 0 0110 0v4" stroke="#ffffff" stroke-width="2" stroke-linecap="round"/></svg>`,
        'Reset your password',
        bodyText(`Hi ${escapeHtml(user.name)},`) +
        bodyText(`We received a request to reset the password for your ${escapeHtml(appName)} account. If you made this request, click the button below to set a new password.`) +
        ctaButton(`${appUrl}/reset-password?token=${params.resetToken}`, 'Reset My Password', '#1d4ed8') +
        `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:20px 0;">
          <tr>
            <td style="background-color:#f3f4f6;border-radius:8px;padding:14px 16px;">
              <p style="margin:0;font-size:13px;color:#6b7280;line-height:1.6;">⏱ This link will expire in <strong style="color:#374151;">1 hour</strong>. If you didn't request a password reset, you can safely ignore this email — your account is secure.</p>
            </td>
          </tr>
        </table>`,
        `For security reasons, never share this link with anyone. ${escapeHtml(appName)} will never ask for your password via email.`
      )
      break
  }

  const results: EmailResult[] = []

  if (env.isProd && env.brevoApiKey) {
    try {
      await withProviderCircuitBreaker('brevo', () => retryWithBackoff(async () => {
        await sendWithBrevo(user.email, user.name, subject, htmlContent)
      }, 3, 1000))
      results.push({ success: true, provider: 'brevo' })
      logger.info({ provider: 'brevo', type: params.type, userId: params.userId }, 'Email sent')
      return
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      results.push({ success: false, provider: 'brevo', error: errorMsg })
      logger.warn({ provider: 'brevo', error: errorMsg, userId: params.userId }, 'Email failed')

      emitToAdmins('email:provider_failed', {
        provider: 'brevo',
        recipient: user.email,
        error: errorMsg,
        timestamp: Date.now()
      })
    }
  }

  if (env.smtpHost && env.smtpPort) {
    try {
      await withProviderCircuitBreaker('smtp', () => retryWithBackoff(async () => {
        await sendWithSMTP(user.email, user.name, subject, htmlContent)
      }, 2, 500))
      results.push({ success: true, provider: 'smtp' })
      logger.info({ provider: 'smtp', type: params.type, userId: params.userId }, 'Email sent')
      return
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      results.push({ success: false, provider: 'smtp', error: errorMsg })

      emitToAdmins('email:provider_failed', {
        provider: 'smtp',
        recipient: user.email,
        error: errorMsg,
        timestamp: Date.now()
      })
    }
  }

  if (env.resendApiKey) {
    try {
      await withProviderCircuitBreaker('resend', () => retryWithBackoff(async () => {
        await sendWithResend(user.email, user.name, subject, htmlContent)
      }, 2, 500))
      results.push({ success: true, provider: 'resend' })
      logger.info({ provider: 'resend', type: params.type, userId: params.userId }, 'Email sent')
      return
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      results.push({ success: false, provider: 'resend', error: errorMsg })

      emitToAdmins('email:provider_failed', {
        provider: 'resend',
        recipient: user.email,
        error: errorMsg,
        timestamp: Date.now()
      })
    }
  }

  if (env.isDev) {
    logger.debug({ type: params.type, userId: params.userId, email: user.email }, 'Email (dev mode)')
    return
  }

  const failureSummary = {
    recipient: user.email,
    type: params.type,
    results,
    timestamp: Date.now()
  }

  logger.error(failureSummary, 'All email providers failed')
  emitToAdmins('email:all_providers_failed', failureSummary)

  throw new Error(`All email providers failed for ${user.email}`)
}

async function sendWithBrevo(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), EMAIL_TIMEOUT_MS)

  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'accept': 'application/json',
        'api-key': env.brevoApiKey!,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: {
          name: env.brevoSenderName || env.appName,
          email: env.brevoSenderEmail
        },
        to: [{ email, name }],
        subject,
        htmlContent
      })
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Brevo API error: ${error}`)
    }
  } finally {
    clearTimeout(timeout)
  }
}

interface SmtpTransporter { sendMail: (opts: Record<string, unknown>) => Promise<unknown> }
let cachedSmtpTransporter: SmtpTransporter | null = null

async function getSmtpTransporter(): Promise<SmtpTransporter> {
  if (cachedSmtpTransporter) return cachedSmtpTransporter
  const nodemailer = await import('nodemailer')
  cachedSmtpTransporter = nodemailer.createTransport({
    host: env.smtpHost,
    port: env.smtpPort,
    secure: env.smtpPort === 465,
    connectionTimeout: EMAIL_TIMEOUT_MS,
    socketTimeout: EMAIL_TIMEOUT_MS
  })
  return cachedSmtpTransporter
}

async function sendWithSMTP(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  const transporter = await getSmtpTransporter()
  const senderEmail = env.smtpSenderEmail || env.brevoSenderEmail || `noreply@${new URL(env.appUrl).hostname}`
  await transporter.sendMail({
    from: `"${env.appName}" <${senderEmail}>`,
    to: `"${name}" <${email}>`,
    subject,
    html: htmlContent
  })
}

async function sendWithResend(
  email: string,
  name: string,
  subject: string,
  htmlContent: string
): Promise<void> {
  const fromDomain = new URL(env.appUrl).hostname

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), EMAIL_TIMEOUT_MS)

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Authorization': `Bearer ${env.resendApiKey!}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: `${env.appName} <noreply@${fromDomain}>`,
        to: [`${name} <${email}>`],
        subject,
        html: htmlContent
      })
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Resend API error: ${error}`)
    }
  } finally {
    clearTimeout(timeout)
  }
}