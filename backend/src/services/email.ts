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
  type: 'accountApproved' | 'accountRejected' | 'accountSuspended' | 'newMessage' | 'adminNewMessage' | 'passwordReset' | 'passwordResetAdmin' | 'conversationClosed'
  userId: string
  reason?: string
  messageCount?: number
  resetToken?: string
  tempPassword?: string
  closingNote?: string
  conversationCount?: number
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
        else if (state === 'HALF_OPEN') emitToAdmins('email:circuit_recovery', { provider: 'brevo', state, failures, timestamp: Date.now() })
        else if (state === 'CLOSED') emitToAdmins('email:circuit_closed', { provider: 'brevo', state, failures, timestamp: Date.now() })
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
        else if (state === 'HALF_OPEN') emitToAdmins('email:circuit_recovery', { provider: 'gmail', state, failures, timestamp: Date.now() })
        else if (state === 'CLOSED') emitToAdmins('email:circuit_closed', { provider: 'gmail', state, failures, timestamp: Date.now() })
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

function buildEmailTemplate(title: string, userGreeting: string, bodyHtml: string, iconEmoji?: string) {
  const brand = getBrand()
  const appUrl = env.appUrl
  const logoUrl = brand.logoUrl
  const siteName = escapeHtml(brand.siteName)
  const year = new Date().getFullYear()
  const companyName = escapeHtml(brand.company || brand.siteName)
  const supportEmail = escapeHtml(brand.supportEmail || '')

  const headerContent = logoUrl
    ? `<img src="${escapeHtml(logoUrl)}" alt="${siteName}" style="height: 48px; display: block; margin: 0 auto;" />`
    : `<span style="font-size: 26px; font-weight: 800; color: #ffffff; letter-spacing: -0.5px;">${siteName}</span>`

  const iconRow = iconEmoji
    ? `<tr><td style="padding: 0 40px 0; text-align: center;"><div style="width: 64px; height: 64px; background: rgba(255,255,255,0.15); border-radius: 50%; display: inline-block; line-height: 64px; font-size: 30px;">${iconEmoji}</div></td></tr>`
    : ''

  return `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="color-scheme" content="light">
  <meta name="supported-color-schemes" content="light">
  <!--[if mso]>
    <xml>
      <o:OfficeDocumentSettings>
        <o:PixelsPerInch>96</o:PixelsPerInch>
      </o:OfficeDocumentSettings>
    </xml>
  <![endif]-->
  <style>
    @media only screen and (max-width: 600px) {
      .email-container { width: 100% !important; }
      .email-padding { padding: 24px 20px !important; }
      .email-header { padding: 32px 20px 16px !important; }
      .email-body { padding: 16px 20px 32px !important; }
      .email-btn { display: block !important; text-align: center !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f0f2f5; -webkit-font-smoothing: antialiased; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <!-- Preview text (hidden) -->
  <div style="display:none; max-height:0; overflow:hidden; mso-hide:all;">${title}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div>

  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f0f2f5;" role="presentation">
    <tr>
      <td align="center" style="padding: 40px 16px;">
        <!-- Main Card -->
        <table class="email-container" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width: 560px; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 2px 16px rgba(0,0,0,0.08);" role="presentation">

          <!-- Green Gradient Header -->
          <tr>
            <td class="email-header" style="padding: 40px 40px 24px; text-align: center; background: linear-gradient(135deg, #00a884 0%, #008069 50%, #006655 100%);">
              <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
                ${iconRow}
                <tr>
                  <td style="padding-top: 16px; text-align: center;">
                    ${headerContent}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td class="email-body" style="padding: 32px 40px 40px;">
              <h2 style="color: #0f172a; font-size: 22px; font-weight: 700; margin: 0 0 8px 0; letter-spacing: -0.3px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">${title}</h2>
              <p style="margin: 0 0 24px 0; font-size: 15px; color: #64748b; line-height: 1.5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">Hi ${escapeHtml(userGreeting)},</p>
              ${bodyHtml}
            </td>
          </tr>

          <!-- Divider + Footer inside card -->
          <tr>
            <td style="padding: 0 40px 32px; border-top: 1px solid #f1f5f9;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
                <tr>
                  <td style="padding-top: 20px; text-align: center;">
                    <p style="margin: 0 0 8px 0; font-size: 13px; color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">This email was sent by ${siteName} &middot; <a href="${appUrl}/settings" style="color: #008069; text-decoration: none; font-weight: 500;">Email preferences</a></p>
                    <p style="margin: 0; font-size: 12px; color: #cbd5e1; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">&copy; ${year} ${companyName}. All rights reserved.</p>
                    ${supportEmail ? `<p style="margin: 8px 0 0; font-size: 12px; color: #cbd5e1; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;"><a href="mailto:${supportEmail}" style="color: #94a3b8; text-decoration: none;">${supportEmail}</a></p>` : ''}
                  </td>
                </tr>
              </table>
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
      subject = `Welcome to ${appName} — Account Approved`
      htmlContent = buildEmailTemplate(
        `Your account has been approved!`,
        user.name,
        `✅`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">Great news! Your account has been securely verified and approved. You now have full access to your dashboard and all platform features.</p>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/login" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Go to Dashboard</a>
          </td></tr>
        </table>
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">Welcome aboard,<br><span style="font-weight: 500; color: #64748b;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'accountRejected':
      subject = `${appName} — Account Application Update`
      htmlContent = buildEmailTemplate(
        `Application Update`,
        user.name,
        `📋`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">We've carefully reviewed your application, but unfortunately we're unable to approve your account at this time.</p>
        ${params.reason ? `<table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td style="padding-bottom: 24px;"><div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px; padding: 16px 20px;"><p style="margin: 0; font-size: 13px; color: #dc2626; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Reviewer's Note</p><p style="margin: 8px 0 0; font-size: 14px; color: #991b1b; line-height: 1.5;">${escapeHtml(params.reason)}</p></div></td></tr></table>` : ''}
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">Regards,<br><span style="font-weight: 500; color: #64748b;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'accountSuspended':
      subject = `${appName} — Account Suspended`
      htmlContent = buildEmailTemplate(
        `Account Suspended`,
        user.name,
        `⚠️`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">Your account access has been temporarily restricted to protect our community and ensure compliance with our platform policies.</p>
        ${params.reason ? `<table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td style="padding-bottom: 24px;"><div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px; padding: 16px 20px;"><p style="margin: 0; font-size: 13px; color: #dc2626; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Reason</p><p style="margin: 8px 0 0; font-size: 14px; color: #991b1b; line-height: 1.5;">${escapeHtml(params.reason)}</p></div></td></tr></table>` : ''}
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">Regards,<br><span style="font-weight: 500; color: #64748b;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'conversationClosed':
      subject = `${appName} — Conversation Closed`
      htmlContent = buildEmailTemplate(
        `Conversation Resolved`,
        user.name,
        `✅`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">Our support team has resolved and closed your recent conversation. Thank you for reaching out — we're always here if you need further assistance.</p>
        ${params.closingNote ? `<table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td style="padding-bottom: 24px;"><div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 20px;"><p style="margin: 0; font-size: 13px; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Closing Note</p><p style="margin: 8px 0 0; font-size: 14px; color: #334155; line-height: 1.5;">${escapeHtml(params.closingNote)}</p></div></td></tr></table>` : ''}
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/home/chat" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Return to Chat</a>
          </td></tr>
        </table>
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">Best regards,<br><span style="font-weight: 500; color: #64748b;">The ${escapeHtml(appName)} Team</span></p>`
      )
      break

    case 'newMessage': {
      const msgLabel = params.messageCount === 1 ? 'new message' : `${params.messageCount} new messages`
      subject = `${msgLabel.charAt(0).toUpperCase() + msgLabel.slice(1)} on ${appName}`
      htmlContent = buildEmailTemplate(
        `${params.messageCount} new message${params.messageCount === 1 ? '' : 's'}`,
        user.name,
        `💬`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">You have <strong style="color: #0f172a;">${params.messageCount} new message${params.messageCount === 1 ? '' : 's'}</strong> waiting for you on your dashboard.</p>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/home/chat" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">View Messages</a>
          </td></tr>
        </table>
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">The ${escapeHtml(appName)} Team</p>`
      )
      break
    }

    case 'passwordReset':
      if (!params.resetToken) throw new Error('Reset token missing')
      subject = `${appName} — Reset Your Password`
      htmlContent = buildEmailTemplate(
        `Reset Your Password`,
        user.name,
        `🔑`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">We received a request to reset your password. Click the button below to set a new one.</p>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/reset-password?token=${encodeURIComponent(params.resetToken)}" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Reset Password</a>
          </td></tr>
        </table>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-top: 16px; border-top: 1px solid #f1f5f9;">
            <p style="margin: 0 0 6px 0; font-size: 13px; color: #94a3b8;">Didn't request this? You can safely ignore this email — your account is secure.</p>
            <p style="margin: 0; font-size: 12px; color: #cbd5e1;">This link expires in 30 minutes.</p>
          </td></tr>
        </table>`
      )
      break

    case 'passwordResetAdmin':
      if (!params.tempPassword) throw new Error('Temporary password missing')
      subject = `${appName} — Temporary Password`
      htmlContent = buildEmailTemplate(
        `Your Temporary Password`,
        user.name,
        `🔐`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">An administrator has reset your password. Use the credentials below to log in, then change your password immediately.</p>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <div style="background: #f0fdf4; border: 2px dashed #86efac; border-radius: 10px; padding: 20px; text-align: center; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 22px; font-weight: 700; letter-spacing: 3px; color: #166534;">
              ${escapeHtml(params.tempPassword)}
            </div>
          </td></tr>
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/login" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Login Now</a>
          </td></tr>
        </table>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-top: 16px; border-top: 1px solid #f1f5f9;">
            <p style="margin: 0; font-size: 13px; color: #dc2626; font-weight: 500;">⚠ Change your password in Settings immediately after logging in.</p>
          </td></tr>
        </table>`
      )
      break

    case 'adminNewMessage': {
      const convLabel = params.conversationCount === 1 ? 'conversation' : 'conversations'
      subject = `${params.conversationCount} unread ${convLabel} on ${appName}`
      htmlContent = buildEmailTemplate(
        `${params.conversationCount} unread ${convLabel}`,
        user.name,
        `📬`,
        `<p style="margin: 0 0 24px 0; font-size: 15px; color: #475569; line-height: 1.6;">You have <strong style="color: #0f172a;">${params.conversationCount} unread ${convLabel}</strong> with messages waiting for your response in the admin dashboard.</p>
        <table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">
          <tr><td style="padding-bottom: 24px;">
            <a href="${appUrl}/admin" style="display: inline-block; background-color: #008069; color: #ffffff; padding: 14px 36px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px;">Open Dashboard</a>
          </td></tr>
        </table>
        <p style="margin: 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">The ${escapeHtml(appName)} Team</p>`
      )
      break
    }

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
