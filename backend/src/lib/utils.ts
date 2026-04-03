import { createHash, createHmac } from 'crypto'
import { env } from './env.js'

const HTML_ENTITY_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;'
}

// RFC 5322 compliant email regex (simplified but comprehensive)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

/**
 * Normalizes and validates an email address.
 * - Trims whitespace
 * - Converts to lowercase
 * - Validates format against RFC 5322
 * - Truncates to 255 characters
 * 
 * @throws Error if email format is invalid
 */
export function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase().slice(0, 255)
  
  // Validate email format
  if (!EMAIL_REGEX.test(normalized)) {
    throw new Error(`Invalid email format: ${email.slice(0, 50)}`)
  }
  
  // Additional check: ensure there's exactly one @ and it has content on both sides
  const atIndex = normalized.indexOf('@')
  if (atIndex === -1 || atIndex === 0 || atIndex === normalized.length - 1) {
    throw new Error(`Invalid email format: ${email.slice(0, 50)}`)
  }
  
  // Check for consecutive dots (not allowed in valid emails)
  if (normalized.includes('..')) {
    throw new Error(`Invalid email format: consecutive dots not allowed`)
  }
  
  return normalized
}

/**
 * Safely normalizes an email, returning null instead of throwing.
 * Useful for batch operations where individual failures shouldn't stop processing.
 */
export function normalizeEmailSafe(email: string): string | null {
  try {
    return normalizeEmail(email)
  } catch {
    return null
  }
}

export function escapeHtml(str: string): string {
  return str.replace(/[&<>"'`=/]/g, char => HTML_ENTITY_MAP[char] || char)
}

export function sanitizeText(str: string): string {
  return str
    .trim()
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .slice(0, 10000)
}

export function sanitizeName(str: string): string {
  return str
    .trim()
    .replace(/[<>'"`]/g, '')
    .slice(0, 100)
}

export function sanitizeFilename(str: string): string {
  return str
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
    .replace(/\.\./g, '')
    .slice(0, 255)
}

export type RetryableErrorClassifier = (error: unknown) => boolean

const defaultRetryableClassifier: RetryableErrorClassifier = (error): boolean => {
  if (error instanceof Error) {
    const message = error.message.toLowerCase()
    if (message.includes('timeout')) return true
    if (message.includes('econnreset')) return true
    if (message.includes('econnrefused')) return true
    if (message.includes('enotfound')) return true
    if (message.includes('eai_again')) return true
    if (message.includes('socket hang up')) return true
    if (message.includes('network')) return true
    if (message.includes('temporarily unavailable')) return true
    if (message.includes('service unavailable')) return true
    if (message.includes('circuit breaker is open')) return false
    return false
  }
  return false
}

export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  maxAttempts: number = 3,
  baseDelay: number = 1000,
  isRetryable: RetryableErrorClassifier = defaultRetryableClassifier
): Promise<T> {
  let lastError: Error | null = null

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      if (!isRetryable(error)) {
        throw lastError
      }

      if (attempt === maxAttempts) {
        break
      }

      const delay = baseDelay * Math.pow(2, attempt - 1)
      const jitter = Math.random() * 0.1 * delay
      await new Promise(resolve => setTimeout(resolve, delay + jitter))
    }
  }

  throw lastError || new Error('All retry attempts failed')
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function parseUserAgent(ua: string): { browser: string; os: string; device: string } {
  const s = ua.toLowerCase()

  // Browser
  let browser = 'Unknown'
  if (s.includes('edg/') || s.includes('edge/')) browser = 'Edge'
  else if (s.includes('opr/') || s.includes('opera/')) browser = 'Opera'
  else if (s.includes('chrome/') && !s.includes('chromium/')) browser = 'Chrome'
  else if (s.includes('firefox/')) browser = 'Firefox'
  else if (s.includes('safari/') && !s.includes('chrome/')) browser = 'Safari'
  else if (s.includes('msie') || s.includes('trident/')) browser = 'IE'

  // OS
  let os = 'Unknown'
  if (s.includes('windows nt 10')) os = 'Windows 10/11'
  else if (s.includes('windows nt 6.3')) os = 'Windows 8.1'
  else if (s.includes('windows nt 6.1')) os = 'Windows 7'
  else if (s.includes('windows')) os = 'Windows'
  else if (s.includes('iphone os')) { const m = s.match(/iphone os ([\d_]+)/); os = `iOS ${m ? m[1]?.replace(/_/g, '.') ?? '' : ''}`.trim() }
  else if (s.includes('ipad')) { const m = s.match(/cpu os ([\d_]+)/); os = `iPadOS ${m ? m[1]?.replace(/_/g, '.') ?? '' : ''}`.trim() }
  else if (s.includes('android')) { const m = s.match(/android ([\d.]+)/); os = `Android ${m ? m[1] ?? '' : ''}`.trim() }
  else if (s.includes('mac os x')) { const m = s.match(/mac os x ([\d_]+)/); os = `macOS ${m ? m[1]?.replace(/_/g, '.') ?? '' : ''}`.trim() }
  else if (s.includes('linux')) os = 'Linux'

  // Device type
  let device = 'Desktop'
  if (s.includes('mobile') || s.includes('iphone') || s.includes('android') && !s.includes('tablet')) device = 'Mobile'
  else if (s.includes('tablet') || s.includes('ipad')) device = 'Tablet'

  return { browser, os, device }
}

export function extractDeviceInfo(request: { headers: Record<string, string | string[] | undefined> }): string {
  const ua = request.headers['user-agent']
  const userAgent = typeof ua === 'string' ? ua : ua?.[0] || 'unknown'
  const parsed = parseUserAgent(userAgent)

  return JSON.stringify({
    browser: parsed.browser,
    os: parsed.os,
    device: parsed.device,
    userAgent: userAgent.slice(0, 300),
  })
}

// SECURITY FIX: Use HMAC with secret key instead of plain SHA-256
// This prevents rainbow table attacks even if the hash is leaked
function getHmacKey(): string {
  if (!env.jwtSecret) throw new Error('JWT_SECRET environment variable is required — HMAC operations cannot use a hardcoded fallback')
  return env.jwtSecret
}

export function hashEmail(email: string): string {
  // HMAC-SHA256 with secret key - resistant to rainbow tables
  return createHmac('sha256', getHmacKey())
    .update(email.toLowerCase())
    .digest('hex')
}

export function hashResetToken(token: string): string {
  // HMAC-SHA256 with secret key - resistant to rainbow tables
  return createHmac('sha256', getHmacKey())
    .update(token)
    .digest('hex')
}

/**
 * GDPR-compliant IP address anonymization.
 * Truncates IPv4 to /24 (last octet removed) and IPv6 to /64.
 * For audit logging, stores HMAC hash instead of truncated IP.
 * 
 * @param ipAddress - Raw IP address
 * @param mode - 'truncate' for general use, 'hash' for audit logs
 * @returns Anonymized IP address
 */
export function anonymizeIpAddress(ipAddress: string, mode: 'truncate' | 'hash' = 'truncate'): string {
  if (!ipAddress || ipAddress === 'unknown') return 'unknown'
  
  // Handle IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
  const ipv4Mapped = ipAddress.startsWith('::ffff:')
  const cleanIp = ipv4Mapped ? ipAddress.slice(7) : ipAddress
  
  if (mode === 'hash') {
    // For audit logs - full IP hashed, can correlate but not reverse
    return createHmac('sha256', getHmacKey())
      .update(cleanIp)
      .digest('hex')
      .substring(0, 32) // 32 chars is enough for uniqueness
  }
  
  // IPv4: truncate to /24 (remove last octet)
  if (cleanIp.includes('.') && !cleanIp.includes(':')) {
    const parts = cleanIp.split('.')
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`
    }
  }
  
  // IPv6: truncate to /64 (first 4 segments)
  if (cleanIp.includes(':')) {
    const parts = cleanIp.split(':')
    if (parts.length >= 4) {
      return `${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}::/64`
    }
  }
  
  // Fallback: hash if format is unexpected
  return createHmac('sha256', getHmacKey())
    .update(cleanIp)
    .digest('hex')
    .substring(0, 16)
}

export function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

const ULID_REGEX = /^[0-9A-HJKMNP-TV-Z]{26}$/

export function isValidId(id: string): boolean {
  return ULID_REGEX.test(id)
}

const FILE_SIGNATURES: Record<string, { signature: number[]; offset?: number }> = {
  'image/jpeg': { signature: [0xFF, 0xD8, 0xFF] },
  'image/png': { signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  'image/gif': { signature: [0x47, 0x49, 0x46, 0x38] },
  'image/webp': { signature: [0x52, 0x49, 0x46, 0x46], offset: 0 },
  'image/bmp': { signature: [0x42, 0x4D] },

  'application/pdf': { signature: [0x25, 0x50, 0x44, 0x46] },
  'application/zip': { signature: [0x50, 0x4B, 0x03, 0x04] },
  'application/x-zip-compressed': { signature: [0x50, 0x4B, 0x03, 0x04] },
}

const WEBP_RIFF = [0x52, 0x49, 0x46, 0x46]
const WEBP_WEBP = [0x57, 0x45, 0x42, 0x50]


function bufferStartsWith(buffer: Buffer, signature: number[], offset: number = 0): boolean {
  if (buffer.length < offset + signature.length) return false
  for (let i = 0; i < signature.length; i++) {
    if (buffer[offset + i] !== signature[i]) return false
  }
  return true
}

export function validateFileSignature(buffer: Buffer, mimeType: string): boolean {
  const sig = FILE_SIGNATURES[mimeType]
  // SECURITY FIX: Return false for unknown mime types instead of allowing them
  if (!sig) return false

  const offset = sig.offset ?? 0
  if (!bufferStartsWith(buffer, sig.signature, offset)) return false

  if (mimeType === 'image/webp') {
    if (!bufferStartsWith(buffer, WEBP_RIFF, 0)) return false
    if (buffer.length < 12) return false
    if (!bufferStartsWith(buffer, WEBP_WEBP, 8)) return false
    return true
  }

  return true
}

// Allowed MIME types for reports
const ALLOWED_REPORT_MEDIA_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp',
  'application/pdf', 'text/plain', 'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
])

/**
 * Validates media ownership and freshness for report attachments.
 * Used by both registration reports and user reports.
 * 
 * @param mediaRecord - The media record from the database
 * @param userId - The ID of the user claiming ownership
 * @param maxAgeHours - Maximum age of the upload in hours (default: 1)
 * @returns Object with valid flag and error message if invalid
 */
export function validateReportMedia(
  mediaRecord: { id: string; status: string; uploadedBy: string; uploadedAt: Date; mimeType?: string } | undefined,
  userId: string,
  maxAgeHours: number = 1
): { valid: boolean; error?: string } {
  if (!mediaRecord) {
    return { valid: false, error: 'Invalid media reference' }
  }

  // Media must be CONFIRMED (upload completed) — was checking 'PENDING' but status is 'CONFIRMED' after upload+confirm, causing all report attachments to fail
  if (mediaRecord.status !== 'CONFIRMED') {
    return { valid: false, error: 'Media upload is not complete or has already been used' }
  }

  // Media must belong to the user
  if (mediaRecord.uploadedBy !== userId) {
    return { valid: false, error: 'Invalid media ownership' }
  }

  // SECURITY FIX: Validate MIME type if provided
  if (mediaRecord.mimeType && !ALLOWED_REPORT_MEDIA_TYPES.has(mediaRecord.mimeType)) {
    return { valid: false, error: 'Invalid media type for reports' }
  }

  // Media must be fresh (within maxAgeHours)
  const maxAgeMs = maxAgeHours * 60 * 60 * 1000
  const cutoffTime = new Date(Date.now() - maxAgeMs)
  if (new Date(mediaRecord.uploadedAt) < cutoffTime) {
    return { valid: false, error: 'Media upload expired' }
  }

  return { valid: true }
}
