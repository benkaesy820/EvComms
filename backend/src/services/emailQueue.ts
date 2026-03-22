import { serverState } from '../state.js'
import { sendEmail } from './email.js'
import { getConfig } from '../lib/config.js'
import { sleep } from '../lib/utils.js'
import { logger } from '../lib/logger.js'

// Optimized email queue with batch processing and concurrency control

interface QueuedEmail {
  userId: string
  messageCount: number
  firstMessageAt: number
  timer: NodeJS.Timeout
  priority: number // Higher = more important (e.g., password resets)
}

interface EmailMetrics {
  sent: number
  failed: number
  retried: number
  cancelled: number
  averageSendTimeMs: number
}

let pendingSends: Set<Promise<void>> = new Set()
const metrics: EmailMetrics = {
  sent: 0,
  failed: 0,
  retried: 0,
  cancelled: 0,
  averageSendTimeMs: 0
}

// Concurrency control - max 5 concurrent email sends to prevent overwhelming providers
const MAX_CONCURRENT_SENDS = 5
let activeSendCount = 0

/**
 * Queue an email notification for a user.
 * Implements debouncing to batch multiple messages into a single email.
 */
export function queueEmailNotification(userId: string): void {
  const config = getConfig()

  // Check if user has disabled email notifications
  const emailEnabled = serverState.emailPreferences.get(userId)
  if (emailEnabled === false) {
    logger.debug({ userId }, 'Email notifications disabled for user')
    return
  }

  // Don't send if user is currently online
  const presence = serverState.userPresence.get(userId)
  if (presence?.status === 'online') {
    return
  }

  // Check minimum offline time threshold
  const now = Date.now()
  const offlineThreshold = config.email.notification.minOfflineSeconds * 1000
  if (presence && (now - presence.lastSeen) < offlineThreshold) {
    return
  }

  const existing = serverState.pendingEmails.get(userId)
  const debounceMs = config.email.notification.debounceSeconds * 1000
  const maxDelayMs = config.email.notification.maxDelaySeconds * 1000

  if (existing) {
    // Clear existing timer to reset debounce
    clearTimeout((existing as QueuedEmail).timer)

    const elapsed = now - (existing as QueuedEmail).firstMessageAt
    const shouldSendNow = elapsed >= maxDelayMs

    if (shouldSendNow) {
      // Max delay reached, send immediately
      scheduleEmailSend(userId, (existing as QueuedEmail).messageCount + 1)
      serverState.pendingEmails.delete(userId)
      return
    }

    // Reset timer with debounce
    const timer = setTimeout(() => {
      scheduleEmailSend(userId, (existing as QueuedEmail).messageCount + 1)
      serverState.pendingEmails.delete(userId)
    }, debounceMs)

    serverState.pendingEmails.set(userId, {
      ...(existing as QueuedEmail),
      messageCount: (existing as QueuedEmail).messageCount + 1,
      timer
    })

    logger.debug({ userId, messageCount: (existing as QueuedEmail).messageCount + 1 }, 'Email notification debounced')
  } else {
    // First message for this user
    const timer = setTimeout(() => {
      scheduleEmailSend(userId, 1)
      serverState.pendingEmails.delete(userId)
    }, debounceMs)

    const queuedEmail: QueuedEmail = {
      userId,
      messageCount: 1,
      firstMessageAt: now,
      timer,
      priority: 1 // Normal priority for message notifications
    }

    serverState.pendingEmails.set(userId, queuedEmail)
    logger.debug({ userId }, 'Email notification queued')
  }
}

/**
 * Queue a high-priority email (e.g., password reset) that bypasses debouncing.
 * Critical emails like password resets are always sent regardless of notification preferences.
 */
export function queueHighPriorityEmail(
  userId: string,
  type: 'passwordReset' | 'passwordResetAdmin' | 'accountApproved',
  extraParams?: { resetToken?: string; tempPassword?: string }
): void {
  // Cancel any pending notification for this user to avoid duplicate emails
  cancelEmailNotification(userId)

  // Send immediately - critical emails bypass notification preferences
  scheduleEmailSend(userId, 1, type, extraParams)
}

function scheduleEmailSend(
  userId: string,
  messageCount: number,
  emailType: 'newMessage' | 'passwordReset' | 'passwordResetAdmin' | 'accountApproved' = 'newMessage',
  extraParams?: { resetToken?: string; tempPassword?: string }
): void {
  // Double-check notification preference for non-critical emails only
  const isNonCriticalEmail = (type: string): boolean => type === 'newMessage'
  
  if (isNonCriticalEmail(emailType)) {
    const emailEnabled = serverState.emailPreferences.get(userId)
    if (emailEnabled === false) {
      return
    }
  }

  const sendPromise = sendEmailWithRetry(userId, messageCount, emailType, extraParams).catch((error) => {
    logger.error({ userId, error: error.message, type: emailType }, 'Email notification failed permanently')
    metrics.failed++
  })
  
  pendingSends.add(sendPromise)
  
  sendPromise.finally(() => {
    pendingSends.delete(sendPromise)
    activeSendCount--
  })
}

async function sendEmailWithRetry(
  userId: string, 
  messageCount: number, 
  emailType: 'newMessage' | 'passwordReset' | 'passwordResetAdmin' | 'accountApproved' = 'newMessage',
  extraParams?: { resetToken?: string; tempPassword?: string }
): Promise<void> {
  const config = getConfig()
  const maxRetries = config.email.notification.maxRetries
  const backoffMs = config.email.notification.retryBackoffMs

  // Concurrency control - wait if too many active sends
  while (activeSendCount >= MAX_CONCURRENT_SENDS) {
    await sleep(100)
  }
  activeSendCount++

  const startTime = Date.now()

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      if (emailType === 'newMessage') {
        await sendEmail({
          type: 'newMessage',
          userId,
          messageCount
        })
      } else {
        await sendEmail({
          type: emailType,
          userId,
          ...(extraParams?.resetToken ? { resetToken: extraParams.resetToken } : {}),
          ...(extraParams?.tempPassword ? { tempPassword: extraParams.tempPassword } : {})
        })
      }
      
      const sendTime = Date.now() - startTime
      metrics.sent++
      metrics.averageSendTimeMs = 
        (metrics.averageSendTimeMs * (metrics.sent - 1) + sendTime) / metrics.sent
      
      logger.info({ userId, messageCount, type: emailType, attempt: attempt + 1, sendTimeMs: sendTime }, 'Email notification sent')
      return
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error'
      logger.warn({ userId, attempt: attempt + 1, error: errMsg, type: emailType }, 'Email notification attempt failed')
      metrics.retried++

      if (attempt < maxRetries - 1) {
        // Exponential backoff with jitter
        const delay = backoffMs * Math.pow(2, attempt) + Math.random() * 1000
        await sleep(delay)
      }
    }
  }

  metrics.failed++
  throw new Error(`Failed to send email after ${maxRetries} attempts`)
}

/**
 * Cancel a pending email notification for a user.
 * Called when user reads messages or disables notifications.
 */
export function cancelEmailNotification(userId: string): void {
  const pending = serverState.pendingEmails.get(userId)
  if (pending) {
    clearTimeout((pending as QueuedEmail).timer)
    serverState.pendingEmails.delete(userId)
    metrics.cancelled++
    logger.debug({ userId }, 'Email notification cancelled')
  }
}

/**
 * Drain all pending emails during shutdown.
 * Forces immediate sending of all queued emails with timeout.
 */
export async function drainEmailQueue(timeoutMs: number = 5000): Promise<void> {
  const pending = Array.from(serverState.pendingEmails.values())
  
  logger.info({ pendingCount: pending.length, inFlightCount: pendingSends.size }, 'Draining email queue')
  
  // Clear all pending timers and send immediately
  for (const item of pending) {
    clearTimeout((item as QueuedEmail).timer)
    // Schedule immediate send
    scheduleEmailSend((item as QueuedEmail).userId, (item as QueuedEmail).messageCount)
  }
  
  serverState.pendingEmails.clear()
  
  // Wait for in-flight sends to complete
  if (pendingSends.size > 0) {
    const drainPromise = Promise.allSettled(pendingSends)
    const timeoutPromise = sleep(timeoutMs).then(() => {
      logger.warn({ count: pendingSends.size }, 'Email queue drain timed out')
    })
    
    await Promise.race([drainPromise, timeoutPromise])
  }
  
  logger.info({ 
    drained: pending.length, 
    metrics: { ...metrics }
  }, 'Email queue drained')
}

/**
 * Get current email queue statistics.
 */
export function getEmailQueueStats(): { 
  pending: number
  inFlight: number
  activeSends: number
  metrics: EmailMetrics
} {
  return {
    pending: serverState.pendingEmails.size,
    inFlight: pendingSends.size,
    activeSends: activeSendCount,
    metrics: { ...metrics }
  }
}

/**
 * Reset email metrics (useful for testing).
 */
export function resetEmailMetrics(): void {
  metrics.sent = 0
  metrics.failed = 0
  metrics.retried = 0
  metrics.cancelled = 0
  metrics.averageSendTimeMs = 0
}
