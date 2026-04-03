import { serverState } from '../state.js'
import { sendEmail } from './email.js'
import { getConfig } from '../lib/config.js'
import { sleep } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { getRedis } from '../redis.js'
import { isUserOnlineGlobally } from '../socket/index.js'

// Local-only debounce tracker for admin emails (avoids type conflicts with user pendingEmails LRU)
interface AdminEmailDebounce { messageCount: number; firstMessageAt: number; timer: NodeJS.Timeout }
const localAdminEmails = new Map<string, AdminEmailDebounce>()

// Optimized email queue with batch processing and concurrency control

interface QueuedEmail {
  userId: string
  messageCount: number
  firstMessageAt: number
  timer: NodeJS.Timeout
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
export async function queueEmailNotification(userId: string): Promise<void> {
  const config = getConfig()

  // Check if user has disabled email notifications
  const emailEnabled = serverState.emailPreferences.get(userId)
  if (emailEnabled === false) {
    logger.debug({ userId }, 'Email notifications disabled for user')
    return
  }

  // Natively check globally connected socket mesh to prevent cluster-blind notifications
  const isOnline = await isUserOnlineGlobally(userId)
  if (isOnline) {
    return
  }

  // Check minimum offline time threshold
  const now = Date.now()
  const offlineThreshold = config.email.notification.minOfflineSeconds * 1000
  const presence = serverState.userPresence.get(userId)
  if (presence && (now - presence.lastSeen) < offlineThreshold) {
    return
  }

  const debounceSeconds = config.email.notification.debounceSeconds
  const redis = getRedis()

  if (redis) {
    const lock = await redis.set(`email_debounce:${userId}`, '1', 'EX', debounceSeconds, 'NX')
    if (lock === 'OK') {
      logger.debug({ userId }, 'Email notification Redis lock acquired. Dispatching.')
      scheduleEmailSend(userId, 1).catch(e => logger.error({ e }, 'Immediate send failed'))
    } else {
      logger.debug({ userId }, 'Email notification debounced by Redis.')
    }
  } else {
    const existing = serverState.pendingEmails.get(userId)
    const debounceMs = debounceSeconds * 1000
    const maxDelayMs = config.email.notification.maxDelaySeconds * 1000

    if (existing) {
      clearTimeout((existing as QueuedEmail).timer)
      const elapsed = now - (existing as QueuedEmail).firstMessageAt
      if (elapsed >= maxDelayMs) {
        scheduleEmailSend(userId, (existing as QueuedEmail).messageCount + 1).catch(e => logger.error({ e }, 'Max delay send failed'))
        serverState.pendingEmails.delete(userId)
        return
      }
      const timer = setTimeout(() => {
        scheduleEmailSend(userId, (existing as QueuedEmail).messageCount + 1).catch(e => logger.error({ e }, 'Debounced send failed'))
        serverState.pendingEmails.delete(userId)
      }, debounceMs)
      serverState.pendingEmails.set(userId, {
        ...(existing as QueuedEmail),
        messageCount: (existing as QueuedEmail).messageCount + 1,
        timer
      })
    } else {
      const timer = setTimeout(() => {
        scheduleEmailSend(userId, 1).catch(e => logger.error({ e }, 'Initial send failed'))
        serverState.pendingEmails.delete(userId)
      }, debounceMs)
      const queuedEmail: QueuedEmail = {
        userId,
        messageCount: 1,
        firstMessageAt: now,
        timer,
      }
      serverState.pendingEmails.set(userId, queuedEmail)
    }
  }
}

/**
 * Queue a debounced email notification for an offline admin.
 * Uses the same distributed lock and debounce pattern as user emails.
 * Batches multiple conversation notifications into a single email.
 */
export async function queueAdminEmailNotification(adminId: string): Promise<void> {
  const config = getConfig()

  const isOnline = await isUserOnlineGlobally(adminId)
  if (isOnline) return

  const now = Date.now()
  const offlineThreshold = config.email.notification.minOfflineSeconds * 1000
  const presence = serverState.userPresence.get(adminId)
  if (presence && (now - presence.lastSeen) < offlineThreshold) return

  const debounceSeconds = config.email.notification.debounceSeconds
  const redis = getRedis()

  if (redis) {
    const lock = await redis.set(`admin_email_debounce:${adminId}`, '1', 'EX', debounceSeconds, 'NX')
    if (lock === 'OK') {
      logger.debug({ adminId }, 'Admin email notification dispatching.')
      scheduleAdminEmailSend(adminId, 1).catch(e => logger.error({ e }, 'Admin immediate send failed'))
    } else {
      logger.debug({ adminId }, 'Admin email notification debounced by Redis.')
    }
  } else {
    const key = `admin_email:${adminId}`
    const existing = localAdminEmails.get(key)
    const debounceMs = debounceSeconds * 1000
    const maxDelayMs = config.email.notification.maxDelaySeconds * 1000

    if (existing) {
      clearTimeout(existing.timer)
      const elapsed = now - existing.firstMessageAt
      if (elapsed >= maxDelayMs) {
        scheduleAdminEmailSend(adminId, existing.messageCount + 1).catch(e => logger.error({ e }, 'Admin max delay send failed'))
        localAdminEmails.delete(key)
        return
      }
      const timer = setTimeout(() => {
        scheduleAdminEmailSend(adminId, localAdminEmails.get(key)!.messageCount).catch(e => logger.error({ e }, 'Admin debounced send failed'))
        localAdminEmails.delete(key)
      }, debounceMs)
      existing.messageCount += 1
      existing.timer = timer
    } else {
      const timer = setTimeout(() => {
        scheduleAdminEmailSend(adminId, 1).catch(e => logger.error({ e }, 'Admin debounced send failed'))
        localAdminEmails.delete(key)
      }, debounceMs)
      localAdminEmails.set(key, { messageCount: 1, firstMessageAt: now, timer })
    }
  }
}

async function scheduleAdminEmailSend(adminId: string, conversationCount: number): Promise<void> {
  const sendPromise = sendAdminEmailWithRetry(adminId, conversationCount).catch((error) => {
    logger.error({ adminId, error: error.message }, 'Admin email notification failed')
    metrics.failed++
  })
  pendingSends.add(sendPromise)
  await sendPromise
  pendingSends.delete(sendPromise)
}

async function sendAdminEmailWithRetry(adminId: string, conversationCount: number): Promise<void> {
  const config = getConfig()
  const maxRetries = config.email.notification.maxRetries
  const backoffMs = config.email.notification.retryBackoffMs

  while (activeSendCount >= MAX_CONCURRENT_SENDS) {
    await sleep(100)
  }
  activeSendCount++

  try {
    const startTime = Date.now()
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        await sendEmail({
          type: 'adminNewMessage',
          userId: adminId,
          conversationCount
        })
        const sendTime = Date.now() - startTime
        metrics.sent++
        metrics.averageSendTimeMs =
          (metrics.averageSendTimeMs * (metrics.sent - 1) + sendTime) / metrics.sent
        logger.info({ adminId, conversationCount, attempt: attempt + 1, sendTimeMs: sendTime }, 'Admin email sent')
        return
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error'
        logger.warn({ adminId, attempt: attempt + 1, error: errMsg }, 'Admin email attempt failed')
        metrics.retried++
        if (attempt < maxRetries - 1) {
          const delay = backoffMs * Math.pow(2, attempt) + Math.random() * 1000
          await sleep(delay)
        }
      }
    }
    metrics.failed++
    throw new Error(`Failed to send admin email after ${maxRetries} attempts`)
  } finally {
    activeSendCount--
  }
}

/**
 * Queue a high-priority email (e.g., password reset) that bypasses debouncing.
 */
export async function queueHighPriorityEmail(
  userId: string,
  type: 'passwordReset' | 'passwordResetAdmin' | 'accountApproved',
  extraParams?: { resetToken?: string; tempPassword?: string }
): Promise<void> {
  const redis = getRedis()
  if (redis) {
    const lockKey = `lock:highprio:${userId}:${type}`
    const lock = await redis.set(lockKey, '1', 'EX', 10, 'NX')
    if (lock !== 'OK') {
       logger.warn({ userId, type }, 'High priority email debounced by Redis.')
       return
    }
  }

  cancelEmailNotification(userId)
  await scheduleEmailSend(userId, 1, type, extraParams)
}

async function scheduleEmailSend(
  userId: string,
  messageCount: number,
  emailType: 'newMessage' | 'passwordReset' | 'passwordResetAdmin' | 'accountApproved' = 'newMessage',
  extraParams?: { resetToken?: string; tempPassword?: string }
): Promise<void> {
  const isNonCriticalEmail = (type: string): boolean => type === 'newMessage'

  if (isNonCriticalEmail(emailType)) {
    const emailEnabled = serverState.emailPreferences.get(userId)
    if (emailEnabled === false) return
  }

  const sendPromise = sendEmailWithRetry(userId, messageCount, emailType, extraParams).catch((error) => {
    logger.error({ userId, error: error.message, type: emailType }, 'Email notification failed')
    metrics.failed++
  })

  pendingSends.add(sendPromise)
  await sendPromise
  pendingSends.delete(sendPromise)
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

  while (activeSendCount >= MAX_CONCURRENT_SENDS) {
    await sleep(100)
  }
  activeSendCount++

  try {
    const startTime = Date.now()
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        if (emailType === 'newMessage') {
          await sendEmail({ type: 'newMessage', userId, messageCount })
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

        logger.info({ userId, messageCount, type: emailType, attempt: attempt + 1, sendTimeMs: sendTime }, 'Email sent')
        return
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error'
        logger.warn({ userId, attempt: attempt + 1, error: errMsg, type: emailType }, 'Email attempt failed')
        metrics.retried++
        if (attempt < maxRetries - 1) {
          const delay = backoffMs * Math.pow(2, attempt) + Math.random() * 1000
          await sleep(delay)
        }
      }
    }
    metrics.failed++
    throw new Error(`Failed to send email after ${maxRetries} attempts`)
  } finally {
    activeSendCount--
  }
}

/**
 * Cancel a pending email notification for a user.
 */
export function cancelEmailNotification(userId: string): void {
  const redis = getRedis()
  if (redis) {
    redis.del(`email_debounce:${userId}`).catch(() => {})
    metrics.cancelled++
    return
  }

  const pending = serverState.pendingEmails.get(userId)
  if (pending) {
    clearTimeout((pending as QueuedEmail).timer)
    serverState.pendingEmails.delete(userId)
    metrics.cancelled++
  }
}

/**
 * Drain all pending emails during shutdown.
 */
export async function drainEmailQueue(timeoutMs: number = 5000): Promise<void> {
  const pending = Array.from(serverState.pendingEmails.values())

  logger.info({ pendingCount: pending.length, inFlightCount: pendingSends.size }, 'Draining email queue')

  const drainPromises = []
  for (const item of pending) {
    clearTimeout((item as QueuedEmail).timer)
    drainPromises.push(scheduleEmailSend((item as QueuedEmail).userId, (item as QueuedEmail).messageCount).catch(e => logger.error({ e }, 'Drain send failed')))
  }

  await Promise.allSettled(drainPromises)
  serverState.pendingEmails.clear()

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
