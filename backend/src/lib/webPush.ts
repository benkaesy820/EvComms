import webpush from 'web-push'
import { eq, inArray } from 'drizzle-orm'
import { db } from '../db/index.js'
import { pushSubscriptions } from '../db/schema.js'
import { env } from './env.js'
import { logger } from './logger.js'

let initialized = false

/**
 * Initialize web-push with VAPID keys.
 * Called lazily on first notification send to avoid startup failures
 * when VAPID keys are missing in development.
 */
function ensureInitialized() {
  if (initialized) return
  if (!env.vapidPublicKey || !env.vapidPrivateKey) {
    logger.warn('VAPID keys not configured — web push disabled')
    return
  }
  webpush.setVapidDetails(
    env.vapidSubject,
    env.vapidPublicKey,
    env.vapidPrivateKey,
  )
  initialized = true
  logger.info({ publicKey: env.vapidPublicKey.slice(0, 20) + '...' }, 'Web push initialized')
}

export interface PushPayload {
  title: string
  body: string
  icon?: string
  badge?: string
  tag?: string
  data?: Record<string, unknown>
  /** Notification action buttons (rendered by the OS/browser) */
  actions?: Array<{ action: string; title: string; icon?: string }>
  /** If true, notification is shown silently (no sound/vibration) */
  silent?: boolean
}

/**
 * Send a Web Push notification to every registered device for a given user.
 *
 * Reliability features:
 * - Promise.allSettled: one bad subscription never blocks the others
 * - Retry transient 5xx/429 errors once after 1s backoff
 * - Auto-remove 410 Gone / 404 Not Found subscriptions (expired/revoked)
 * - Batch-delete expired subscriptions in a single query
 * - TTL 24h: messages deliver when device comes back online
 * - Urgency header: helps mobile browsers prioritize delivery
 *
 * Browser-specific notes:
 * - Chrome/Edge: Uses FCM push service — requires valid VAPID keys
 * - Firefox: Uses Mozilla AutoPush — more forgiving error messages
 * - Safari: Not supported (requires APNs, different protocol)
 * - Android Chrome: Notifications auto-dismiss after ~20s unless
 *   requireInteraction is true (set in service worker)
 */
export async function sendPushToUser(
  userId: string,
  payload: PushPayload,
): Promise<void> {
  ensureInitialized()
  if (!initialized) return

  const subs = await db.query.pushSubscriptions.findMany({
    where: eq(pushSubscriptions.userId, userId),
    columns: { id: true, endpoint: true, p256dh: true, auth: true },
  })

  if (subs.length === 0) {
    logger.debug({ userId }, 'No push subscriptions found')
    return
  }

  logger.debug({ userId, count: subs.length }, 'Sending push notification')

  // Build the notification payload — always include icon/badge for consistency
  // The service worker uses these as fallbacks if not provided in the payload
  const finalPayload = {
    icon: `${env.appUrl}/icon-192.png`,
    badge: `${env.appUrl}/icon-192.png`,
    ...payload,
  }

  const notification = JSON.stringify(finalPayload)
  const expiredIds: string[] = []
  let successCount = 0
  let failureCount = 0

  await Promise.allSettled(
    subs.map(async (sub) => {
      const subscription = {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth },
      }

      try {
        await webpush.sendNotification(subscription, notification, {
          TTL: 86400, // 24h — deliver when the device comes back online
          headers: { Urgency: 'high' }, // Helps mobile browsers prioritize
        })
        successCount++
      } catch (err: any) {
        const status: number = err?.statusCode ?? 0

        // 410 Gone / 404 Not Found = subscription revoked or expired
        // These should be removed from the database immediately
        if (status === 410 || status === 404) {
          expiredIds.push(sub.id)
          logger.debug(
            { userId, endpoint: sub.endpoint.slice(0, 60), status },
            'Push subscription expired'
          )
          return
        }

        // 429 Too Many Requests or 5xx = transient push-service error → retry once
        if (status === 429 || status >= 500) {
          await new Promise((r) => setTimeout(r, 1000))
          try {
            await webpush.sendNotification(subscription, notification, {
              TTL: 86400,
              headers: { Urgency: 'high' },
            })
            successCount++
            return
          } catch (retryErr: any) {
            logger.warn(
              {
                userId,
                endpoint: sub.endpoint.slice(0, 60),
                status: retryErr?.statusCode,
              },
              'Push retry failed',
            )
            failureCount++
            return
          }
        }

        // 400 Bad Request = malformed subscription (invalid endpoint/keys)
        // Remove from database to prevent future failures
        if (status === 400 || status === 401 || status === 403) {
          expiredIds.push(sub.id)
          logger.warn(
            { userId, endpoint: sub.endpoint.slice(0, 60), status },
            'Push subscription invalid — removing'
          )
          return
        }

        // All other errors — log but don't remove (might be transient)
        logger.warn(
          { userId, endpoint: sub.endpoint.slice(0, 60), status, message: err?.message },
          'Push send failed',
        )
        failureCount++
      }
    }),
  )

  // Batch-delete all expired/invalid subscriptions in a single query
  if (expiredIds.length > 0) {
    await db
      .delete(pushSubscriptions)
      .where(inArray(pushSubscriptions.id, expiredIds))
      .catch((e) => logger.warn({ e }, 'Failed to clean up expired push subscriptions'))
    logger.info(
      { userId, count: expiredIds.length },
      'Cleaned up expired push subscriptions',
    )
  }

  if (failureCount > 0) {
    logger.warn(
      { userId, success: successCount, failed: failureCount },
      'Push notification delivery summary'
    )
  } else {
    logger.debug(
      { userId, success: successCount },
      'Push notification delivered'
    )
  }
}
