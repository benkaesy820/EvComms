import webpush from 'web-push'
import { eq, inArray } from 'drizzle-orm'
import { db } from '../db/index.js'
import { pushSubscriptions } from '../db/schema.js'
import { env } from './env.js'
import { logger } from './logger.js'

let initialized = false

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
}

export interface PushPayload {
  title: string
  body: string
  icon?: string
  badge?: string
  tag?: string
  data?: Record<string, unknown>
}

/**
 * Send a Web Push notification to every registered device for a given user.
 *
 * Reliability notes for PaaS:
 * - Uses Promise.allSettled so one bad subscription never blocks the others.
 * - Retries transient 5xx errors from the push service once after 1 s.
 * - Silently removes subscriptions that report 410 Gone or 404 Not Found.
 * - Batch-deletes expired subscriptions in a single query.
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

  if (subs.length === 0) return

  const finalPayload = {
    icon: `${env.appUrl}/icon-192.png`,
    badge: `${env.appUrl}/icon-192.png`,
    ...payload,
  }
  const notification = JSON.stringify(finalPayload)
  const expiredIds: string[] = []

  await Promise.allSettled(
    subs.map(async (sub) => {
      const subscription = {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth },
      }

      try {
        await webpush.sendNotification(subscription, notification, {
          TTL: 86400, // 24 h — deliver when the device comes back online
          urgency: 'normal',
        })
      } catch (err: any) {
        const status: number = err?.statusCode ?? 0

        // 410 Gone / 404 Not Found = subscription revoked or expired
        if (status === 410 || status === 404) {
          expiredIds.push(sub.id)
          return
        }

        // 429 Too Many Requests or 5xx = transient push-service error → retry once
        if (status === 429 || status >= 500) {
          await new Promise((r) => setTimeout(r, 1000))
          try {
            await webpush.sendNotification(subscription, notification, {
              TTL: 86400,
              urgency: 'normal',
            })
          } catch (retryErr: any) {
            logger.warn(
              {
                userId,
                endpoint: sub.endpoint.slice(0, 60),
                status: retryErr?.statusCode,
              },
              'Push retry failed',
            )
          }
          return
        }

        logger.warn(
          { userId, endpoint: sub.endpoint.slice(0, 60), status },
          'Push send failed',
        )
      }
    }),
  )

  // Batch-delete all expired subscriptions in a single query
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
}
