import webpush from 'web-push'
import { eq } from 'drizzle-orm'
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
  webpush.setVapidDetails(env.vapidSubject, env.vapidPublicKey, env.vapidPrivateKey)
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
 * Silently removes subscriptions that have expired or been rejected by the push service.
 */
export async function sendPushToUser(userId: string, payload: PushPayload): Promise<void> {
  ensureInitialized()
  if (!initialized) return

  const subs = await db.query.pushSubscriptions.findMany({
    where: eq(pushSubscriptions.userId, userId),
    columns: { id: true, endpoint: true, p256dh: true, auth: true },
  })

  if (subs.length === 0) return

  const notification = JSON.stringify(payload)
  const expiredIds: string[] = []

  await Promise.allSettled(
    subs.map(async (sub) => {
      try {
        await webpush.sendNotification(
          { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
          notification,
          { TTL: 86400 } // 24h TTL — deliver when the device comes online
        )
      } catch (err: any) {
        // HTTP 410 Gone = subscription expired/revoked — clean it up
        if (err?.statusCode === 410 || err?.statusCode === 404) {
          expiredIds.push(sub.id)
        } else {
          logger.warn({ userId, endpoint: sub.endpoint, status: err?.statusCode }, 'Push send failed')
        }
      }
    })
  )

  if (expiredIds.length > 0) {
    await Promise.allSettled(
      expiredIds.map((id) => db.delete(pushSubscriptions).where(eq(pushSubscriptions.id, id)))
    )
    logger.info({ userId, count: expiredIds.length }, 'Cleaned up expired push subscriptions')
  }
}
