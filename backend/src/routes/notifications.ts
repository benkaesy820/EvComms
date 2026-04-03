import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { ulid } from 'ulid'
import { eq, and } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '../db/index.js'
import { pushSubscriptions } from '../db/schema.js'
import { env } from '../lib/env.js'
import { logger } from '../lib/logger.js'
import { sendPushToUser } from '../lib/webPush.js'

const subscribeSchema = z.object({
  endpoint: z.string().url(),
  keys: z.object({
    p256dh: z.string().min(1),
    auth: z.string().min(1),
  }),
})

const unsubscribeSchema = z.object({
  endpoint: z.string().url(),
})

export async function notificationRoutes(fastify: FastifyInstance): Promise<void> {
  // GET /api/notifications/vapid-public-key
  // Returns the VAPID public key so the frontend JS can subscribe
  fastify.get('/vapid-public-key', async (_req: FastifyRequest, reply: FastifyReply) => {
    if (!env.vapidPublicKey) {
      return reply.code(503).send({ success: false, error: { code: 'PUSH_NOT_CONFIGURED', message: 'Web push not configured' } })
    }
    return reply.send({ success: true, publicKey: env.vapidPublicKey })
  })

  // POST /api/notifications/subscribe
  fastify.post('/subscribe', async (req: FastifyRequest, reply: FastifyReply) => {
    logger.info({ userId: req?.user?.id }, 'Push subscribe request received')
    if (!req.user) return reply.code(401).send({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    if (!env.vapidPublicKey) {
      return reply.code(503).send({ success: false, error: { code: 'PUSH_NOT_CONFIGURED', message: 'Web push not configured' } })
    }

    const parsed = subscribeSchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ success: false, error: { code: 'VALIDATION_ERROR', message: parsed.error.issues.map(i => i.message).join(', ') } })
    }

    const { endpoint, keys } = parsed.data
    const userAgent = (req.headers['user-agent'] ?? '').slice(0, 512)

    try {
      // Upsert: same endpoint = update keys + userId (handle browser re-subscribe)
      const existing = await db.query.pushSubscriptions.findFirst({
        where: eq(pushSubscriptions.endpoint, endpoint),
        columns: { id: true, userId: true },
      })

      if (existing) {
        await db.update(pushSubscriptions)
          .set({ userId: req.user.id, p256dh: keys.p256dh, auth: keys.auth, userAgent, updatedAt: new Date() })
          .where(eq(pushSubscriptions.id, existing.id))
      } else {
        await db.insert(pushSubscriptions).values({
          id: ulid(),
          userId: req.user.id,
          endpoint,
          p256dh: keys.p256dh,
          auth: keys.auth,
          userAgent,
        })
      }

      logger.info({ userId: req.user.id, endpoint: endpoint.slice(0, 60) }, 'Push subscription saved')
      return reply.code(201).send({ success: true })
    } catch (err) {
      logger.error({ err, userId: req.user.id }, 'Failed to save push subscription')
      return reply.code(500).send({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Failed to save subscription' } })
    }
  })

  // DELETE /api/notifications/unsubscribe
  fastify.delete('/unsubscribe', async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.user) return reply.code(401).send({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })

    const parsed = unsubscribeSchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ success: false, error: { code: 'VALIDATION_ERROR', message: 'Invalid endpoint' } })
    }

    await db.delete(pushSubscriptions).where(
      and(
        eq(pushSubscriptions.endpoint, parsed.data.endpoint),
        eq(pushSubscriptions.userId, req.user.id)
      )
    )

    return reply.send({ success: true })
  })

  // POST /api/notifications/test-push
  // Dev/debug endpoint: sends a real push notification to the authenticated user.
  // Bypasses the "user must be offline" socket guard so you can verify the full
  // VAPID → push-service → service-worker → OS-banner pipeline from curl.
  // Restricted to SUPER_ADMIN to prevent misuse.
  fastify.post('/test-push', async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.user) return reply.code(401).send({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    if (req.user.role !== 'SUPER_ADMIN') return reply.code(403).send({ success: false, error: { code: 'FORBIDDEN', message: 'Super admin only' } })

    const subs = await db.query.pushSubscriptions.findMany({
      where: eq(pushSubscriptions.userId, req.user.id),
      columns: { id: true, endpoint: true },
    })

    if (subs.length === 0) {
      return reply.code(404).send({
        success: false,
        error: { code: 'NO_SUBSCRIPTION', message: 'No push subscription found for your account. Enable notifications in Settings first.' },
      })
    }

    try {
      await sendPushToUser(req.user.id, {
        title: '🔔 EvComms Test',
        body: 'Push notifications are working correctly!',
        tag: 'test-push',
        data: { url: '/' },
      })
      logger.info({ userId: req.user.id, subscriptions: subs.length }, 'Test push sent')
      return reply.send({ success: true, message: `Push sent to ${subs.length} device(s)` })
    } catch (err) {
      logger.error({ err, userId: req.user.id }, 'Test push failed')
      return reply.code(500).send({ success: false, error: { code: 'PUSH_FAILED', message: 'Push delivery failed. Check server logs for details.' } })
    }
  })
}
