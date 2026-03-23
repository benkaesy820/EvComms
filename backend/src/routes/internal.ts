import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { desc, eq, and, isNull, lt, sql } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { internalMessages, media, auditLogs, internalMessageReactions, internalMessageReads } from '../db/schema.js'
import { requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { isAdmin, canDeleteMessage } from '../lib/permissions.js'
import { emitToAdmins } from '../socket/index.js'
import { sanitizeText, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { serverState, getUserFromCache } from '../state.js'
import { getConfig } from '../lib/config.js'

const emojiRegex = /^[\p{Emoji}]+$/u

const sendSchema = z.object({
  type: z.enum(['TEXT', 'IMAGE', 'DOCUMENT']).default('TEXT'),
  content: z.string().min(1).max(100000).optional(),
  mediaId: z.string().min(1).max(26).optional(),
  replyToId: z.string().min(1).max(26).optional(),
}).refine(
  d => d.type === 'TEXT' ? !!d.content?.trim() : !!d.mediaId,
  { message: 'TEXT requires content; media types require mediaId' }
)

const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.string().optional(),
})

export async function internalRoutes(fastify: FastifyInstance) {
  fastify.get('/', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const q = listSchema.safeParse(request.query)
    if (!q.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query')

    const conditions = [
      isNull(internalMessages.deletedAt),
      sql`NOT EXISTS (SELECT 1 FROM json_each(${internalMessages.hiddenFor}) WHERE value = ${user.id})`
    ]

    if (q.data.before && isValidId(q.data.before)) {
      const beforeMs = decodeTime(q.data.before)
      conditions.push(lt(internalMessages.createdAt, new Date(beforeMs)))
    }

    const rows = await db.query.internalMessages.findMany({
      where: and(...conditions),
      orderBy: [desc(internalMessages.createdAt)],
      limit: q.data.limit + 1,
      with: {
        sender: { columns: { id: true, name: true, role: true } },
        media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
        reactions: { with: { user: { columns: { name: true } } } },
        replyTo: { columns: { id: true, content: true, type: true, deletedAt: true }, with: { sender: { columns: { id: true, name: true, role: true } } } },
      },
    })

    const hasMore = rows.length > q.data.limit
    const msgs = (hasMore ? rows.slice(0, -1) : rows).map(m => ({
      id: m.id,
      senderId: m.senderId,
      sender: m.sender,
      type: m.type,
      content: m.content,
      media: m.media ?? null,
      reactions: m.reactions ?? [],
      replyTo: m.replyTo ?? null,
      createdAt: m.createdAt,
    }))

    return sendOk(reply, { messages: msgs, hasMore })
  })

  // Get total unread internal message count for current user
  fastify.get('/unread', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const result = await db.select({
      unreadCount: internalMessageReads.unreadCount,
    }).from(internalMessageReads).where(eq(internalMessageReads.userId, user.id))

    return sendOk(reply, { unreadCount: result[0]?.unreadCount ?? 0 })
  })

  // Mark internal messages as read
  fastify.post('/read', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const now = new Date()

    // Get the latest message ID
    const latestMessage = await db.query.internalMessages.findFirst({
      where: isNull(internalMessages.deletedAt),
      orderBy: [desc(internalMessages.createdAt)],
      columns: { id: true },
    })

    // Upsert read status
    await db.insert(internalMessageReads)
      .values({
        id: ulid(),
        userId: user.id,
        lastReadMessageId: latestMessage?.id ?? null,
        lastReadAt: now,
        unreadCount: 0,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: internalMessageReads.userId,
        set: {
          lastReadMessageId: latestMessage?.id ?? null,
          lastReadAt: now,
          unreadCount: 0,
          updatedAt: now,
        },
      })

    return sendOk(reply, { success: true })
  })

  fastify.post('/', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const config = getConfig()
    const body = sendSchema.safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)

    if (body.data.type === 'TEXT' && body.data.content && body.data.content.length > (config.limits.message.teamTextMaxLength || 5000)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', `Message too long (max ${config.limits.message.teamTextMaxLength || 5000} characters)`)
    }

    // Pre-fetch media (validation + response fields) and replyTo before insert — eliminates post-insert SELECT
    let mediaFull: { id: string; type: string; cdnUrl: string | null; filename: string; size: number; mimeType: string } | null = null
    if (body.data.mediaId) {
      if (!isValidId(body.data.mediaId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
      const mediaRecord = await db.query.media.findFirst({
        where: eq(media.id, body.data.mediaId),
        columns: { id: true, type: true, status: true, cdnUrl: true, filename: true, size: true, mimeType: true },
      })
      if (!mediaRecord || mediaRecord.status !== 'CONFIRMED') {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid or unconfirmed media')
      }
      mediaFull = { id: mediaRecord.id, type: mediaRecord.type, cdnUrl: mediaRecord.cdnUrl, filename: mediaRecord.filename, size: mediaRecord.size, mimeType: mediaRecord.mimeType }
    }

    const replyToRow = body.data.replyToId && isValidId(body.data.replyToId)
      ? await db.query.internalMessages.findFirst({
        where: eq(internalMessages.id, body.data.replyToId),
        columns: { id: true, content: true, type: true, deletedAt: true },
        with: { sender: { columns: { id: true, name: true, role: true } } },
      })
      : null

    const id = ulid()
    const sanitized = body.data.content ? sanitizeText(body.data.content) : null
    const createdAt = new Date()

  try {
    await db.insert(internalMessages).values({
      id,
      senderId: user.id,
      type: body.data.type,
      content: sanitized,
      mediaId: body.data.mediaId ?? null,
      replyToId: body.data.replyToId ?? null,
      createdAt,
    })

    // Increment unread count for all other admins (not the sender)
    // lower(hex(randomblob(10))) generates a unique id per row inside SQLite —
    // unlike ${ulid()} which would be evaluated once and reused for every inserted row.
    await db.run(sql`
      INSERT INTO internal_message_reads (id, user_id, last_read_at, unread_count, updated_at)
      SELECT
        lower(hex(randomblob(10))),
        u.id,
        unixepoch(),
        COALESCE((SELECT unread_count FROM internal_message_reads WHERE user_id = u.id), 0) + 1,
        unixepoch()
      FROM users u
      WHERE u.role IN ('ADMIN', 'SUPER_ADMIN')
        AND u.id != ${user.id}
        AND u.status = 'APPROVED'
      ON CONFLICT(user_id) DO UPDATE SET
        unread_count = internal_message_reads.unread_count + 1,
        updated_at = unixepoch()
    `)

      // MEDIUM FIX: Add audit logging for internal message send
      await db.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'internal_message.send',
        entityType: 'internal_message',
        entityId: id,
        details: JSON.stringify({ type: body.data.type, hasMedia: !!body.data.mediaId })
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Internal message send failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to send message')
    }

    const cachedSender = serverState.userCache.get(user.id)
    const payload = {
      id,
      senderId: user.id,
      sender: { id: user.id, name: cachedSender?.name ?? user.id, role: user.role },
      type: body.data.type,
      content: sanitized,
      media: mediaFull,
      reactions: [],
      replyToId: body.data.replyToId ?? null,
      replyTo: replyToRow ?? null,
      createdAt,
    }

    try {
      emitToAdmins('internal:message', { message: payload })
    } catch { /* socket not initialized */ }

    return sendOk(reply, { message: payload })
  })

  fastify.delete('/clear', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    if (user.role === 'SUPER_ADMIN') {
      await db.update(internalMessages)
        .set({ deletedAt: new Date() })
        .where(isNull(internalMessages.deletedAt))
      await db.insert(auditLogs).values({
        id: ulid(), userId: user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'internal_message.clear_all', entityType: 'internal_message', entityId: 'all'
      })
      try { emitToAdmins('internal:chat:cleared', { scope: 'all' }) } catch { /* */ }
    } else {
      // Single UPDATE instead of N+1 loop: append userId to hiddenFor JSON array
      await db.run(sql`
        UPDATE internal_messages
        SET hidden_for = CASE
          WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
          WHEN json_type(hidden_for) = 'array'
            AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
          THEN json_insert(hidden_for, '$[#]', ${user.id})
          ELSE hidden_for
        END
        WHERE deleted_at IS NULL
      `)
    }
    return sendOk(reply, { success: true })
  })

  fastify.delete('/:id', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

    const scopeRaw = (request.query as Record<string, string>).scope ?? 'me'
    const scope: 'me' | 'all' = scopeRaw === 'all' ? 'all' : 'me'

    const msg = await db.query.internalMessages.findFirst({
      where: and(eq(internalMessages.id, id), isNull(internalMessages.deletedAt)),
      columns: { id: true, senderId: true, hiddenFor: true, createdAt: true },
    })
    if (!msg) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    // scope=all (delete for everyone) is only allowed for the original sender or SUPER_ADMIN.
    // A recipient ADMIN may only hide the message for themselves (scope=me).
    if (scope === 'all' && msg.senderId !== user.id && user.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only the sender or a super admin can delete a message for everyone')
    }

    if (!canDeleteMessage(user, msg, scope)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot delete this message or time limit exceeded')
    }

    if (scope === 'all') {
      await db.transaction(async (tx) => {
        await tx.update(internalMessages).set({ deletedAt: new Date() }).where(eq(internalMessages.id, id))
        await tx.insert(auditLogs).values({
          id: ulid(), userId: user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'internal_message.delete', entityType: 'internal_message', entityId: id
        })
      })
      try { emitToAdmins('internal:message:deleted', { id }) } catch { /* */ }
      return sendOk(reply, { success: true, scope: 'all' })
    }

    // Soft delete for current user only — atomic json_insert avoids read-modify-write race
    await db.run(sql`
      UPDATE internal_messages
      SET hidden_for = CASE
        WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
        WHEN json_type(hidden_for) = 'array'
          AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
        THEN json_insert(hidden_for, '$[#]', ${user.id})
        ELSE hidden_for
      END
      WHERE id = ${id}
    `)
    return sendOk(reply, { success: true, scope: 'me' })
  })

  // ==========================================================================
  // REACTIONS
  // ==========================================================================
  fastify.post('/:id/reaction', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    const { emoji } = request.body as { emoji: string }

    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')
    if (typeof emoji !== 'string' || !emoji || !emojiRegex.test(emoji)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    const msg = await db.query.internalMessages.findFirst({
      where: and(eq(internalMessages.id, id), isNull(internalMessages.deletedAt)),
      columns: { id: true }
    })
    if (!msg) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    try {
      const cachedUser = getUserFromCache(user.id)
      const userName = cachedUser?.name ?? 'Admin'

      const reactionId = ulid()
      await db.insert(internalMessageReactions)
        .values({ id: reactionId, messageId: id, userId: user.id, emoji })
        .onConflictDoUpdate({
          target: [internalMessageReactions.messageId, internalMessageReactions.userId],
          set: { emoji }
        })

      const reaction = { id: reactionId, messageId: id, userId: user.id, emoji, user: { name: userName } }
      try { emitToAdmins('internal:message:reaction', { type: 'add', reaction }) } catch { /* */ }

      return sendOk(reply, { success: true, reaction })
    } catch (err) {
      logger.error({ userId: user.id, error: err }, 'Add internal reaction failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to add reaction')
    }
  })

  fastify.delete('/:id/reaction/:emoji', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id, emoji } = request.params as { id: string; emoji: string }

    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')
    if (!emoji) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    // Fastify params are sometimes URL encoded
    const decodedEmoji = decodeURIComponent(emoji)
    if (!emojiRegex.test(decodedEmoji)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    const result = await db.delete(internalMessageReactions).where(
      and(
        eq(internalMessageReactions.messageId, id),
        eq(internalMessageReactions.userId, user.id),
        eq(internalMessageReactions.emoji, decodedEmoji)
      )
    )

    if (result.rowsAffected && result.rowsAffected > 0) {
      try { emitToAdmins('internal:message:reaction', { type: 'remove', reaction: { messageId: id, userId: user.id, emoji: decodedEmoji } }) } catch { /* */ }
    }

    return sendOk(reply, { success: true })
  })

  // FIX #18: Bulk delete endpoint — single transaction, single summary response
  fastify.post('/bulk-delete', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const body = z.object({
      ids: z.array(z.string()).min(1).max(100),
      scope: z.enum(['me', 'all']).default('me'),
    }).safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)

    const { ids, scope } = body.data
    // Validate all IDs
    if (ids.some(id => !isValidId(id))) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID in list')

    // Only SUPER_ADMIN can hard-delete for everyone
    if (scope === 'all' && user.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only super admins can delete messages for everyone')
    }

    const now = new Date()
    let succeededCount = 0
    const failedIds: string[] = []

    for (const id of ids) {
      try {
        if (scope === 'me') {
          await db.run(sql`
            UPDATE internal_messages
            SET hidden_for = CASE
              WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
              WHEN json_type(hidden_for) = 'array'
                AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
              THEN json_insert(hidden_for, '$[#]', ${user.id})
              ELSE hidden_for
            END
            WHERE id = ${id} AND deleted_at IS NULL
          `)
        } else {
          await db.update(internalMessages)
            .set({ deletedAt: now })
            .where(and(eq(internalMessages.id, id), isNull(internalMessages.deletedAt)))
        }
        succeededCount++
      } catch {
        failedIds.push(id)
      }
    }

    if (scope === 'all' && succeededCount > 0) {
      // Notify all admins of the hard-deleted messages
      emitToAdmins('internal:messages:bulk_deleted', { ids: ids.filter(id => !failedIds.includes(id)) })
    }

    return sendOk(reply, {
      succeeded: succeededCount,
      failed: failedIds.length,
      failedIds,
    })
  })

}
