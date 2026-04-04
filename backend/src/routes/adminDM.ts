import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { and, desc, eq, isNull, inArray, lt, or, sql } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { directMessages, users, directMessageReactions, media, auditLogs, dmRecipientStatus } from '../db/schema.js'
import { requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { canDeleteMessage } from '../lib/permissions.js'
import { sanitizeText, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { emitToUser, isUserOnlineGlobally } from '../socket/index.js'
import { serverState, getUserFromCache } from '../state.js'
import { logger } from '../lib/logger.js'
import { getConfig } from '../lib/config.js'
import { sendPushToUser } from '../lib/webPush.js'

const emojiRegex = /^[\p{Emoji}]+$/u

// Zod schema for reaction body — NFC-normalises emoji before storage so
// encoding-equivalent sequences (composed vs decomposed) always match.
const reactionBodySchema = z.object({
  emoji: z.string().min(1).max(10)
    .transform(s => s.normalize('NFC'))
    .pipe(z.string().regex(emojiRegex, 'Must be valid emoji'))
})

const sendDMSchema = z.object({
  content: z.string().min(1).max(100000).optional(),
  type: z.enum(['TEXT', 'IMAGE', 'DOCUMENT']).default('TEXT'),
  mediaId: z.string().min(1).max(26).optional(),
  tempId: z.string().max(64).optional(),
  replyToId: z.string().min(1).max(26).optional(),
}).refine(d => d.content || d.mediaId, { message: 'content or mediaId required' })

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.string().optional(),
})

export async function adminDMRoutes(fastify: FastifyInstance) {
  // HIGH FIX: Use requireAdmin preHandler for all admin DM endpoints
  fastify.get('/dm/conversations', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const q = paginationSchema.safeParse(request.query)
    const limit = q.success ? q.data.limit : 50
    const before = q.success ? q.data.before : undefined

    let beforeTs: number | undefined
    if (before && isValidId(before)) {
      beforeTs = decodeTime(before)
    }

    // Single query: join partner user row, filter by admin role, group by partner — no JS sort/filter
    const rows = await db
      .select({
        partnerId: sql<string>`CASE WHEN ${directMessages.senderId} = ${user.id} THEN ${directMessages.recipientId} ELSE ${directMessages.senderId} END`,
        partnerName: users.name,
        partnerRole: users.role,
        msgId: sql<string>`max(${directMessages.id})`,
        content: directMessages.content,
        type: directMessages.type,
        senderId: directMessages.senderId,
        createdAt: directMessages.createdAt,
      })
      .from(directMessages)
      .innerJoin(users, sql`${users.id} = CASE WHEN ${directMessages.senderId} = ${user.id} THEN ${directMessages.recipientId} ELSE ${directMessages.senderId} END`)
      .where(and(
        isNull(directMessages.deletedAt),
        sql`NOT EXISTS (SELECT 1 FROM json_each(${directMessages.hiddenFor}) WHERE value = ${user.id})`,
        or(eq(directMessages.senderId, user.id), eq(directMessages.recipientId, user.id))!,
        inArray(users.role, ['ADMIN', 'SUPER_ADMIN'] as const),
        beforeTs ? lt(directMessages.createdAt, new Date(beforeTs)) : undefined
      ))
      .groupBy(sql`CASE WHEN ${directMessages.senderId} = ${user.id} THEN ${directMessages.recipientId} ELSE ${directMessages.senderId} END`)
      .orderBy(sql`max(${directMessages.id}) DESC`)
      .limit(limit + 1)

    const hasMore = rows.length > limit
    const page = hasMore ? rows.slice(0, limit) : rows

    // Fetch unread counts for each conversation partner
    const partnerIds = page.map(r => r.partnerId).filter((id): id is string => !!id)
    const unreadCounts = partnerIds.length > 0
      ? await db.select({
          partnerId: dmRecipientStatus.partnerId,
          unreadCount: dmRecipientStatus.unreadCount,
        }).from(dmRecipientStatus)
        .where(and(
          eq(dmRecipientStatus.userId, user.id),
          inArray(dmRecipientStatus.partnerId, partnerIds)
        ))
      : []

    const unreadCountMap = new Map(unreadCounts.map(u => [u.partnerId, u.unreadCount]))

    const conversations = page.map(r => {
      const ts = r.createdAt instanceof Date ? r.createdAt.getTime() : Number(r.createdAt)
      return {
        partner: { id: r.partnerId, name: r.partnerName, role: r.partnerRole },
        lastMessage: { id: r.msgId, content: r.content, type: r.type, senderId: r.senderId, createdAt: ts },
        unreadCount: unreadCountMap.get(r.partnerId) ?? 0,
      }
    })

    return sendOk(reply, { conversations, hasMore })
  })

  fastify.get('/dm/:adminId', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { adminId } = request.params as { adminId: string }
    if (!isValidId(adminId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin ID')
    if (adminId === user.id) return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot DM yourself')

    const other = await db.query.users.findFirst({
      where: and(eq(users.id, adminId), eq(users.status, 'APPROVED')),
      columns: { id: true, name: true, role: true }
    })
    if (!other || (other.role !== 'ADMIN' && other.role !== 'SUPER_ADMIN')) {
      return sendError(reply, 404, 'NOT_FOUND', 'Admin not found or not active')
    }
    const q = paginationSchema.safeParse(request.query)
    const limit = q.success ? q.data.limit : 50
    const before = q.success ? q.data.before : undefined

    const conditions = [
      isNull(directMessages.deletedAt),
      sql`NOT EXISTS (SELECT 1 FROM json_each(${directMessages.hiddenFor}) WHERE value = ${user.id})`,
      or(
        and(eq(directMessages.senderId, user.id), eq(directMessages.recipientId, adminId)),
        and(eq(directMessages.senderId, adminId), eq(directMessages.recipientId, user.id))
      )!
    ]

    if (before && isValidId(before)) {
      // Decode timestamp from ULID — no extra DB round-trip needed
      const beforeMs = decodeTime(before)
      conditions.push(lt(directMessages.createdAt, new Date(beforeMs)))
    }

    const msgs = await db.query.directMessages.findMany({
      where: and(...conditions),
      orderBy: [desc(directMessages.createdAt)],
      limit: limit + 1,
      with: {
        sender: { columns: { id: true, name: true, role: true } },
        media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
        reactions: { with: { user: { columns: { name: true } } } },
        replyTo: { columns: { id: true, content: true, type: true, deletedAt: true }, with: { sender: { columns: { id: true, name: true, role: true } } } }
      }
    })

    const hasMore = msgs.length > limit
    const result = (hasMore ? msgs.slice(0, -1) : msgs).map(msg => ({
      ...msg,
      replyTo: msg.replyTo
        ? {
          ...msg.replyTo,
          // Don't expose content of soft-deleted reply targets (#28)
          content: msg.replyTo.deletedAt ? null : msg.replyTo.content,
        }
        : null,
    }))

    return sendOk(reply, { messages: result, hasMore, partner: other })
  })

  fastify.post('/dm/:adminId', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return


    const { adminId } = request.params as { adminId: string }
    if (!isValidId(adminId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin ID')
    if (adminId === user.id) return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot DM yourself')

    const other = await db.query.users.findFirst({
      where: and(eq(users.id, adminId), eq(users.status, 'APPROVED')),
      columns: { id: true, name: true, role: true }
    })
    if (!other || (other.role !== 'ADMIN' && other.role !== 'SUPER_ADMIN')) {
      return sendError(reply, 404, 'NOT_FOUND', 'Admin not found')
    }

    const body = sendDMSchema.safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)

    const config = getConfig()
    const { type, mediaId, tempId } = body.data
    const content = body.data.content ? sanitizeText(body.data.content) : null

    if (type === 'TEXT' && content && content.length > (config.limits.message.teamTextMaxLength || 5000)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', `Message too long (max ${config.limits.message.teamTextMaxLength || 5000} characters)`)
    }

    const id = ulid()
    const createdAt = new Date()

    // Pre-fetch media and replyTo before insert — eliminates post-insert SELECT
    const [mediaRecord, replyToRow] = await Promise.all([
      mediaId
        ? db.query.media.findFirst({
          where: eq(media.id, mediaId),
          columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true }
        })
        : Promise.resolve(null),
      body.data.replyToId
        ? db.query.directMessages.findFirst({
          where: eq(directMessages.id, body.data.replyToId),
          columns: { id: true, content: true, type: true, deletedAt: true },
          with: { sender: { columns: { id: true, name: true, role: true } } }
        })
        : Promise.resolve(null),
    ])

    try {
      // C-5 FIX: All three writes in one atomic transaction.
      // A crash between any two previously left the DM without an audit log or a missing
      // unread-count bump for the recipient.
      await db.transaction(async (tx) => {
        await tx.insert(directMessages).values({ id, senderId: user.id, recipientId: adminId, type, content, mediaId: mediaId ?? null, replyToId: body.data.replyToId ?? null, createdAt })

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'direct_message.send',
          entityType: 'direct_message',
          entityId: id,
          details: JSON.stringify({ recipientId: adminId, type, hasMedia: !!mediaId })
        })

        // Increment recipient's unread count for this conversation.
        const now = new Date()
        await tx.insert(dmRecipientStatus)
          .values({
            id: ulid(),
            userId: adminId,
            partnerId: user.id,
            lastReadAt: now,
            unreadCount: 1,
            updatedAt: now,
          })
          .onConflictDoUpdate({
            target: [dmRecipientStatus.userId, dmRecipientStatus.partnerId],
            set: {
              unreadCount: sql`${dmRecipientStatus.unreadCount} + 1`,
              updatedAt: now,
            },
          })
      })
    } catch (err) {
      logger.error({ userId: user.id, error: err }, 'DM send failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to send message')
    }

    const cachedSender = getUserFromCache(user.id)
    const msg = {
      id,
      senderId: user.id,
      sender: { id: user.id, name: cachedSender?.name ?? user.id, role: user.role },
      recipientId: adminId,
      type,
      content,
      mediaId: mediaId ?? null,
      media: mediaRecord ?? null,
      hiddenFor: null,
      deletedAt: null,
      replyToId: body.data.replyToId ?? null,
      replyTo: replyToRow ?? null,
      reactions: [],
      createdAt,
    }

    emitToUser(adminId, 'dm:message', { message: msg, tempId })

    // Push: cross-instance online check
    const recipientOnline = await isUserOnlineGlobally(adminId)
    if (!recipientOnline) {
      const senderName = getUserFromCache(user.id)?.name ?? 'DM'
      const preview = content
        ? content.slice(0, 80) + (content.length > 80 ? '\u2026' : '')
        : type === 'IMAGE' ? '[Image]' : '[File]'
      sendPushToUser(adminId, {
        title: `${senderName} (Direct Message)`,
        body: preview,
        tag: `dm:${user.id}`,
        data: { url: `/admin/dm?partner=${user.id}` },
      }).catch(e => logger.warn({ e }, 'Push to DM recipient failed'))
    }

    reply.code(201)
    return sendOk(reply, { message: msg, tempId })
  })

  fastify.delete('/dm/message/:messageId', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return


    const { messageId } = request.params as { messageId: string }
    if (!isValidId(messageId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID')

    const scopeRaw = (request.query as { scope?: string }).scope ?? 'me'
    const scope: 'me' | 'all' = scopeRaw === 'all' ? 'all' : 'me'

    const msg = await db.query.directMessages.findFirst({
      where: and(eq(directMessages.id, messageId), isNull(directMessages.deletedAt)),
      columns: { id: true, senderId: true, recipientId: true, hiddenFor: true, createdAt: true }
    })

    if (!msg) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    // Only actual participants (or super admin) should even attempt deletion
    if (msg.senderId !== user.id && msg.recipientId !== user.id && user.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Not part of this conversation')
    }

    // scope=all (delete for everyone) is only allowed for the original sender or SUPER_ADMIN.
    // A recipient ADMIN may only hide the message for themselves (scope=me).
    if (scope === 'all' && msg.senderId !== user.id && user.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only the sender or a super admin can delete a message for everyone')
    }

    if (!canDeleteMessage(user, msg, scope)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot delete this message or time limit exceeded')
    }

    const now = new Date()

    if (scope === 'me') {
      await db.run(sql`
        UPDATE direct_messages
        SET hidden_for = CASE
          WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
          WHEN json_type(hidden_for) = 'array'
            AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
          THEN json_insert(hidden_for, '$[#]', ${user.id})
          ELSE hidden_for
        END
        WHERE id = ${messageId}
      `)
      
      // MEDIUM FIX: Add audit logging for soft delete (scope=me)
      await db.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'dm.message_hidden',
        entityType: 'direct_message',
        entityId: messageId,
        details: JSON.stringify({ scope: 'me' })
      })
    } else {
      await db.update(directMessages).set({ deletedAt: now }).where(eq(directMessages.id, messageId))
      const otherId = msg.senderId === user.id ? msg.recipientId : msg.senderId
      emitToUser(otherId, 'dm:message:deleted', { messageId })
      
      // Audit log for hard delete (#audit-fix)
      await db.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'dm.message_deleted',
        entityType: 'direct_message',
        entityId: messageId,
        details: JSON.stringify({ otherId, scope })
      })
    }

    return sendOk(reply, { success: true })
  })

  fastify.post('/dm/:adminId/bulk-delete', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { adminId } = request.params as { adminId: string }
    if (!isValidId(adminId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin ID')

    const body = z.object({
      ids: z.array(z.string()).min(1).max(100),
      scope: z.enum(['me', 'all']).default('me'),
    }).safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)

    const { ids, scope } = body.data
    if (ids.some(id => !isValidId(id))) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID in list')

    const now = new Date()
    let succeededCount = 0
    const failedIds: string[] = []

    // H-6 FIX: Pre-fetch all rows in one inArray query instead of one SELECT per message.
    let rows: { id: string; senderId: string; recipientId: string; hiddenFor: string | null; createdAt: Date }[] = []
    try {
      rows = await db.query.directMessages.findMany({
        where: and(inArray(directMessages.id, ids), isNull(directMessages.deletedAt)),
        columns: { id: true, senderId: true, recipientId: true, hiddenFor: true, createdAt: true }
      })
    } catch {
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to fetch messages')
    }

    const rowMap = new Map(rows.map(r => [r.id, r]))

    // Auth-check every id in-memory against pre-fetched rows.
    const authorizedIds: string[] = []
    for (const id of ids) {
      const msg = rowMap.get(id)
      if (!msg) { failedIds.push(id); continue }
      if (msg.senderId !== user.id && msg.recipientId !== user.id && user.role !== 'SUPER_ADMIN') {
        failedIds.push(id); continue
      }
      if (scope === 'all' && msg.senderId !== user.id && user.role !== 'SUPER_ADMIN') {
        failedIds.push(id); continue
      }
      if (!canDeleteMessage(user, msg, scope)) {
        failedIds.push(id); continue
      }
      authorizedIds.push(id)
    }

    if (authorizedIds.length > 0) {
      if (scope === 'me') {
        // Single batched UPDATE for all authorised ids — eliminates N writes.
        try {
          await db.run(sql`
            UPDATE direct_messages
            SET hidden_for = CASE
              WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
              WHEN json_type(hidden_for) = 'array'
                AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
              THEN json_insert(hidden_for, '$[#]', ${user.id})
              ELSE hidden_for
            END
            WHERE id IN (${sql.join(authorizedIds.map(id => sql`${id}`), sql`, `)})
              AND deleted_at IS NULL
          `)
          succeededCount = authorizedIds.length
        } catch {
          failedIds.push(...authorizedIds)
        }
      } else {
        // scope=all: hard-delete each individually (row count matters for success tracking).
        for (const id of authorizedIds) {
          try {
            await db.update(directMessages).set({ deletedAt: now }).where(eq(directMessages.id, id))
            succeededCount++
          } catch {
            failedIds.push(id)
          }
        }
      }
    }

    if (scope === 'all' && succeededCount > 0) {
      try {
        const successfulIds = ids.filter(id => !failedIds.includes(id))
        emitToUser(user.id, 'dm:messages:bulk_deleted', { adminId, ids: successfulIds })
        emitToUser(adminId, 'dm:messages:bulk_deleted', { adminId: user.id, ids: successfulIds })
      } catch { /* socket error — non-fatal */ }
    }

    return sendOk(reply, { succeeded: succeededCount, failed: failedIds.length, failedIds })
  })

  fastify.delete('/dm/:adminId/clear', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { adminId } = request.params as { adminId: string }
    if (!isValidId(adminId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin ID')

    await db.run(sql`
      UPDATE direct_messages
      SET hidden_for = CASE
        WHEN hidden_for IS NULL OR hidden_for = '[]' THEN json_array(${user.id})
        WHEN json_type(hidden_for) = 'array'
          AND NOT EXISTS (SELECT 1 FROM json_each(hidden_for) WHERE value = ${user.id})
        THEN json_insert(hidden_for, '$[#]', ${user.id})
        ELSE hidden_for
      END
      WHERE deleted_at IS NULL
      AND (
        (sender_id = ${user.id} AND recipient_id = ${adminId})
        OR
        (sender_id = ${adminId} AND recipient_id = ${user.id})
      )
    `)
    return sendOk(reply, { success: true })
  })

  // ========================================================================
  // UNREAD COUNT & MARK READ
  // ========================================================================

  // Get total unread DM count for current user
  fastify.get('/dm/unread', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const result = await db.select({
      totalUnread: sql<number>`COALESCE(SUM(${dmRecipientStatus.unreadCount}), 0)`,
    }).from(dmRecipientStatus).where(eq(dmRecipientStatus.userId, user.id))

    return sendOk(reply, { unreadCount: result[0]?.totalUnread ?? 0 })
  })

  // Mark DMs with a specific partner as read
  fastify.post('/dm/:adminId/read', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { adminId } = request.params as { adminId: string }
    if (!isValidId(adminId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin ID')

    const now = new Date()

    // Upsert: set unread count to 0 and update last read timestamp
    await db.insert(dmRecipientStatus)
      .values({
        id: ulid(),
        userId: user.id,
        partnerId: adminId,
        lastReadAt: now,
        unreadCount: 0,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: [dmRecipientStatus.userId, dmRecipientStatus.partnerId],
        set: {
          unreadCount: 0,
          lastReadAt: now,
          updatedAt: now,
        },
      })

    // Notify partner that their outgoing messages have been read
    emitToUser(adminId, 'dm:read', { partnerId: user.id, readAt: now.getTime() })

    return sendOk(reply, { success: true })
  })

// ========================================================================
  // REACTIONS
  // ========================================================================
  fastify.post('/dm/:adminId/:messageId/reaction', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return


    const { adminId, messageId } = request.params as { adminId: string; messageId: string }

    if (!isValidId(adminId) || !isValidId(messageId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid IDs')

    // Validate + NFC-normalise via Zod (replaces unsafe `as { emoji: string }` assertion)
    const bodyParsed = reactionBodySchema.safeParse(request.body)
    if (!bodyParsed.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')
    const emoji = bodyParsed.data.emoji

    const msg = await db.query.directMessages.findFirst({
      where: and(eq(directMessages.id, messageId), isNull(directMessages.deletedAt)),
      columns: { id: true, senderId: true, recipientId: true }
    })
    if (!msg) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    // Verify user is part of the conversation
    if (msg.senderId !== user.id && msg.recipientId !== user.id) {
      return sendError(reply, 403, 'FORBIDDEN', 'Not part of this conversation')
    }

    try {
      // Upsert: unique constraint is on (messageId, userId) only — see migration 0003.
      // Do NOT add emoji to the conflict target or the upsert will break.
      const reactionId = ulid()
      await db.insert(directMessageReactions)
        .values({ id: reactionId, messageId, userId: user.id, emoji })
        .onConflictDoUpdate({
          target: [directMessageReactions.messageId, directMessageReactions.userId],
          set: { emoji, id: reactionId }
        })

      // Use name from server state (populated on socket connect) — no extra DB lookup
      const userName = serverState.userNames.get(user.id) ?? 'Unknown'
      const reaction = { id: reactionId, messageId, userId: user.id, emoji, user: { name: userName } }

      // Notify both parties
      emitToUser(user.id, 'dm:message:reaction', { adminId, messageId, type: 'add', reaction })
      if (adminId !== user.id) {
        emitToUser(adminId, 'dm:message:reaction', { adminId: user.id, messageId, type: 'add', reaction })
      }

      return sendOk(reply, { success: true, reaction })
    } catch (err) {
      logger.error({ userId: user.id, error: err }, 'Add DM reaction failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to add reaction')
    }
  })

  fastify.delete('/dm/:adminId/:messageId/reaction/:emoji', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return


    const { adminId, messageId, emoji } = request.params as { adminId: string; messageId: string; emoji: string }

    if (!isValidId(adminId) || !isValidId(messageId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid IDs')
    if (!emoji) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    // Safe-decode then NFC-normalise to match the stored value
    let decodedEmoji: string
    try {
      decodedEmoji = decodeURIComponent(emoji).normalize('NFC')
    } catch {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')
    }
    if (!emojiRegex.test(decodedEmoji)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    const result = await db.delete(directMessageReactions).where(
      and(
        eq(directMessageReactions.messageId, messageId),
        eq(directMessageReactions.userId, user.id),
        eq(directMessageReactions.emoji, decodedEmoji)
      )
    )

    if (result.rowsAffected && result.rowsAffected > 0) {
      const reaction = { messageId, userId: user.id, emoji: decodedEmoji }
      // Notify both parties
      emitToUser(user.id, 'dm:message:reaction', { adminId, messageId, type: 'remove', reaction })
      if (adminId !== user.id) {
        emitToUser(adminId, 'dm:message:reaction', { adminId: user.id, messageId, type: 'remove', reaction })
      }
    }

    return sendOk(reply, { success: true })
  })
}
