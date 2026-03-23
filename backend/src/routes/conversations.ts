import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { and, desc, eq, isNull, lt, sql, ne } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { conversations, messages, media, auditLogs, messageReactions, users, registrationReports, announcements } from '../db/schema.js'
import { requireApprovedUser, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { canAccessConversation, canDeleteMessage, canUploadMedia, isAdmin } from '../lib/permissions.js'
import { getConfig } from '../lib/config.js'
import { emitToUser, emitToAdmins, getOnlineSuperAdminIds } from '../socket/index.js'
import { cancelEmailNotification, queueEmailNotification } from '../services/emailQueue.js'
import { sendEmail } from '../services/email.js'
import { createRateLimiters } from '../middleware/rateLimit.js'
import { setConversationOwner, serverState, getUserFromCache } from '../state.js'
import { sanitizeText, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'

const textMessageSchema = z.object({
  type: z.literal('TEXT'),
  content: z.string().min(1).max(100000),
  replyToId: z.string().min(1).max(26).optional(),
  announcementId: z.string().min(1).max(26).optional(),
})

const mediaMessageSchema = z.object({
  type: z.enum(['IMAGE', 'DOCUMENT']),
  mediaId: z.string().min(1),
  content: z.string().max(100000).optional(),
  replyToId: z.string().min(1).max(26).optional(),
  announcementId: z.string().min(1).max(26).optional(),
})

const messageSchema = z.discriminatedUnion('type', [
  textMessageSchema,
  mediaMessageSchema
])

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.string().optional()
})

/** Error interface for database constraint errors */
interface DbError {
  code?: string
  message?: string
}

/** Checks if error is a database constraint error */
function isDbConstraintError(error: unknown): boolean {
  const err = error as DbError
  return (
    err?.code === 'SQLITE_CONSTRAINT' ||
    (err as any)?.cause?.code === 'SQLITE_CONSTRAINT' ||
    (err?.message?.includes('UNIQUE constraint') ?? false) ||
    (err?.message?.includes('SQLITE_CONSTRAINT') ?? false)
  )
}

export async function conversationRoutes(fastify: FastifyInstance) {
  logger.info('>>> CONVERSATION ROUTES REGISTERED <<<')
  const rateLimiters = createRateLimiters()

  fastify.get('/', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const userIsAdmin = isAdmin(user)
    const includeArchived = (request.query as { archived?: string }).archived === 'true'

    if (userIsAdmin) {
      const adminQuery = paginationSchema.safeParse(request.query)
      const limit = adminQuery.success ? adminQuery.data.limit : 50
      const before = adminQuery.success ? adminQuery.data.before : undefined

      // Build WHERE clauses as raw sql literals using the alias 'c' so they work
      // correctly inside the raw sql`` template below. Drizzle ORM expressions
      // (eq/isNull/lt) generate fully-qualified "table"."column" names which
      // conflict with the alias and silently return no rows in libSQL.
      const whereParts: ReturnType<typeof sql>[] = []

      // Regular ADMINs only see conversations assigned to them
      if (user.role === 'ADMIN') {
        whereParts.push(sql`c.assigned_admin_id = ${user.id}`)
      }
      // Filter by archive status
      if (!includeArchived) {
        whereParts.push(sql`c.archived_at IS NULL`)
      }
      whereParts.push(sql`c.deleted_at IS NULL`)

      // Pagination cursor encodes all sort keys of the last row on the previous page.
      // Format: JSON { tier:0|1, waitingSince:ms|null, lastMessageAt:ms|null, id:string }
      // tier=0 = waiting rows (waiting_since IS NOT NULL AND archived_at IS NULL)
      // tier=1 = normal rows
      // This prevents duplicate waiting rows reappearing on Load More.
      if (before) {
        try {
          const cur = JSON.parse(before) as { tier: number; waitingSince: number | null; lastMessageAt: number | null; id: string }
          if (cur.tier === 0 && cur.waitingSince != null) {
            // Paginating within the waiting tier.
            // Keep only waiting rows that sort strictly after the cursor.
            const wsSeconds = Math.floor(cur.waitingSince / 1000)
            whereParts.push(sql`c.waiting_since IS NOT NULL`)
            whereParts.push(sql`c.archived_at IS NULL`)
            whereParts.push(sql`(c.waiting_since > ${wsSeconds} OR (c.waiting_since = ${wsSeconds} AND c.id > ${cur.id}))`)
          } else {
            // Paginating within the normal tier — all waiting rows already delivered.
            whereParts.push(sql`(c.waiting_since IS NULL OR c.archived_at IS NOT NULL)`)
            if (cur.lastMessageAt != null) {
              whereParts.push(sql`c.last_message_at < ${cur.lastMessageAt}`)
            }
          }
        } catch {
          // Legacy plain-integer cursor — keep backward compat.
          const beforeMs = parseInt(before, 10)
          if (!isNaN(beforeMs) && beforeMs > 0) {
            whereParts.push(sql`c.last_message_at < ${beforeMs}`)
          }
        }
      }

      const whereClause = whereParts.length > 0
        ? sql`WHERE ${sql.join(whereParts, sql` AND `)}`
        : sql``

      const rows = await db.all(sql`
        SELECT
          c.id, c.user_id, c.assigned_admin_id, c.created_at, c.last_message_at,
          c.unread_count, c.admin_unread_count, c.archived_at, c.archived_by, c.updated_at, c.subsidiary_id, c.registration_report_id, c.waiting_since, c.last_admin_reply_at,
          json_object('id', u.id, 'name', u.name, 'email', u.email, 'status', u.status) as user,
          CASE WHEN a.id IS NOT NULL THEN json_object('id', a.id, 'name', a.name, 'role', a.role) ELSE NULL END as assigned_admin,
          CASE WHEN rr.id IS NOT NULL THEN json_object('id', rr.id, 'subject', rr.subject, 'description', rr.description, 'status', rr.status, 'created_at', rr.created_at) ELSE NULL END as registration_report,
          json_object('id', m.id, 'type', CASE WHEN m.deleted_at IS NOT NULL THEN 'DELETED' ELSE m.type END, 'content', CASE WHEN m.deleted_at IS NOT NULL THEN NULL ELSE m.content END, 'sender_id', m.sender_id, 'created_at', m.created_at, 'deleted_at', m.deleted_at) as last_message
        FROM conversations c
        INNER JOIN users u ON u.id = c.user_id
        LEFT JOIN users a ON a.id = c.assigned_admin_id
        LEFT JOIN registration_reports rr ON rr.id = c.registration_report_id
        LEFT JOIN messages m ON m.id = (
          SELECT id FROM messages
          WHERE conversation_id = c.id AND deleted_at IS NULL
          ORDER BY created_at DESC LIMIT 1
        )
        ${whereClause}
        ORDER BY CASE WHEN c.waiting_since IS NOT NULL AND c.archived_at IS NULL THEN 0 ELSE 1 END ASC, c.waiting_since ASC NULLS LAST, c.last_message_at DESC NULLS LAST
        LIMIT ${limit + 1}
      `)

  const hasMore = rows.length > limit
  const conversationsToReturn = hasMore ? rows.slice(0, -1) : rows

  const result = conversationsToReturn.map((row: any) => ({
    id: row.id,
    userId: row.user_id,
    user: row.user ? JSON.parse(row.user) : null,
    assignedAdminId: row.assigned_admin_id,
    assignedAdmin: row.assigned_admin ? JSON.parse(row.assigned_admin) : null,
    subsidiaryId: row.subsidiary_id,
    registrationReportId: row.registration_report_id,
    registrationReport: row.registration_report ? JSON.parse(row.registration_report) : null,
    unreadCount: row.unread_count,
    adminUnreadCount: row.admin_unread_count,
    lastMessageAt: row.last_message_at,
    createdAt: row.created_at,
    archivedAt: row.archived_at ?? null,
    archivedBy: row.archived_by ?? null,
    waitingSince: row.waiting_since ? row.waiting_since * 1000 : null,
    lastAdminReplyAt: row.last_admin_reply_at ? row.last_admin_reply_at * 1000 : null,
    lastMessage: row.last_message && row.last_message !== 'null' ? JSON.parse(row.last_message) : null
  }))

  // Build composite cursor from the last row's sort keys so Load More never duplicates
  // waiting-tier rows. tier=0 = waiting; tier=1 = normal.
  let nextCursor: string | null = null
  if (hasMore && result.length > 0) {
    const last = result[result.length - 1]!
    const tier = (last.waitingSince != null && last.archivedAt == null) ? 0 : 1
    nextCursor = JSON.stringify({
      tier,
      waitingSince: last.waitingSince ?? null,
      lastMessageAt: last.lastMessageAt ?? null,
      id: last.id,
    })
  }

  return sendOk(reply, { conversations: result, hasMore, nextCursor })
    } else {
      const conversation = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, user.id),
          isNull(conversations.deletedAt)
        ),
        columns: { 
          id: true, 
          userId: true, 
          assignedAdminId: true, 
          subsidiaryId: true, 
          unreadCount: true, 
          lastMessageAt: true, 
          createdAt: true,
          archivedAt: true,
          archivedBy: true,
          waitingSince: true,
          lastAdminReplyAt: true,
        },
        with: {
          assignedAdmin: { columns: { id: true, name: true, role: true } },
          messages: {
            where: isNull(messages.deletedAt),
            orderBy: [desc(messages.createdAt)],
            limit: 1,
            columns: { id: true, type: true, content: true, senderId: true, createdAt: true }
          }
        }
      })

      if (!conversation) {
        return sendOk(reply, { conversation: null })
      }

      return sendOk(reply, {
        conversation: {
          id: conversation.id,
          userId: conversation.userId,
          assignedAdminId: conversation.assignedAdminId,
          assignedAdmin: conversation.assignedAdmin ?? null,
          subsidiaryId: conversation.subsidiaryId,
          unreadCount: conversation.unreadCount,
          lastMessageAt: conversation.lastMessageAt,
          createdAt: conversation.createdAt,
          archivedAt: conversation.archivedAt ?? null,
          archivedBy: conversation.archivedBy ?? null,
          waitingSince: conversation.waitingSince ? conversation.waitingSince.getTime() : null,
          lastAdminReplyAt: conversation.lastAdminReplyAt ? conversation.lastAdminReplyAt.getTime() : null,
          lastMessage: conversation.messages[0] || null
        }
      })
    }
  })

  fastify.get('/:id', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return
    if (!isAdmin(user)) return sendError(reply, 403, 'FORBIDDEN', 'Admins only')

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid conversation ID')

    const conv = await db.query.conversations.findFirst({
      where: eq(conversations.id, id),
      with: {
        user: { columns: { id: true, name: true, email: true, status: true } },
        assignedAdmin: { columns: { id: true, name: true, role: true } },
        messages: {
          where: isNull(messages.deletedAt),
          orderBy: [desc(messages.createdAt)],
          limit: 1,
          columns: { id: true, type: true, content: true, senderId: true, createdAt: true }
        }
      }
    })

    if (!conv) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
    if (!canAccessConversation(user, conv)) return sendError(reply, 403, 'FORBIDDEN', 'Access denied')

    return sendOk(reply, {
      conversation: {
        id: conv.id,
        userId: conv.userId,
        user: conv.user,
        assignedAdminId: conv.assignedAdminId,
        assignedAdmin: conv.assignedAdmin ?? null,
        subsidiaryId: conv.subsidiaryId,
        unreadCount: conv.unreadCount,
        adminUnreadCount: conv.adminUnreadCount,
        lastMessageAt: conv.lastMessageAt,
        createdAt: conv.createdAt,
        lastMessage: conv.messages[0] || null
      }
    })
  })

  fastify.post('/', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    if (isAdmin(user)) {
      return sendError(reply, 400, 'BAD_REQUEST', 'Admins do not have their own conversations')
    }

    const body = z.object({ subsidiaryId: z.string().nullable().optional() }).safeParse(request.body ?? {})

    const existing = await db.query.conversations.findFirst({
      where: eq(conversations.userId, user.id),
      columns: { id: true, subsidiaryId: true, assignedAdminId: true }
    })

    // Update subsidiaryId if it changed
    if (existing) {
      if (body.success && body.data.subsidiaryId !== undefined && existing.subsidiaryId !== body.data.subsidiaryId) {
        await db.update(conversations)
          .set({ subsidiaryId: body.data.subsidiaryId })
          .where(eq(conversations.id, existing.id))

        // Smart re-assignment in background — non-blocking so user gets instant response
        import('../lib/assignmentEngine.js')
          .then(({ reassignForSubsidiary }) =>
            reassignForSubsidiary(
              existing.id,
              body.data.subsidiaryId ?? null,
              existing.assignedAdminId,
              user.id,           // user.id IS the conversation owner — no second DB read needed
            )
          )
          .catch((err) => logger.warn({ err, conversationId: existing.id }, 'Subsidiary reassignment failed — non-fatal'))

        return sendOk(reply, { conversation: { ...existing, subsidiaryId: body.data.subsidiaryId } })
      }
      return sendOk(reply, { conversation: existing })
    }

    const id = ulid()
    const now = new Date()

    try {
      await db.insert(conversations).values({
        id,
        userId: user.id,
        subsidiaryId: body.success ? body.data.subsidiaryId : undefined,
        createdAt: now,
        unreadCount: 0
      })
      setConversationOwner(id, user.id)
    } catch (error) {
      if (isDbConstraintError(error)) {
        const existingConv = await db.query.conversations.findFirst({
          where: eq(conversations.userId, user.id),
          columns: { id: true }
        })
        if (existingConv) {
          return sendOk(reply, { conversation: existingConv })
        }
      }
      logger.error({ userId: user.id, error }, 'Conversation creation failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to create conversation')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, id)
    })

    return reply.code(201).send({ success: true, conversation })
  })

fastify.post('/for-user', { preHandler: requireApprovedUser }, async (request, reply) => {
  const user = requireUser(request, reply)
  if (!user) return
  if (!isAdmin(user)) return sendError(reply, 403, 'FORBIDDEN', 'Admins only')

  const body = z.object({
    userId: z.string().min(1).max(26),
    subsidiaryId: z.string().optional(),
    reportId: z.string().min(1).max(26).optional(),
  }).safeParse(request.body)
  if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input')

  const { userId, reportId } = body.data
  if (!isValidId(userId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
  if (reportId && !isValidId(reportId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid report ID')

  const targetUser = await db.query.users.findFirst({
    where: eq(users.id, userId),
    columns: { id: true, role: true, status: true }
  })
  if (!targetUser || targetUser.role !== 'USER') return sendError(reply, 404, 'NOT_FOUND', 'User not found')

  // Validate report exists and belongs to the user if provided
  if (reportId) {
    const report = await db.query.registrationReports.findFirst({
      where: eq(registrationReports.id, reportId),
      columns: { userId: true, status: true }
    })
    if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')
    if (report.userId !== userId) return sendError(reply, 400, 'VALIDATION_ERROR', 'Report does not belong to user')

    // Ensure this report is not already linked to a different conversation
    const reportLinkedConv = await db.query.conversations.findFirst({
      where: eq(conversations.registrationReportId, reportId),
      columns: { id: true, userId: true }
    })
    if (reportLinkedConv && reportLinkedConv.userId !== userId) {
      return sendError(reply, 409, 'CONFLICT', 'Report is already linked to another conversation')
    }
  }

  const existing = await db.query.conversations.findFirst({
    where: eq(conversations.userId, userId),
    columns: { id: true, registrationReportId: true }
  })
  if (existing) {
    // If a reportId is provided and the conversation doesn't have one yet, link it now
    if (reportId && !existing.registrationReportId) {
      await db.update(conversations)
        .set({ registrationReportId: reportId })
        .where(eq(conversations.id, existing.id))
      return sendOk(reply, { conversation: { ...existing, registrationReportId: reportId } })
    }
    return sendOk(reply, { conversation: existing })
  }

  const id = ulid()
  const now = new Date()
  try {
    await db.insert(conversations).values({
      id,
      userId,
      subsidiaryId: body.data.subsidiaryId,
      registrationReportId: reportId || null,
      assignedAdminId: user.role === 'ADMIN' ? user.id : null,
      createdAt: now,
      unreadCount: 0
    })
    setConversationOwner(id, userId)
  } catch (error) {
    if (isDbConstraintError(error)) {
      const conv = await db.query.conversations.findFirst({ where: eq(conversations.userId, userId), columns: { id: true } })
      if (conv) return sendOk(reply, { conversation: conv })
    }
    logger.error({ userId: user.id, error }, 'Conversation initiation failed')
    return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to initiate conversation')
  }
  // Emit conversation:new so all admins see it in their sidebar immediately
  try {
    const targetUserInfo = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: { id: true, name: true, email: true, status: true }
    })
    // When a regular ADMIN creates the conversation they are auto-assigned.
    // Build the assignedAdmin shape from cache so the sidebar card shows the
    // correct admin name immediately without a refresh.
    const selfAssigned = user.role === 'ADMIN'
    const cachedCreator = selfAssigned ? getUserFromCache(user.id) : null
    emitToAdmins('conversation:new', {
      conversation: {
        id,
        userId,
        assignedAdminId: selfAssigned ? user.id : null,
        registrationReportId: reportId || null,
        subsidiaryId: body.data.subsidiaryId || null,
        createdAt: now.getTime(),
        lastMessageAt: null,
        unreadCount: 0,
        adminUnreadCount: 0,
        archivedAt: null,
        archivedBy: null,
        updatedAt: now.getTime(),
        user: targetUserInfo ?? { id: userId, name: 'Unknown', email: '', status: 'APPROVED' },
        assignedAdmin: selfAssigned
          ? { id: user.id, name: cachedCreator?.name ?? 'Admin', role: user.role }
          : null,
        lastMessage: null,
      }
    })
  } catch (emitErr) {
    logger.warn({ emitErr }, 'Failed to emit conversation:new — non-fatal')
  }

  reply.code(201)
  return sendOk(reply, { conversation: { id } })
})

  fastify.get('/:conversationId/messages', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { conversationId } = request.params as { conversationId: string }

    if (!isValidId(conversationId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid conversation ID')
    }

    const query = paginationSchema.safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      columns: { id: true, userId: true, assignedAdminId: true }
    })

    if (!conversation) {
      return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
    }

    if (!canAccessConversation(user, conversation)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    const conditions = [
      eq(messages.conversationId, conversationId),
      isNull(messages.deletedAt),
      // SECURE: Drizzle sql template properly parameterizes ${user.id}
      // ${messages.hiddenFor} is a column reference, not user input
      sql`NOT EXISTS (SELECT 1 FROM json_each(${messages.hiddenFor}) WHERE value = ${user.id})`
    ]

    if (query.data.before && isValidId(query.data.before)) {
      // Decode timestamp from ULID — no extra DB round-trip needed
      const beforeMs = decodeTime(query.data.before)
      conditions.push(lt(messages.createdAt, new Date(beforeMs)))
    }

    const messageList = await db.query.messages.findMany({
      where: and(...conditions),
      orderBy: [desc(messages.createdAt)],
      limit: query.data.limit + 1,
      with: {
        sender: {
          columns: { id: true, name: true, role: true }
        },
        media: {
          columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true, metadata: true }
        },
        reactions: {
          with: {
            user: { columns: { id: true, name: true } }
          }
        },
        replyTo: {
          columns: { id: true, type: true, content: true, deletedAt: true },
          with: { sender: { columns: { name: true } } },
        },
        linkedAnnouncement: { columns: { id: true, title: true, type: true, template: true } },
      }
    })

    const hasMore = messageList.length > query.data.limit
    const messagesToReturn = hasMore ? messageList.slice(0, -1) : messageList

    const validatedMessages = messagesToReturn.map(msg => ({
      id: msg.id,
      conversationId: msg.conversationId,
      senderId: msg.senderId,
      sender: msg.sender,
      type: msg.type,
      content: msg.content,
      status: msg.status,
      readAt: msg.readAt,
      createdAt: msg.createdAt,
      media: msg.media,
      reactions: msg.reactions?.map(r => ({
        id: r.id,
        emoji: r.emoji,
        userId: r.userId,
        user: r.user
      })) || [],
      replyToId: msg.replyToId,
      replyTo: msg.replyTo ?? null,
      announcementId: msg.announcementId,
      linkedAnnouncement: msg.linkedAnnouncement ?? null,
    }))

    return sendOk(reply, {
      messages: validatedMessages,
      hasMore
    })
  })

  // GET a single message by ID — used for notification deep-links and reply navigation (#12)
  fastify.get('/:conversationId/messages/:messageId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { conversationId, messageId } = request.params as { conversationId: string; messageId: string }
    if (!isValidId(conversationId) || !isValidId(messageId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      columns: { id: true, userId: true, assignedAdminId: true }
    })
    if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
    if (!canAccessConversation(user, conversation)) return sendError(reply, 403, 'FORBIDDEN', 'Access denied')

    const msg = await db.query.messages.findFirst({
      where: and(
        eq(messages.id, messageId),
        eq(messages.conversationId, conversationId),
        isNull(messages.deletedAt),
        sql`NOT EXISTS (SELECT 1 FROM json_each(${messages.hiddenFor}) WHERE value = ${user.id})`
      ),
      with: {
        sender: { columns: { id: true, name: true, role: true } },
        media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true, metadata: true } },
        reactions: { with: { user: { columns: { id: true, name: true } } } },
        replyTo: {
          columns: { id: true, type: true, content: true, deletedAt: true },
          with: { sender: { columns: { name: true } } }
        },
        linkedAnnouncement: { columns: { id: true, title: true, type: true, template: true } }
      }
    })

    if (!msg) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    return sendOk(reply, {
      message: {
        id: msg.id,
        conversationId: msg.conversationId,
        senderId: msg.senderId,
        sender: msg.sender,
        type: msg.type,
        content: msg.content,
        status: msg.status,
        readAt: msg.readAt,
        createdAt: msg.createdAt,
        media: msg.media,
        reactions: msg.reactions?.map(r => ({
          id: r.id,
          emoji: r.emoji,
          userId: r.userId,
          user: r.user
        })) ?? [],
        replyToId: msg.replyToId,
        replyTo: msg.replyTo
          ? { ...msg.replyTo, content: msg.replyTo.deletedAt ? null : msg.replyTo.content }
          : null,
        announcementId: msg.announcementId,
        linkedAnnouncement: msg.linkedAnnouncement ?? null
      }
    })
  })

  fastify.post('/:conversationId/messages', {
    preHandler: [requireApprovedUser, rateLimiters.message]
  }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { conversationId } = request.params as { conversationId: string }

    if (!isValidId(conversationId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid conversation ID')
    }

    const body = messageSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const config = getConfig()

    if (body.data.type === 'TEXT' && body.data.content) {
      // Enforce per-role limits — USER uses textMaxLength, admins use teamTextMaxLength.
      // Both are enforced server-side so the config can't be bypassed via the API.
      const maxLen = user.role === 'USER'
        ? config.limits.message.textMaxLength
        : config.limits.message.teamTextMaxLength
      if (body.data.content.length > maxLen) {
        return sendError(reply, 400, 'VALIDATION_ERROR', `Message too long (max ${maxLen} characters)`)
      }
    }

    if (body.data.type !== 'TEXT' && !config.features.mediaUpload) {
      return sendError(reply, 403, 'FORBIDDEN', 'Media uploads are disabled')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      columns: { id: true, userId: true, assignedAdminId: true, unreadCount: true, adminUnreadCount: true, lastMessageAt: true, createdAt: true, subsidiaryId: true }
    })

    if (!conversation) {
      return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
    }

    if (!canAccessConversation(user, conversation)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    // Fetch media once — reuse for both validation and payload (avoids double DB round-trip)
    let mediaForPayload: { id: string; type: string; cdnUrl: string | null; filename: string; size: number; mimeType: string; metadata: string | null } | null = null

    if (body.data.type !== 'TEXT') {
      if (!canUploadMedia(user)) {
        return sendError(reply, 403, 'FORBIDDEN', 'Media uploads not permitted')
      }

      const mediaRecord = await db.query.media.findFirst({
        where: eq(media.id, body.data.mediaId),
        columns: { id: true, status: true, type: true, uploadedBy: true, cdnUrl: true, filename: true, size: true, mimeType: true, metadata: true }
      })

      if (!mediaRecord || mediaRecord.status !== 'CONFIRMED') {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid or unconfirmed media')
      }

      if (mediaRecord.type !== body.data.type) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Media type does not match message type')
      }

      if (mediaRecord.uploadedBy !== user.id && !isAdmin(user)) {
        return sendError(reply, 403, 'FORBIDDEN', 'Media does not belong to you')
      }

      // Reuse validated record for payload — no second SELECT needed
      mediaForPayload = { id: mediaRecord.id, type: mediaRecord.type, cdnUrl: mediaRecord.cdnUrl, filename: mediaRecord.filename, size: mediaRecord.size, mimeType: mediaRecord.mimeType, metadata: mediaRecord.metadata }
    }

    const messageId = ulid()
    const now = new Date()
    const userIsAdmin = isAdmin(user)
    const isAdminSending = userIsAdmin && conversation.userId !== user.id
    // Sanitize once here — reuse in the INSERT and in messagePayload below
    const sanitizedContent = body.data.type === 'TEXT'
      ? sanitizeText(body.data.content)
      : (body.data.content ? sanitizeText(body.data.content) : null)

    try {
      await db.transaction(async (tx) => {
        await tx.insert(messages).values({
          id: messageId,
          conversationId,
          senderId: user.id,
          type: body.data.type,
          content: sanitizedContent,
          mediaId: body.data.type !== 'TEXT' ? (body.data.mediaId ?? null) : null,
          replyToId: body.data.replyToId || null,
          announcementId: body.data.announcementId || null,
        })

        // Smart workload-based auto-assign
        if (!userIsAdmin) {
          const { pickBestAdmin } = await import('../lib/assignmentEngine.js')
          const pick = await pickBestAdmin(conversation.subsidiaryId)
          if (pick) {
            const updateResult = await tx.update(conversations)
              .set({ assignedAdminId: pick })
              .where(and(
                eq(conversations.id, conversationId),
                isNull(conversations.assignedAdminId)
              ))
            if (updateResult.rowsAffected === 0) {
              logger.debug({ conversationId, userId: user.id }, 'Conversation already assigned by another request')
            }
          }
        }

        // Track waiting state: user sent → set waitingSince; admin replied → clear it
        if (!userIsAdmin) {
          await tx.update(conversations)
            .set({ waitingSince: now })
            .where(and(eq(conversations.id, conversationId), isNull(conversations.waitingSince)))
        } else {
          await tx.update(conversations)
            .set({ waitingSince: null, lastAdminReplyAt: now })
            .where(eq(conversations.id, conversationId))
        }

        await tx.update(conversations)
          .set({
            lastMessageAt: now,
            ...(isAdminSending ? { unreadCount: sql`unread_count + 1` } : { adminUnreadCount: sql`admin_unread_count + 1` })
          })
          .where(eq(conversations.id, conversationId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'message.send',
          entityType: 'message',
          entityId: messageId,
          details: JSON.stringify({ conversationId, type: body.data.type })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, conversationId, error }, 'Message send failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to send message')
    }

    // Re-read conversation for fresh unread counts after the transaction (#4 #42)
    const updatedConversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      columns: { unreadCount: true, adminUnreadCount: true, assignedAdminId: true }
    })
    const freshUnreadCount = updatedConversation?.unreadCount ?? 0
    const freshAdminUnreadCount = updatedConversation?.adminUnreadCount ?? 0

    // Fetch replyTo snippet only if present (1 small query vs 4-JOIN full SELECT) (#32)
    let replyToSnippet: { id: string; type: string; content: string | null; deletedAt: Date | null; sender: { name: string } | null } | null = null
    if (body.data.replyToId && isValidId(body.data.replyToId)) {
      const rt = await db.query.messages.findFirst({
        where: eq(messages.id, body.data.replyToId),
        columns: { id: true, type: true, content: true, deletedAt: true },
        with: { sender: { columns: { name: true } } }
      })
      if (rt) {
        replyToSnippet = { ...rt, content: rt.deletedAt ? null : rt.content, sender: rt.sender ?? null }
      }
    }

    // Fetch linkedAnnouncement snippet only if present (#32)
    let linkedAnnouncement: { id: string; title: string; type: string; template: string | null } | null = null
    if (body.data.announcementId && isValidId(body.data.announcementId)) {
      linkedAnnouncement = await db.query.announcements.findFirst({
        where: eq(announcements.id, body.data.announcementId),
        columns: { id: true, title: true, type: true, template: true }
      }) ?? null
    }

    // Build cached sender from state — avoids the JOIN entirely
    const cachedSender = getUserFromCache(user.id)
    const senderShape = { id: user.id, name: cachedSender?.name ?? 'Unknown', role: user.role }

    const messagePayload = {
      id: messageId,
      conversationId,
      senderId: user.id,
      sender: senderShape,
      type: body.data.type,
      content: sanitizedContent,
      status: 'SENT',
      createdAt: now,
      media: mediaForPayload,
      replyToId: body.data.replyToId ?? null,
      replyTo: replyToSnippet,
      announcementId: body.data.announcementId ?? null,
      linkedAnnouncement,
    }

    const convUpdatePayload = {
      conversationId,
      userId: conversation.userId,
      unreadCount: freshUnreadCount,
      adminUnreadCount: freshAdminUnreadCount,
      lastMessageAt: now.getTime(),
      lastMessage: messagePayload,
      assignedAdminId: updatedConversation?.assignedAdminId ?? conversation.assignedAdminId,
      // When admin replies, push waitingSince: null so the waiting badge clears in real-time
      // When admin replies clear the waiting badge; when user sends start the clock
      waitingSince: userIsAdmin ? null : now.getTime(),
    }

    if (userIsAdmin) {
      emitToUser(conversation.userId, 'message:new', { message: messagePayload })
      // Update the sending admin's own conversation list sidebar
      emitToUser(user.id, 'conversation:updated', convUpdatePayload)
      // Super admins get updates for oversight (unless they are the sender)
      const superAdmins = getOnlineSuperAdminIds()
      superAdmins.forEach(adminId => {
        if (adminId !== user.id) {
          emitToUser(adminId, 'message:new', { message: messagePayload })
          emitToUser(adminId, 'conversation:updated', convUpdatePayload)
        }
      })
    } else {
      // Only emit to assigned admin + SUPER_ADMINs (privacy — regular admins must not see unassigned chats)
      const assignedAdminId = updatedConversation?.assignedAdminId ?? conversation.assignedAdminId
      const wasAlreadyAssigned = !!conversation.assignedAdminId
      const superAdmins = getOnlineSuperAdminIds()
      if (assignedAdminId) {
        emitToUser(assignedAdminId, 'message:new', { message: messagePayload })
        emitToUser(assignedAdminId, 'conversation:updated', convUpdatePayload)
        // If this is a freshly auto-assigned conversation, tell the admin they were assigned
        if (!wasAlreadyAssigned) {
          const targetUserInfo = getUserFromCache(conversation.userId)
          emitToUser(assignedAdminId, 'conversation:assigned_to_you', {
            conversationId,
            userName: targetUserInfo?.name ?? 'a user',
          })
        }
      }
      superAdmins.forEach(adminId => {
        if (adminId !== assignedAdminId) {
          emitToUser(adminId, 'message:new', { message: messagePayload })
          emitToUser(adminId, 'conversation:updated', convUpdatePayload)
          // Super admins get the assignment toast for unassigned conversations
          if (!assignedAdminId && !wasAlreadyAssigned) {
            const targetUserInfo = getUserFromCache(conversation.userId)
            emitToUser(adminId, 'conversation:assigned_to_you', {
              conversationId,
              userName: targetUserInfo?.name ?? 'a user',
            })
          }
        }
      })
      // Also notify the sender's other browser tabs
      emitToUser(user.id, 'message:new', { message: messagePayload })
    }

    if (isAdminSending) {
      queueEmailNotification(conversation.userId)
    }

    return reply.code(201).send({
      success: true,
      message: messagePayload
    })
  })

  fastify.patch('/:conversationId/assign', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    // Only SUPER_ADMIN can assign conversations
    if (user.role !== 'SUPER_ADMIN') return sendError(reply, 403, 'FORBIDDEN', 'Super admin only')

    const { conversationId } = request.params as { conversationId: string }
    if (!isValidId(conversationId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid conversation ID')

    const body = z.object({
      adminId: z.string().min(1).max(26).nullable(),
    }).safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input')

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      with: { user: { columns: { id: true, name: true } } },
    })
    if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')

    const oldAdminId = conversation.assignedAdminId
    const newAdminId = body.data.adminId

    let targetAdmin: { id: string, name: string, role: string, status: string } | undefined

    // Validate the target admin exists and is an admin/super_admin
    if (newAdminId) {
      targetAdmin = await db.query.users.findFirst({
        where: eq(users.id, newAdminId),
        columns: { id: true, name: true, role: true, status: true },
      })
      if (!targetAdmin || targetAdmin.status !== 'APPROVED' || (targetAdmin.role !== 'ADMIN' && targetAdmin.role !== 'SUPER_ADMIN')) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid admin target')
      }
    }

    try {
      await db.transaction(async (tx) => {
        await tx.update(conversations)
          .set({ assignedAdminId: newAdminId })
          .where(eq(conversations.id, conversationId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'conversation.assign',
          entityType: 'conversation',
          entityId: conversationId,
          details: JSON.stringify({ oldAdminId, newAdminId })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, conversationId, error }, 'Failed to assign conversation')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to assign conversation')
    }

    const chatUserName = conversation.user?.name ?? 'a user'

    // Notify old admin they lost this conversation
    if (oldAdminId && oldAdminId !== newAdminId) {
      emitToUser(oldAdminId, 'conversation:removed', {
        conversationId,
        userName: chatUserName,
      })
    }

    // Notify new admin they have been assigned
    if (newAdminId && newAdminId !== oldAdminId) {
      emitToUser(newAdminId, 'conversation:assigned_to_you', {
        conversationId,
        userName: chatUserName,
      })
    }

    // Broadcast assignment update to all admins (for super admin overview)
    emitToAdmins('conversation:assigned', {
      conversationId,
      assignedAdminId: newAdminId,
      assignedAdminName: newAdminId ? targetAdmin?.name : undefined,
      assignedAdminRole: newAdminId ? targetAdmin?.role : undefined,
      oldAdminId,
    })

  return sendOk(reply, { success: true })
  })


  // POST /:conversationId/mark-read — HTTP fallback for when socket is unavailable.
  // Mirrors the socket handler in socket/index.ts so read state is always persisted
  // even if the client is briefly offline (e.g. mobile backgrounded, hard refresh timing).
  fastify.post('/:conversationId/mark-read', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return sendError(reply, 401, 'UNAUTHORIZED', 'Unauthorized')

    const { conversationId } = request.params as { conversationId: string }
    if (!isValidId(conversationId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid conversation ID')

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, conversationId),
      columns: { id: true, userId: true, assignedAdminId: true },
    })
    if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
    if (!canAccessConversation(user, conversation)) return sendError(reply, 403, 'FORBIDDEN', 'Access denied')

    const now = new Date()

    if (isAdmin(user)) {
      // Admin marks user messages as read
      await db.transaction(async (tx) => {
        const result = await tx.update(messages)
          .set({ status: 'READ', readAt: now, updatedAt: now })
          .where(and(
            eq(messages.conversationId, conversationId),
            eq(messages.senderId, conversation.userId),
            eq(messages.status, 'SENT'),
            isNull(messages.deletedAt)
          ))
        if ((result.rowsAffected ?? 0) > 0) {
          await tx.update(conversations)
            .set({ adminUnreadCount: 0 })
            .where(eq(conversations.id, conversationId))
          emitToAdmins('conversation:updated', { conversationId, adminUnreadCount: 0 })
          emitToUser(conversation.userId, 'messages:read', {
            conversationId,
            readBy: user.id,
            readAt: now.getTime(),
          })
        }
      })
    } else {
      // User marks admin messages as read
      await db.transaction(async (tx) => {
        const result = await tx.update(messages)
          .set({ status: 'READ', readAt: now, updatedAt: now })
          .where(and(
            eq(messages.conversationId, conversationId),
            ne(messages.senderId, user.id),
            eq(messages.status, 'SENT'),
            isNull(messages.deletedAt)
          ))
        if ((result.rowsAffected ?? 0) > 0) {
          await tx.update(conversations)
            .set({ unreadCount: 0 })
            .where(eq(conversations.id, conversationId))
          if (conversation.assignedAdminId) {
            emitToUser(conversation.assignedAdminId, 'messages:read', {
              conversationId,
              readBy: user.id,
              readAt: now.getTime(),
            })
            emitToUser(conversation.assignedAdminId, 'conversation:updated', {
              conversationId,
              unreadCount: 0,
            })
          }
          emitToUser(user.id, 'messages:read', {
            conversationId,
            readBy: user.id,
            readAt: now.getTime(),
          })
        }
      })
    }

    return sendOk(reply, { success: true })
  })

  // Archive conversation
  fastify.patch('/:id/archive', { preHandler: requireApprovedUser }, async (request, reply) => {
    try {
      const user = requireUser(request, reply)
      if (!user) return sendError(reply, 401, 'UNAUTHORIZED', 'Unauthorized')

      const { id } = request.params as { id: string }
      if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

      const conversation = await db.query.conversations.findFirst({
        where: and(eq(conversations.id, id), isNull(conversations.deletedAt)),
        columns: { id: true, userId: true, assignedAdminId: true, archivedAt: true }
      })

      if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
      if (conversation.archivedAt) return sendError(reply, 400, 'VALIDATION_ERROR', 'Conversation already archived')

      const isAssignedAdmin = conversation.assignedAdminId === user.id
      const isSuperAdmin = user.role === 'SUPER_ADMIN'

      if (!isAssignedAdmin && !isSuperAdmin) {
        return sendError(reply, 403, 'FORBIDDEN', 'Access denied. Only admins can archive conversations.')
      }

      const body = z.object({
        closingNote: z.string().max(1000).trim().optional()
      }).safeParse(request.body ?? {})

      const closingNote = body.success ? body.data.closingNote : undefined

      const now = new Date()

      // Send closing note as a final message before archiving
      if (closingNote) {
        const msgId = ulid()
        await db.insert(messages).values({
          id: msgId,
          conversationId: id,
          senderId: user.id,
          type: 'TEXT',
          content: closingNote,
          status: 'SENT',
          createdAt: now,
          updatedAt: now,
        })
        await db.update(conversations)
          .set({ lastMessageAt: now, adminUnreadCount: 0 })
          .where(eq(conversations.id, id))

        emitToUser(conversation.userId, 'message:new', {
          id: msgId,
          conversationId: id,
          senderId: user.id,
          type: 'TEXT',
          content: closingNote,
          status: 'SENT',
          createdAt: now.getTime(),
        })
      }

      await db.update(conversations)
        .set({ archivedAt: now, archivedBy: user.id, waitingSince: null })
        .where(eq(conversations.id, id))

      emitToAdmins('conversation:archived', { conversationId: id, archivedBy: user.id })
      emitToUser(conversation.userId, 'conversation:archived', { conversationId: id, archivedBy: user.id, closingNote: closingNote ?? null })

      // Email the user
      try {
        await sendEmail({ type: 'conversationClosed', userId: conversation.userId, ...(closingNote ? { closingNote } : {}) })
      } catch (emailErr) {
        logger.warn({ userId: conversation.userId, emailErr }, 'Failed to send conversation closed email')
      }

      return sendOk(reply, { archived: true })
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      logger.error({ error: errorMessage }, 'Failed to archive conversation')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to archive conversation')
    }
  })

  // Unarchive conversation (admin only)
  fastify.patch('/:id/unarchive', { preHandler: requireApprovedUser }, async (request, reply) => {
    try {
      const user = requireUser(request, reply)
      if (!user) return

      const { id } = request.params as { id: string }
      if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

      const conversation = await db.query.conversations.findFirst({
        where: and(eq(conversations.id, id), isNull(conversations.deletedAt)),
        columns: { id: true, userId: true, assignedAdminId: true, archivedAt: true }
      })

      if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
      if (!conversation.archivedAt) return sendError(reply, 400, 'VALIDATION_ERROR', 'Conversation not archived')

      const isAssignedAdmin = conversation.assignedAdminId === user.id
      const isSuperAdmin = user.role === 'SUPER_ADMIN'

      if (!isAssignedAdmin && !isSuperAdmin) {
        return sendError(reply, 403, 'FORBIDDEN', 'Access denied. Only admins can unarchive conversations.')
      }

      await db.update(conversations)
        .set({ archivedAt: null, archivedBy: null, waitingSince: null })
        .where(eq(conversations.id, id))

      emitToAdmins('conversation:unarchived', { conversationId: id, unarchivedBy: user.id })
      emitToUser(conversation.userId, 'conversation:unarchived', { conversationId: id, unarchivedBy: user.id })

      return sendOk(reply, { unarchived: true })
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      logger.error({ error: errorMessage }, 'Failed to unarchive conversation')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to unarchive conversation')
    }
  })

  // Reopen conversation (user only — lets the user self-serve unarchive their own conversation)
  fastify.post('/:id/reopen', { preHandler: requireApprovedUser }, async (request, reply) => {
    try {
      const user = requireUser(request, reply)
      if (!user) return

      if (isAdmin(user)) {
        return sendError(reply, 403, 'FORBIDDEN', 'Admins should use unarchive instead')
      }

      const { id } = request.params as { id: string }
      if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

      const conversation = await db.query.conversations.findFirst({
        where: and(eq(conversations.id, id), isNull(conversations.deletedAt)),
        columns: { id: true, userId: true, assignedAdminId: true, archivedAt: true }
      })

      if (!conversation) return sendError(reply, 404, 'NOT_FOUND', 'Conversation not found')
      if (conversation.userId !== user.id) return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
      if (!conversation.archivedAt) return sendError(reply, 400, 'VALIDATION_ERROR', 'Conversation is not archived')

      await db.update(conversations)
        .set({ archivedAt: null, archivedBy: null, waitingSince: null })
        .where(eq(conversations.id, id))

      // Notify the assigned admin (or all admins if unassigned)
      emitToAdmins('conversation:reopened', { conversationId: id, reopenedBy: user.id })
      emitToUser(user.id, 'conversation:unarchived', { conversationId: id })

      return sendOk(reply, { reopened: true })
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      logger.error({ error: errorMessage }, 'Failed to reopen conversation')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to reopen conversation')
    }
  })
}

const reactionSchema = z.object({
  emoji: z.string().min(1).max(10).regex(/^[\p{Emoji}]+$/u, 'Must be valid emoji')
})

export async function reactionRoutes(fastify: FastifyInstance) {
  fastify.post('/:messageId/reactions', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { messageId } = request.params as { messageId: string }

    if (!isValidId(messageId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID')
    }

    const body = reactionSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji', body.error.issues)
    }

    const message = await db.query.messages.findFirst({
      where: and(eq(messages.id, messageId), isNull(messages.deletedAt)),
      columns: { id: true, conversationId: true }
    })

    if (!message) {
      return sendError(reply, 404, 'NOT_FOUND', 'Message not found')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, message.conversationId),
      columns: { id: true, userId: true, assignedAdminId: true }
    })

    if (!conversation || !canAccessConversation(user, conversation)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    const reactionId = ulid()

    try {
      // Single upsert: ON CONFLICT (messageId, userId) replaces the emoji
      await db.insert(messageReactions)
        .values({ id: reactionId, messageId, userId: user.id, emoji: body.data.emoji })
        .onConflictDoUpdate({
          target: [messageReactions.messageId, messageReactions.userId],
          set: { emoji: body.data.emoji }
        })
    } catch (error) {
      const err = error as { code?: string }
      if (err.code === 'SQLITE_CONSTRAINT') {
        return sendOk(reply, { success: true, alreadyReacted: true })
      }
      logger.error({ userId: user.id, messageId, error }, 'Reaction add failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to add reaction')
    }

    const userName = serverState.userNames.get(user.id) || 'Unknown'
    const reaction = {
      id: reactionId,
      messageId,
      userId: user.id,
      emoji: body.data.emoji,
      user: { id: user.id, name: userName }
    }

    emitToAdmins('message:reaction', { messageId, reaction, action: 'add' })
    emitToUser(conversation.userId, 'message:reaction', { messageId, reaction, action: 'add' })

    return reply.code(201).send({ success: true, reaction })
  })

  fastify.delete('/:messageId/reactions/:emoji', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { messageId, emoji } = request.params as { messageId: string; emoji: string }

    if (!isValidId(messageId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID')
    }

    const message = await db.query.messages.findFirst({
      where: and(eq(messages.id, messageId), isNull(messages.deletedAt)),
      columns: { id: true, conversationId: true }
    })

    if (!message) {
      return sendError(reply, 404, 'NOT_FOUND', 'Message not found')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, message.conversationId),
      columns: { id: true, userId: true, assignedAdminId: true }
    })

    if (!conversation || !canAccessConversation(user, conversation)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    let decodedEmoji: string
    try {
      decodedEmoji = decodeURIComponent(emoji)
    } catch {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')
    }

    if (!/[\p{Emoji}]+/u.test(decodedEmoji)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')
    }

    const reaction = await db.query.messageReactions.findFirst({
      where: and(
        eq(messageReactions.messageId, messageId),
        eq(messageReactions.userId, user.id)
      ),
      columns: { id: true }
    })

    if (!reaction) {
      return sendError(reply, 404, 'NOT_FOUND', 'Reaction not found')
    }

    await db.delete(messageReactions).where(eq(messageReactions.id, reaction.id))

    emitToAdmins('message:reaction', {
      messageId,
      reaction: { userId: user.id, emoji: decodedEmoji },
      action: 'remove'
    })
    emitToUser(conversation.userId, 'message:reaction', {
      messageId,
      reaction: { userId: user.id, emoji: decodedEmoji },
      action: 'remove'
    })

  return sendOk(reply, { success: true })
  })

}

export async function messageRoutes(fastify: FastifyInstance) {
  fastify.delete('/:messageId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { messageId } = request.params as { messageId: string }
    if (!isValidId(messageId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid message ID')

    const permanent = (request.query as { permanent?: string }).permanent === 'true'
    const scopeRaw = (request.query as { scope?: string }).scope ?? 'all'
    const scope: 'me' | 'all' = scopeRaw === 'me' ? 'me' : 'all'

    const message = await db.query.messages.findFirst({
      where: permanent
        ? eq(messages.id, messageId)
        : and(
          eq(messages.id, messageId),
          isNull(messages.deletedAt)
        ),
      columns: { id: true, senderId: true, conversationId: true, hiddenFor: true, createdAt: true, deletedAt: true }
    })

    if (!message) return sendError(reply, 404, 'NOT_FOUND', 'Message not found')

    // unified permissions check
    if (!canDeleteMessage(user, message, scope)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot delete this message or time limit exceeded')
    }

    if (permanent && user.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only super admins can permanently delete messages')
    }

    const conversation = await db.query.conversations.findFirst({
      where: eq(conversations.id, message.conversationId),
      columns: { id: true, userId: true, assignedAdminId: true }
    })

    // Verify the user has access to the conversation (critical for ADMIN scope='all')
    if (!conversation || !canAccessConversation(user, conversation)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    const now = new Date()

    try {
      await db.transaction(async (tx) => {
        if (permanent) {
          await tx.delete(messages).where(eq(messages.id, messageId))
        } else if (scope === 'me') {
          let hidden: string[] = []
          try { hidden = JSON.parse(message.hiddenFor ?? '[]') } catch { hidden = [] }
          if (!hidden.includes(user.id)) hidden.push(user.id)

          await tx.update(messages)
            .set({ hiddenFor: JSON.stringify(hidden) })
            .where(eq(messages.id, messageId))
        } else {
          // scope === 'all' (soft delete for everyone)
          await tx.update(messages)
            .set({ deletedAt: now, deletedBy: user.id })
            .where(eq(messages.id, messageId))
        }

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: permanent ? 'message.delete_permanent' : (scope === 'me' ? 'message.hide' : 'message.delete'),
          entityType: 'message',
          entityId: messageId,
          details: JSON.stringify({ conversationId: message.conversationId, permanent, scope })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, messageId, error }, 'Message delete failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to delete message')
    }

    // Only emit deletion events if we actually deleted it for everyone (soft or perm)
    if (scope === 'all' || permanent) {
      const payload = { messageId, conversationId: message.conversationId, deletedBy: user.id, deletedAt: now.getTime() }
      emitToAdmins('message:deleted', payload)
      if (conversation) emitToUser(conversation.userId, 'message:deleted', payload)
    }

  return sendOk(reply, { success: true })
  })
}