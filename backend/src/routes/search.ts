import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { or, like, eq, isNull, desc, and, inArray } from 'drizzle-orm'
import { db } from '../db/index.js'
import { users, conversations, announcements, messages, registrationReports, userReports } from '../db/schema.js'
import { requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { createRateLimiters } from '../middleware/rateLimit.js'

const searchSchema = z.object({
  q: z.string().min(1).max(100).trim(),
  type: z.enum(['all', 'users', 'conversations', 'announcements', 'messages', 'reports']).default('all'),
  limit: z.coerce.number().int().min(1).max(20).default(5),
})

export async function searchRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  fastify.get('/search', { preHandler: [requireAdmin, rateLimiters.api] }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const parsed = searchSchema.safeParse(request.query)
    if (!parsed.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query')

    const { q, type, limit } = parsed.data

    // Strip LIKE wildcard characters to prevent expensive wildcard injection attacks
    const sanitizedQuery = q.replace(/[%_]/g, '').trim()
    if (!sanitizedQuery || sanitizedQuery.length < 1) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Search query too short after sanitization')
    }
    // Full-content pattern for text/content fields; prefix pattern for indexed name/email fields
    const fullPattern = `%${sanitizedQuery}%`
    const prefixPattern = `${sanitizedQuery}%`

    // Step 1: find users matching the query (needed for both users and conversations results)
    const needUsers = type === 'all' || type === 'users' || type === 'conversations'
    const matchingUsers = needUsers
      ? await db.query.users.findMany({
        where: or(
          like(users.name, prefixPattern),
          like(users.email, prefixPattern)
        ),
        columns: { id: true, name: true, email: true, role: true, status: true, createdAt: true },
        orderBy: [desc(users.createdAt)],
        limit: limit * 2,
      })
      : []

    const matchingUserIds = matchingUsers.map((u) => u.id)

    // Step 2: parallel fetch of all result types
    const [matchConversations, matchAnnouncements, matchMessages, matchRegReports, matchUserReports] = await Promise.all([
      (type === 'all' || type === 'conversations') && matchingUserIds.length > 0
        ? db.query.conversations.findMany({
          where: and(
            inArray(conversations.userId, matchingUserIds),
            actor.role === 'ADMIN' ? eq(conversations.assignedAdminId, actor.id) : undefined
          ),
          with: { user: { columns: { id: true, name: true, email: true, status: true } } },
          columns: { id: true, lastMessageAt: true, unreadCount: true, adminUnreadCount: true, assignedAdminId: true },
          orderBy: [desc(conversations.lastMessageAt)],
          limit,
        })
        : Promise.resolve([]),

      (type === 'all' || type === 'announcements')
        ? db.query.announcements.findMany({
          where: or(
            like(announcements.title, fullPattern),
            like(announcements.content, fullPattern)
          ),
          columns: { id: true, title: true, type: true, isActive: true, createdAt: true },
          orderBy: [desc(announcements.createdAt)],
          limit,
        })
        : Promise.resolve([]),

      (type === 'all' || type === 'messages')
        ? db.query.messages.findMany({
          where: and(
            like(messages.content, fullPattern),
            isNull(messages.deletedAt),
            eq(messages.type, 'TEXT'),
            actor.role === 'ADMIN' ? inArray(messages.conversationId,
              db.select({ id: conversations.id }).from(conversations).where(eq(conversations.assignedAdminId, actor.id))
            ) : undefined
          ),
          columns: { id: true, conversationId: true, content: true, createdAt: true },
          with: { sender: { columns: { id: true, name: true, role: true } } },
          orderBy: [desc(messages.createdAt)],
          limit,
        })
        : Promise.resolve([]),

      // Registration reports — SUPER_ADMIN only; search subject and description
      (type === 'all' || type === 'reports') && actor.role === 'SUPER_ADMIN'
        ? db.query.registrationReports.findMany({
          where: or(
            like(registrationReports.subject, fullPattern),
            like(registrationReports.description, fullPattern)
          ),
          columns: { id: true, subject: true, description: true, status: true, createdAt: true, userId: true },
          with: { user: { columns: { id: true, name: true, email: true } } },
          orderBy: [desc(registrationReports.createdAt)],
          limit,
        })
        : Promise.resolve([]),

      // User reports — all admins can search; regular ADMINs see only reports from their assigned users
      (type === 'all' || type === 'reports')
        ? db.query.userReports.findMany({
          where: and(
            or(
              like(userReports.subject, fullPattern),
              like(userReports.description, fullPattern)
            ),
            actor.role === 'ADMIN'
              ? inArray(userReports.userId,
                db.select({ id: conversations.userId }).from(conversations).where(eq(conversations.assignedAdminId, actor.id))
              )
              : undefined
          ),
          columns: { id: true, subject: true, description: true, status: true, createdAt: true, userId: true },
          with: { user: { columns: { id: true, name: true, email: true } } },
          orderBy: [desc(userReports.createdAt)],
          limit,
        })
        : Promise.resolve([]),
    ])

    // ADMIN can only see users assigned to their conversations
    const assignedUserIdSet = actor.role === 'ADMIN'
      ? new Set(matchConversations.map((c) => c.user?.id).filter(Boolean))
      : null
    const matchUsers = type === 'all' || type === 'users'
      ? matchingUsers
          .filter((u) => assignedUserIdSet === null || assignedUserIdSet.has(u.id))
          .slice(0, limit)
      : []

    return sendOk(reply, {
      users: matchUsers,
      conversations: matchConversations,
      announcements: matchAnnouncements,
      messages: matchMessages,
      registrationReports: matchRegReports,
      userReports: matchUserReports,
    })
  })
}
