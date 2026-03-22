import type { FastifyInstance } from 'fastify'
import { sql, and, isNull, gt, eq } from 'drizzle-orm'
import { db } from '../db/index.js'
import { users, conversations, messages, sessions, announcements } from '../db/schema.js'
import { requireAdmin, requireUser, sendOk, sendError } from '../middleware/auth.js'
import { logger } from '../lib/logger.js'
import { getCacheConfig } from '../lib/config.js'

// FIX #2: Cache separately for SUPER_ADMIN (platform-wide) vs ADMIN (scoped)
let superAdminStatsCache: { data: unknown; expiresAt: number } | null = null

export async function statsRoutes(fastify: FastifyInstance) {
  fastify.get('/', { preHandler: requireAdmin }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const cacheConfig = getCacheConfig()

    // FIX #2: Regular admins get scoped workload stats, not platform-wide numbers
    if (actor.role !== 'SUPER_ADMIN') {
      try {
        const [assignedConvs, unreadConvs, waitingConvs] = await Promise.all([
          db.select({ count: sql<number>`count(*)`.as('count') })
            .from(conversations)
            .where(and(
              eq(conversations.assignedAdminId, actor.id),
              isNull(conversations.archivedAt),
              isNull(conversations.deletedAt)
            )),

          db.select({ count: sql<number>`count(*)`.as('count') })
            .from(conversations)
            .where(and(
              eq(conversations.assignedAdminId, actor.id),
              isNull(conversations.archivedAt),
              isNull(conversations.deletedAt),
              sql`${conversations.adminUnreadCount} > 0`
            )),

          db.select({ count: sql<number>`count(*)`.as('count') })
            .from(conversations)
            .where(and(
              eq(conversations.assignedAdminId, actor.id),
              isNull(conversations.archivedAt),
              isNull(conversations.deletedAt),
              sql`${conversations.waitingSince} IS NOT NULL`
            )),
        ])

        return sendOk(reply, {
          stats: {
            scope: 'admin',
            conversations: {
              assigned: Number(assignedConvs[0]?.count ?? 0),
              unread: Number(unreadConvs[0]?.count ?? 0),
              waiting: Number(waitingConvs[0]?.count ?? 0),
            },
          }
        })
      } catch (error) {
        logger.error({ error }, 'Admin scoped stats query failed')
        return sendError(reply, 503, 'INTERNAL_ERROR', 'Failed to fetch stats')
      }
    }

    // SUPER_ADMIN: full platform stats with cache
    if (superAdminStatsCache && superAdminStatsCache.expiresAt > Date.now()) {
      return sendOk(reply, superAdminStatsCache.data as Record<string, unknown>)
    }

    try {
      const now = new Date()

      const [
        userStats,
        conversationCount,
        messageCount,
        activeSessionCount,
        announcementCount,
      ] = await Promise.all([
        db.select({
          status: users.status,
          count: sql<number>`count(*)`.as('count'),
        })
          .from(users)
          .where(eq(users.role, 'USER'))
          .groupBy(users.status),

        db.select({ count: sql<number>`count(*)`.as('count') })
          .from(conversations),

        db.select({ count: sql<number>`count(*)`.as('count') })
          .from(messages)
          .where(isNull(messages.deletedAt)),

        db.select({ count: sql<number>`count(*)`.as('count') })
          .from(sessions)
          .where(and(
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, now)
          )),

        db.select({ count: sql<number>`count(*)`.as('count') })
          .from(announcements)
          .where(eq(announcements.isActive, true)),
      ])

      const statusMap: Record<string, number> = {}
      let totalUsers = 0
      for (const row of userStats) {
        statusMap[row.status] = Number(row.count)
        totalUsers += Number(row.count)
      }

      const payload = {
        stats: {
          scope: 'super_admin',
          users: {
            total: totalUsers,
            pending: statusMap['PENDING'] ?? 0,
            approved: statusMap['APPROVED'] ?? 0,
            rejected: statusMap['REJECTED'] ?? 0,
            suspended: statusMap['SUSPENDED'] ?? 0,
          },
          conversations: Number(conversationCount[0]?.count ?? 0),
          messages: Number(messageCount[0]?.count ?? 0),
          activeSessions: Number(activeSessionCount[0]?.count ?? 0),
          activeAnnouncements: Number(announcementCount[0]?.count ?? 0),
        },
      }
      superAdminStatsCache = { data: payload, expiresAt: Date.now() + cacheConfig.statsTTLMs }
      return sendOk(reply, payload)
    } catch (error) {
      logger.error({ error }, 'Stats query failed')
      return sendError(reply, 503, 'INTERNAL_ERROR', 'Failed to fetch stats')
    }
  })
}

/** Called by other routes after mutations that affect platform stats (e.g. user status change). */
export function invalidateStatsCache(): void {
  superAdminStatsCache = null
}
