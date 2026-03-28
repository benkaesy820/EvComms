/**
 * Admin Queue Route
 *
 * GET /admin/queue
 *   Returns:
 *     - unassignedCount: conversations with no assigned admin
 *     - waitingConversations: conversations where user is waiting, sorted by wait time (oldest first)
 *     - idleConversations: conversations where last admin reply was > idleThresholdHours ago
 *     - adminWorkloads: per-admin active conversation counts + online status
 *
 * This single endpoint gives SUPER_ADMINs full queue visibility
 * and gives regular ADMINs their own workload context.
 */

import type { FastifyInstance } from 'fastify'
import { and, isNull, lt, isNotNull, eq } from 'drizzle-orm'
import { db } from '../db/index.js'
import { conversations } from '../db/schema.js'
import { requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { getAllAdminWorkloads } from '../lib/assignmentEngine.js'
import { serverState } from '../state.js'
import { getConfig } from '../lib/config.js'
import { logger } from '../lib/logger.js'

export async function queueRoutes(fastify: FastifyInstance) {
  fastify.get('/queue', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const cfg = getConfig()
    const idleThresholdHours = cfg.assignment?.idleThresholdHours ?? 4
    const idleThresholdMs = idleThresholdHours * 60 * 60 * 1000
    const idleCutoff = new Date(Date.now() - idleThresholdMs)

    const isSuperAdmin = user.role === 'SUPER_ADMIN'

    try {
      const [unassignedRows, waitingRows, idleRows, workloads] = await Promise.all([
        // Unassigned active conversations
        db.query.conversations.findMany({
          where: and(
            isNull(conversations.assignedAdminId),
            isNull(conversations.archivedAt),
            isNull(conversations.deletedAt)
          ),
          columns: { id: true, userId: true, createdAt: true, lastMessageAt: true, waitingSince: true },
          with: { user: { columns: { id: true, name: true, email: true } } },
          orderBy: (c, { asc }) => [asc(c.createdAt)],
          limit: 100,
        }),

        // Waiting conversations (user sent, no admin reply yet)
        db.query.conversations.findMany({
          where: and(
            isNotNull(conversations.waitingSince),
            isNull(conversations.archivedAt),
            isNull(conversations.deletedAt),
            // Regular admins only see their own assigned queue
            ...(isSuperAdmin ? [] : [eq(conversations.assignedAdminId, user.id)])
          ),
          columns: {
            id: true, userId: true, assignedAdminId: true,
            waitingSince: true, lastMessageAt: true, lastAdminReplyAt: true
          },
          with: {
            user: { columns: { id: true, name: true } },
            assignedAdmin: { columns: { id: true, name: true } },
          },
          orderBy: (c, { asc }) => [asc(c.waitingSince)],
          limit: 200,
        }),

        // Idle conversations — admin hasn't replied in > idleThresholdHours
        db.query.conversations.findMany({
          where: and(
            isNull(conversations.archivedAt),
            isNull(conversations.deletedAt),
            lt(conversations.lastAdminReplyAt, idleCutoff),
            isNotNull(conversations.lastAdminReplyAt),
            isNotNull(conversations.assignedAdminId),
            ...(isSuperAdmin ? [] : [eq(conversations.assignedAdminId, user.id)])
          ),
          columns: {
            id: true, userId: true, assignedAdminId: true,
            lastAdminReplyAt: true, lastMessageAt: true, waitingSince: true
          },
          with: {
            user: { columns: { id: true, name: true } },
            assignedAdmin: { columns: { id: true, name: true } },
          },
          orderBy: (c, { asc }) => [asc(c.lastAdminReplyAt)],
          limit: 100,
        }),

        // All admin workloads (SUPER_ADMIN sees all; ADMIN sees only their own)
        getAllAdminWorkloads(),
      ])

      const enrichedWorkloads = workloads
        .filter((w) => isSuperAdmin || w.adminId === user.id)
        .map((w) => ({
          adminId: w.adminId,
          name: w.name,
          role: w.role,
          activeCount: w.activeCount,
          isOnline: w.isOnline,
        }))
        .sort((a, b) => a.activeCount - b.activeCount)

      return sendOk(reply, {
        queue: {
          unassignedCount: unassignedRows.length,
          unassigned: isSuperAdmin ? unassignedRows : [],
          waiting: waitingRows.map((c) => ({
            conversationId: c.id,
            userId: c.userId,
            userName: c.user?.name ?? 'Unknown',
            assignedAdminId: c.assignedAdminId,
            assignedAdminName: c.assignedAdmin?.name ?? null,
            waitingSince: c.waitingSince ? c.waitingSince.getTime() : null,
            waitMs: c.waitingSince ? Date.now() - c.waitingSince.getTime() : 0,
          })),
          idle: idleRows.map((c) => ({
            conversationId: c.id,
            userId: c.userId,
            userName: c.user?.name ?? 'Unknown',
            assignedAdminId: c.assignedAdminId,
            assignedAdminName: c.assignedAdmin?.name ?? null,
            lastAdminReplyAt: c.lastAdminReplyAt ? c.lastAdminReplyAt.getTime() : null,
            idleMs: c.lastAdminReplyAt ? Date.now() - c.lastAdminReplyAt.getTime() : 0,
          })),
          adminWorkloads: enrichedWorkloads,
          config: {
            maxConversationsPerAdmin: cfg.assignment?.maxConversationsPerAdmin ?? 25,
            idleThresholdHours,
          },
        },
      })
    } catch (error) {
      logger.error({ error }, 'Queue stats failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to load queue')
    }
  })
}
