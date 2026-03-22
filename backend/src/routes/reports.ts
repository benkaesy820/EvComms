import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { desc, eq, and, lt, sql, inArray, or, isNull, notInArray } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { registrationReports, users, auditLogs, conversations } from '../db/schema.js'
import { requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { isAdmin } from '../lib/permissions.js'
import { isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { emitToAdmins } from '../socket/index.js'

const paginateSchema = z.object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
    before: z.string().optional(),
    status: z.enum(['PENDING', 'REVIEWED', 'ALL']).default('ALL'),
})


function normalizeReport<T extends { createdAt: Date | number | null; user?: { createdAt?: Date | number | null } }>(row: T): T & { createdAt: number } {
    const toMs = (v: Date | number | null | undefined): number => {
        if (v == null) return Date.now()
        if (v instanceof Date) return v.getTime()
        return v < 1e12 ? v * 1000 : v
    }
    const result = { ...row, createdAt: toMs(row.createdAt) }
    if (result.user && result.user.createdAt != null) {
        result.user = { ...result.user, createdAt: toMs(result.user.createdAt) }
    }
    return result
}

export async function reportsRoutes(fastify: FastifyInstance) {
    // GET /reports — paginated list
    // SUPER_ADMIN: sees all reports
    // ADMIN: sees only reports for users assigned to them
    fastify.get('/', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        const query = paginateSchema.safeParse(request.query)
        if (!query.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query')

        const { limit, before, status } = query.data
        const conditions: ReturnType<typeof eq>[] = []

        // Filter by status
        if (status !== 'ALL') {
            conditions.push(eq(registrationReports.status, status))
        }

        // Cursor pagination
        if (before && isValidId(before)) {
            const beforeMs = decodeTime(before)
            conditions.push(lt(registrationReports.createdAt, new Date(beforeMs)))
        }

        // ADMIN can only see reports for their assigned users OR for PENDING users
        // with no assigned conversation yet (i.e., users awaiting initial approval)
        let assignedUserIds: string[] = []
        let unassignedPendingIds: string[] = []
        if (user.role === 'ADMIN') {
            const assignedConversations = await db.query.conversations.findMany({
                where: eq(conversations.assignedAdminId, user.id),
                columns: { userId: true },
            })
            assignedUserIds = assignedConversations.map(c => c.userId)

            // Include PENDING users who have no conversation at all (unassigned registrations).
            // PERF FIX (High): Replace the full conversations table scan with a targeted
            // subquery. Previously loaded ALL conversations into Node memory to build a Set.
            // Now uses SQL EXISTS checks which hit the idx_conversations_user index directly.
            const pendingUsersWithNoConv = (await db.query.users.findMany({
                where: and(eq(users.status, 'PENDING'), eq(users.role, 'USER')),
                columns: { id: true }
            })).map(u => u.id)

            // Filter to only users who truly have no conversation (active or deleted)
            if (pendingUsersWithNoConv.length > 0) {
                const withConvRows = await db.query.conversations.findMany({
                    where: and(
                        inArray(conversations.userId, pendingUsersWithNoConv),
                        isNull(conversations.deletedAt)
                    ),
                    columns: { userId: true }
                })
                const withConvSet = new Set(withConvRows.map(c => c.userId))
                unassignedPendingIds = pendingUsersWithNoConv.filter(id => !withConvSet.has(id))
            }

            // Build condition: assigned to this admin OR (PENDING user with no conversation)
            const pendingUnassignedCondition = unassignedPendingIds.length > 0
                ? inArray(registrationReports.userId, unassignedPendingIds)
                : sql`0 = 1`  // no unassigned pending users — match nothing

            if (assignedUserIds.length > 0) {
                conditions.push(
                    or(
                        inArray(registrationReports.userId, assignedUserIds),
                        pendingUnassignedCondition
                    ) as ReturnType<typeof eq>
                )
            } else if (unassignedPendingIds.length > 0) {
                conditions.push(inArray(registrationReports.userId, unassignedPendingIds) as ReturnType<typeof eq>)
            } else {
                // No assigned users and no unassigned pending users — return empty
                return sendOk(reply, { reports: [], hasMore: false, pendingCount: 0 })
            }
        }

        const rows = await db.query.registrationReports.findMany({
            where: conditions.length > 0 ? and(...conditions) : undefined,
            orderBy: [desc(registrationReports.createdAt)],
            limit: limit + 1,
            with: {
                user: { columns: { id: true, name: true, email: true, status: true, createdAt: true } },
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true } },
            },
        })

        const hasMore = rows.length > limit
        const reports = rows.slice(0, limit)

        // Pending count for badge — SUPER_ADMIN gets global count; ADMIN gets scoped count
        // (assigned users + unassigned PENDING users)
        let pendingCount = 0
        if (user.role === 'SUPER_ADMIN') {
            pendingCount = await db
                .select({ count: sql<number>`count(*)` })
                .from(registrationReports)
                .where(eq(registrationReports.status, 'PENDING'))
                .then(r => r[0]?.count ?? 0)
        } else {
            // For ADMIN: count pending reports that are either assigned to them or unassigned (PENDING user with no conv)
            // PERF FIX: Reuse already-computed unassignedPendingIds from above
            const scopedIds = [...new Set([...assignedUserIds, ...unassignedPendingIds])]
            if (scopedIds.length > 0) {
                pendingCount = await db
                    .select({ count: sql<number>`count(*)` })
                    .from(registrationReports)
                    .where(and(
                        eq(registrationReports.status, 'PENDING'),
                        inArray(registrationReports.userId, scopedIds)
                    ))
                    .then(r => r[0]?.count ?? 0)
            }
        }

        return sendOk(reply, { reports: reports.map(normalizeReport), hasMore, pendingCount })
    })

    // GET /reports/:id — single report
    // SUPER_ADMIN: can view any report
    // ADMIN: can view only if user is assigned to them
    fastify.get('/:id', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        const { id } = request.params as { id: string }
        if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

        const report = await db.query.registrationReports.findFirst({
            where: eq(registrationReports.id, id),
            with: {
                user: { columns: { id: true, name: true, email: true, phone: true, status: true, createdAt: true } },
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
            },
        })

        if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')

        // ADMIN can view reports for:
        // 1. Users assigned to them via a conversation, OR
        // 2. PENDING users who have no conversation yet (unassigned new registrations)
        if (user.role === 'ADMIN') {
            const conversation = await db.query.conversations.findFirst({
                where: and(
                    eq(conversations.userId, report.userId),
                    eq(conversations.assignedAdminId, user.id)
                ),
            })

            if (!conversation) {
                // Check if user is PENDING with no conversation at all
                const reportUser = await db.query.users.findFirst({
                    where: eq(users.id, report.userId),
                    columns: { status: true }
                })
                const anyConversation = await db.query.conversations.findFirst({
                    where: eq(conversations.userId, report.userId),
                    columns: { id: true }
                })

                const isPendingUnassigned = reportUser?.status === 'PENDING' && !anyConversation
                if (!isPendingUnassigned) {
                    return sendError(reply, 403, 'FORBIDDEN', 'You do not have access to this report')
                }
            }
        }

        // Check if user already has a conversation
        const existingConv = await db.query.conversations.findFirst({
            where: eq(conversations.userId, report.userId),
            columns: { id: true },
        })

        return sendOk(reply, { report: normalizeReport(report), hasConversation: !!existingConv })
    })

    // PATCH /reports/:id — mark reviewed (Super Admin only)
    fastify.patch('/:id', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        // Only SUPER_ADMIN can mark reports as reviewed
        if (user.role !== 'SUPER_ADMIN') {
            return sendError(reply, 403, 'FORBIDDEN', 'Super Admin access required')
        }

        const { id } = request.params as { id: string }
        if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

  const report = await db.query.registrationReports.findFirst({
    where: eq(registrationReports.id, id),
    columns: { id: true, status: true, userId: true },
  })
  if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')

  const now = new Date()
  let updated = false
  try {
    await db.transaction(async (tx) => {
      // HIGH FIX: Prevent race condition - only update if still PENDING
      const updateResult = await tx.update(registrationReports)
      .set({
        status: 'REVIEWED',
        reviewedAt: now,
        reviewedBy: user.id,
        updatedAt: now
      })
      .where(and(
        eq(registrationReports.id, id),
        eq(registrationReports.status, 'PENDING')
      ))
      .returning({ id: registrationReports.id })

      // If no rows updated, report was already reviewed or doesn't exist
      if (!updateResult || updateResult.length === 0) {
        throw new Error('Report already reviewed or not found')
      }
      updated = true

      await tx.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'report.reviewed',
        entityType: 'registration_report',
        entityId: id,
      })
    })
  } catch (err) {
    logger.error({ reportId: id, err }, 'Failed to mark report reviewed')
    if (err instanceof Error && err.message === 'Report already reviewed or not found') {
      return sendError(reply, 409, 'CONFLICT', 'Report already reviewed')
    }
    return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update report')
  }

  // Notify all admins that report was reviewed
  if (updated) {
    emitToAdmins('report:reviewed', {
      userId: report.userId,
      reportIds: [id],
      reviewedBy: user.id,
      reviewedAt: now.getTime(),
      autoReviewed: false // Indicates this was manual review by Super Admin
    })
  }

  return sendOk(reply, { reviewed: true })
    })
}
