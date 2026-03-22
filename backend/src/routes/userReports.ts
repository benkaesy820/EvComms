import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { desc, eq, and, lt, sql, inArray } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { userReports, users, auditLogs, conversations, media } from '../db/schema.js'
import { requireApprovedUser, requireAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { isAdmin } from '../lib/permissions.js'
import { isValidId, validateReportMedia, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { emitToAdmins, emitToUser } from '../socket/index.js'
import { createRateLimiters } from '../middleware/rateLimit.js'

const createReportSchema = z.object({
    subject: z.string().min(1).max(200),
    description: z.string().min(1).max(5000),
    mediaId: z.string().optional(),
})

const paginateSchema = z.object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
    before: z.string().optional(),
    status: z.enum(['PENDING', 'RESOLVED', 'ALL']).default('ALL'),
})


// Normalize timestamps to unix milliseconds so the frontend always receives numbers,
// regardless of how Drizzle/libsql deserializes the SQLite integer columns.
function normalizeReport<T extends { createdAt: Date | number | null; updatedAt?: Date | number | null; user?: Record<string, unknown> }>(row: T): T & { createdAt: number } {
    const toMs = (v: Date | number | null | undefined): number => {
        if (v == null) return Date.now()
        if (v instanceof Date) return v.getTime()
        return v < 1e12 ? v * 1000 : v // seconds → ms
    }
    const result = { ...row, createdAt: toMs(row.createdAt) }
    if (result.user && result.user.createdAt != null) {
        result.user = { ...result.user, createdAt: toMs(result.user.createdAt) }
    }
    return result
}

export async function userReportsRoutes(fastify: FastifyInstance) {
    const rateLimiters = createRateLimiters()

    // POST /user-reports — create a new report (approved users only)
    // HIGH FIX: Add rate limiting to prevent spam (10 reports per hour per user)
    fastify.post('/', { preHandler: [requireApprovedUser, rateLimiters.reportCreate] }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return
        
        // Type assertion after null check
        const userId = user.id

        const body = createReportSchema.safeParse(request.body)
        if (!body.success) {
            return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
        }

        // Validate media if provided
        if (body.data.mediaId) {
            const mediaRecord = await db.query.media.findFirst({
                where: eq(media.id, body.data.mediaId),
                columns: { id: true, status: true, uploadedBy: true, uploadedAt: true }
            })

            const validation = validateReportMedia(mediaRecord, userId, 1)
            if (!validation.valid) {
                return sendError(reply, 400, 'VALIDATION_ERROR', validation.error!)
            }
        }

        const reportId = ulid()

        try {
            await db.transaction(async (tx) => {
                await tx.insert(userReports).values({
                    id: reportId,
                    userId: userId,
                    subject: body.data.subject,
                    description: body.data.description,
                    mediaId: body.data.mediaId || null,
                    status: 'PENDING',
                })

                await tx.insert(auditLogs).values({
                    id: ulid(),
                    userId: userId,
                    ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
                    action: 'user_report.created',
                    entityType: 'user_report',
                    entityId: reportId,
                    details: JSON.stringify({ subject: body.data.subject })
                })
            })
        } catch (err) {
            logger.error({ userId: userId, err }, 'Failed to create user report')
            return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to create report')
        }

        // Notify admins via socket
        try {
            emitToAdmins('user_report:new', {
                reportId,
                userId: userId,
                subject: body.data.subject,
                createdAt: Date.now()
            })
        } catch (err) {
            // MEDIUM FIX: Log socket errors for debugging
            logger.debug({ userId, reportId, err }, 'Socket emit failed for new report notification')
        }

        return sendOk(reply, { 
            success: true, 
            message: 'Report submitted successfully',
            reportId 
        })
    })

    // GET /user-reports — list user's own reports
    fastify.get('/', { preHandler: requireApprovedUser }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return
        const userId = user.id

        const query = paginateSchema.safeParse(request.query)
        if (!query.success) {
            return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query')
        }

        const { limit, before, status } = query.data
        const conditions: ReturnType<typeof eq>[] = [eq(userReports.userId, userId)]

        if (status !== 'ALL') {
            conditions.push(eq(userReports.status, status))
        }

        if (before && isValidId(before)) {
            const beforeMs = decodeTime(before)
            conditions.push(lt(userReports.createdAt, new Date(beforeMs)))
        }

        const rows = await db.query.userReports.findMany({
            where: and(...conditions),
            orderBy: [desc(userReports.createdAt)],
            limit: limit + 1,
            with: {
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true } },
            },
        })

        const hasMore = rows.length > limit
        const reports = rows.slice(0, limit)

        return sendOk(reply, { reports: reports.map(normalizeReport), hasMore })
    })

    // GET /user-reports/:id — get single report (user can only view their own)
    fastify.get('/:id', { preHandler: requireApprovedUser }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return
        const userId = user.id

        const { id } = request.params as { id: string }
        if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

        const report = await db.query.userReports.findFirst({
            where: and(eq(userReports.id, id), eq(userReports.userId, userId)),
            with: {
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
            },
        })

        if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')

        return sendOk(reply, { report: normalizeReport(report) })
    })
}

// Admin routes for managing user reports
export async function adminUserReportsRoutes(fastify: FastifyInstance) {
    // GET /admin/user-reports — list all reports (admin only)
    fastify.get('/', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        const query = paginateSchema.safeParse(request.query)
        if (!query.success) {
            return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query')
        }

        const { limit, before, status } = query.data
        const conditions: ReturnType<typeof eq>[] = []
        let assignedUserIds: string[] = []

        // ADMIN can only see reports for their assigned users
        // SUPER_ADMIN can see all reports
        if (user.role === 'ADMIN') {
            const assignedConversations = await db.query.conversations.findMany({
                where: eq(conversations.assignedAdminId, user.id),
                columns: { userId: true },
            })
            assignedUserIds = assignedConversations.map(c => c.userId)

            if (assignedUserIds.length === 0) {
                return sendOk(reply, { reports: [], hasMore: false, pendingCount: 0 })
            }

            conditions.push(inArray(userReports.userId, assignedUserIds))
        }

        if (status !== 'ALL') {
            conditions.push(eq(userReports.status, status))
        }

        if (before && isValidId(before)) {
            const beforeMs = decodeTime(before)
            conditions.push(lt(userReports.createdAt, new Date(beforeMs)))
        }

        const rows = await db.query.userReports.findMany({
            where: conditions.length > 0 ? and(...conditions) : undefined,
            orderBy: [desc(userReports.createdAt)],
            limit: limit + 1,
            with: {
                user: { columns: { id: true, name: true, email: true, status: true } },
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true } },
            },
        })

        const hasMore = rows.length > limit
        const reports = rows.slice(0, limit)

        // Pending count (reuse assignedUserIds from earlier to avoid N+1 query)
        const pendingConditions = [eq(userReports.status, 'PENDING')]
        if (user.role === 'ADMIN') {
            if (assignedUserIds.length > 0) {
                pendingConditions.push(inArray(userReports.userId, assignedUserIds))
            } else {
                return sendOk(reply, { reports, hasMore, pendingCount: 0 })
            }
        }

        const pendingCount = await db
            .select({ count: sql<number>`count(*)` })
            .from(userReports)
            .where(and(...pendingConditions))
            .then(r => r[0]?.count ?? 0)

        return sendOk(reply, { reports: reports.map(normalizeReport), hasMore, pendingCount })
    })

    // GET /admin/user-reports/:id — get single report
    fastify.get('/:id', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        const { id } = request.params as { id: string }
        if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

        const report = await db.query.userReports.findFirst({
            where: eq(userReports.id, id),
            with: {
                user: { columns: { id: true, name: true, email: true, phone: true, status: true } },
                media: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
            },
        })

        if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')

        // ADMIN can only view reports for their assigned users
        if (user.role === 'ADMIN') {
            const conversation = await db.query.conversations.findFirst({
                where: and(
                    eq(conversations.userId, report.userId),
                    eq(conversations.assignedAdminId, user.id)
                ),
            })

            if (!conversation) {
                return sendError(reply, 403, 'FORBIDDEN', 'You do not have access to this report')
            }
        }

        return sendOk(reply, { report: normalizeReport(report) })
    })

    // PATCH /admin/user-reports/:id — resolve a report
    fastify.patch('/:id', { preHandler: requireAdmin }, async (request, reply) => {
        const user = requireUser(request, reply)
        if (!user) return

        const { id } = request.params as { id: string }
        if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

        const report = await db.query.userReports.findFirst({
            where: eq(userReports.id, id),
        })

        if (!report) return sendError(reply, 404, 'NOT_FOUND', 'Report not found')

        // ADMIN can only resolve reports for their assigned users
        if (user.role === 'ADMIN') {
            const conversation = await db.query.conversations.findFirst({
                where: and(
                    eq(conversations.userId, report.userId),
                    eq(conversations.assignedAdminId, user.id)
                ),
            })

            if (!conversation) {
                return sendError(reply, 403, 'FORBIDDEN', 'You do not have access to this report')
            }
        }

        const now = new Date()
        try {
            await db.transaction(async (tx) => {
                // HIGH FIX: Prevent race condition - only update if still PENDING
                const updateResult = await tx.update(userReports)
                    .set({
                        status: 'RESOLVED',
                        resolvedAt: now,
                        resolvedBy: user.id,
                        updatedAt: now
                    })
                    .where(and(
                        eq(userReports.id, id),
                        eq(userReports.status, 'PENDING')
                    ))
                    .returning({ id: userReports.id })

                // If no rows updated, report was already resolved or doesn't exist
                if (!updateResult || updateResult.length === 0) {
                    throw new Error('Report already resolved or not found')
                }

                await tx.insert(auditLogs).values({
                    id: ulid(),
                    userId: user.id,
                    ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
                    action: 'user_report.resolved',
                    entityType: 'user_report',
                    entityId: id,
                })
            })

            // Notify user their report was resolved
            try {
                emitToUser(report.userId, 'user_report:resolved', { reportId: id })
            } catch (err) {
                logger.debug({ userId: report.userId, reportId: id, err }, 'Socket emit failed for resolved report notification')
            }
        } catch (err) {
            logger.error({ reportId: id, err }, 'Failed to resolve user report')
            if (err instanceof Error && err.message === 'Report already resolved or not found') {
                return sendError(reply, 409, 'CONFLICT', 'Report already resolved')
            }
            return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to resolve report')
        }

        return sendOk(reply, { resolved: true })
    })
}
