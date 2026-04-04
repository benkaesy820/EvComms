import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { and, desc, eq, inArray, isNull, like, lt, or } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import crypto from 'crypto'
import { hash } from '@node-rs/argon2'
import { db } from '../db/index.js'
import { auditLogs, sessions, userStatusHistory, users, refreshTokens, registrationReports, conversations, userReports } from '../db/schema.js'
import { requireAdmin, requireSuperAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { updateUserCache, invalidateAllUserSessions } from '../state.js'
import { sendEmail } from '../services/email.js'
import { queueHighPriorityEmail } from '../services/emailQueue.js'
import { emitToUser, emitToAdmins, forceLogout } from '../socket/index.js'
import { invalidateStatsCache } from './stats.js'
import { mediaCleanupService } from '../services/mediaCleanup.js'
import { createRateLimiters } from '../middleware/rateLimit.js'
import { sanitizeText, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'

const statusUpdateSchema = z.object({
  status: z.enum(['PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED']),
  reason: z.string().max(500).transform(s => sanitizeText(s)).optional()
})

const mediaPermissionSchema = z.object({
  mediaPermission: z.boolean()
})

const adminListSchema = z.object({
  status: z.enum(['PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED']).optional(),
  search: z.string().max(255).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.string().optional()
})

function normalizeSearch(value: string): string {
  return value.trim().toLowerCase().replace(/[%_]/g, '\\$&')
}

export async function adminUserRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  fastify.get('/users', { preHandler: requireAdmin }, async (request, reply) => {
    const requestUser = requireUser(request, reply)
    if (!requestUser) return

    const query = adminListSchema.safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    const conditions = []
    if (query.data.status) conditions.push(eq(users.status, query.data.status))
    // Always scope to regular users only — admin management is done through /admin/admins
    conditions.push(eq(users.role, 'USER'))
    if (query.data.search) {
      const search = `%${normalizeSearch(query.data.search)}%`
      conditions.push(or(like(users.email, search), like(users.name, search)))
    }
    if (query.data.before && isValidId(query.data.before)) {
      const beforeMs = decodeTime(query.data.before)
      conditions.push(lt(users.createdAt, new Date(beforeMs)))
    }

    // Normal Admins can only see users whose active conversation is assigned to them.
    if (requestUser.role !== 'SUPER_ADMIN') {
      const assignedConvs = await db.query.conversations.findMany({
        where: eq(conversations.assignedAdminId, requestUser.id),
        columns: { userId: true },
      })
      const assignedUserIds = assignedConvs.map(c => c.userId)
      if (assignedUserIds.length === 0) {
        return sendOk(reply, { users: [], hasMore: false })
      }
      conditions.push(inArray(users.id, assignedUserIds))
    }

    const result = await db.query.users.findMany({
      where: conditions.length ? and(...conditions) : undefined,
      orderBy: [desc(users.createdAt)],
      limit: query.data.limit + 1,
      columns: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        status: true,
        mediaPermission: true,
        rejectionReason: true,
        createdAt: true,
        lastSeenAt: true
      }
    })

    const hasMore = result.length > query.data.limit
    const usersToReturn = hasMore ? result.slice(0, -1) : result

    return sendOk(reply, { users: usersToReturn, hasMore })
  })

  fastify.patch('/users/:userId/status', { preHandler: requireAdmin }, async (request, reply) => {
    const admin = requireUser(request, reply)
    if (!admin) {
      return
    }

    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    const body = statusUpdateSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    if (userId === admin.id) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot change your own status')
    }

    if ((body.data.status === 'REJECTED' || body.data.status === 'SUSPENDED') && !body.data.reason) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Reason required for rejection/suspension')
    }

    // For ADMIN: verify assignment before fetching target (prevents user enumeration).
    // For SUPER_ADMIN: fetch user directly — no assignment constraint.
    // Both checks are independent; run them in parallel for SUPER_ADMIN path.
    let target: Awaited<ReturnType<typeof db.query.users.findFirst>> | undefined
    if (admin.role !== 'SUPER_ADMIN') {
      const [conv, fetchedTarget] = await Promise.all([
        db.query.conversations.findFirst({
          where: and(
            eq(conversations.userId, userId),
            eq(conversations.assignedAdminId, admin.id),
            isNull(conversations.archivedAt),
            isNull(conversations.deletedAt)
          ),
          columns: { id: true }
        }),
        db.query.users.findFirst({ where: eq(users.id, userId) })
      ])
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
      target = fetchedTarget
    } else {
      target = await db.query.users.findFirst({ where: eq(users.id, userId) })
    }

    if (!target) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    if (target.role !== 'USER' && admin.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only super admins can change admin status')
    }

    if (target.role === 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot change super admin status')
    }

    if (target.status === body.data.status) {
      return sendError(reply, 409, 'CONFLICT', 'Status already set')
    }

  const now = new Date()
  let affectedReportIds: string[] = []
  // Holds payloads for newly created userReports — emitted to the user after the transaction
  const createdUserReports: Array<{ reportId: string; subject: string; createdAt: number }> = []

  // Pre-calculate conversation assignment outside transaction to prevent rollback on assignment failure
  let newConvId: string | null = null
  let bestAdminId: string | null = null
  let subId: string | null = null

  if (body.data.status === 'APPROVED') {
    const existingConv = await db.query.conversations.findFirst({
      where: eq(conversations.userId, userId),
      columns: { id: true }
    })
    
    if (!existingConv) {
      if (target.subsidiaryIds) {
        try {
          const parsed = JSON.parse(target.subsidiaryIds)
          if (Array.isArray(parsed) && parsed.length > 0) subId = parsed[0]
        } catch {}
      }
      
      try {
        const { pickBestAdmin } = await import('../lib/assignmentEngine.js')
        bestAdminId = await pickBestAdmin(subId)
      } catch (err) {
        logger.warn({ userId, err }, 'Assignment engine failed during approval pre-flight, defaulting to null')
      }
      newConvId = ulid()
    }
  }

  try {
    await db.transaction(async (tx) => {
      // Strip mediaPermission when suspending/rejecting; keep it when approving
      // (re-approve restores the original permission rather than forcing manual re-grant)
      const mediaPermissionUpdate =
        body.data.status === 'SUSPENDED' || body.data.status === 'REJECTED'
          ? { mediaPermission: false }
          : {}

      await tx.update(users)
      .set({
        status: body.data.status,
        rejectionReason: body.data.status === 'APPROVED' ? null : (body.data.reason || null),
        updatedAt: now,
        ...mediaPermissionUpdate
      })
      .where(eq(users.id, userId))

      await tx.insert(userStatusHistory).values({
        id: ulid(),
        userId,
        previousStatus: target.status,
        newStatus: body.data.status,
        changedBy: admin.id,
        reason: body.data.reason || null
      })

      await tx.insert(auditLogs).values({
        id: ulid(),
        userId: admin.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'user.status_change',
        entityType: 'user',
        entityId: userId,
        details: JSON.stringify({
          previousStatus: target.status,
          newStatus: body.data.status,
          reason: body.data.reason
        })
      })

      if (body.data.status === 'REJECTED' || body.data.status === 'SUSPENDED') {
        await tx.update(sessions)
        .set({ revokedAt: now })
        .where(and(
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt)
        ))

        await tx.update(refreshTokens)
        .set({ revokedAt: now })
        .where(and(
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt)
        ))
      }

      // When approving a user, mark all their pending registration reports
      // as REVIEWED and create corresponding userReport records so they
      // are accessible as normal reports in the conversation context.
      if (body.data.status === 'APPROVED') {
        // First get the IDs of reports that will be updated
        const pendingReports = await tx.select({
          id: registrationReports.id,
          subject: registrationReports.subject,
          description: registrationReports.description,
          mediaId: registrationReports.mediaId,
        })
          .from(registrationReports)
          .where(and(
            eq(registrationReports.userId, userId),
            eq(registrationReports.status, 'PENDING')
          ))
        affectedReportIds = pendingReports.map(r => r.id)

        await tx.update(registrationReports)
        .set({
          status: 'REVIEWED',
          reviewedAt: now,
          reviewedBy: admin.id,
          updatedAt: now,
        })
        .where(and(
          eq(registrationReports.userId, userId),
          eq(registrationReports.status, 'PENDING')
        ))

        // Create a userReport for each registration report so the approved
        // user can reference their original report within their conversation.
        // HIGH FIX: Check for existing userReports derived from this registration
        // report to prevent duplicate insertion on re-approval cycles.
        for (const regReport of pendingReports) {
          const existing = await tx.query.userReports.findFirst({
            where: eq(userReports.sourceRegistrationReportId, regReport.id),
            columns: { id: true }
          })
          if (existing) continue  // Already bridged — skip to prevent duplicate

          const newUserReportId = ulid()
          await tx.insert(userReports).values({
            id: newUserReportId,
            userId,
            subject: regReport.subject,
            description: regReport.description,
            mediaId: regReport.mediaId || null,
            sourceRegistrationReportId: regReport.id,
            status: 'PENDING',
          })
          await tx.insert(auditLogs).values({
            id: ulid(),
            userId: admin.id,
            ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
            action: 'user_report.created_from_registration',
            entityType: 'user_report',
            entityId: newUserReportId,
            details: JSON.stringify({ sourceRegistrationReportId: regReport.id, targetUserId: userId })
          })
          // Collect payload for post-transaction socket emission
          createdUserReports.push({
            reportId: newUserReportId,
            subject: regReport.subject,
            createdAt: now.getTime(),
          })
        }

        // BUG 6 FIX: Auto-create conversation atomically on approval
        if (newConvId) {
          await tx.insert(conversations).values({
            id: newConvId,
            userId: userId,
            subsidiaryId: subId,
            registrationReportId: affectedReportIds.length > 0 ? affectedReportIds[0] : null,
            assignedAdminId: bestAdminId,
            createdAt: now,
            unreadCount: 0,
            adminUnreadCount: 0
          }).onConflictDoNothing()
          
          logger.info({ userId, conversationId: newConvId, assignedAdminId: bestAdminId }, 'Auto-created atomic conversation on approval')
        }
      }
    })
  } catch (error) {
    // Turso uses HTTP/2 pipeline for transactions. An ECONNRESET mid-pipeline means
    // the TCP connection dropped — but the server may have already committed the transaction
    // before the reset. We can't distinguish "committed then dropped" from "rolled back".
    // Strategy: on connection errors, verify the actual DB state and treat as success if
    // the status matches what we intended to set (the transaction went through).
    const isConnError = error instanceof Error && (
      error.message.includes('ECONNRESET') ||
      error.message.includes('pipeline failed') ||
      error.message.includes('socket hang up') ||
      error.message.includes('ECONNREFUSED')
    )

    if (isConnError) {
      try {
        const actualUser = await db.query.users.findFirst({
          where: eq(users.id, userId),
          columns: { status: true }
        })
        if (actualUser?.status === body.data.status) {
          // Transaction committed on Turso despite the connection drop — proceed as success.
          logger.warn(
            { userId, adminId: admin.id, targetStatus: body.data.status },
            'Status update transaction committed despite ECONNRESET — recovering silently'
          )
          // Fall through to the post-transaction code below (no return here).
        } else {
          // Status did NOT change — transaction was rolled back. Genuine failure.
          logger.error({ userId, adminId: admin.id, error }, 'Status update failed (rolled back after ECONNRESET)')
          return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update status')
        }
      } catch (verifyError) {
        // Even the verification SELECT failed — DB is unstable. Return 500.
        logger.error({ userId, adminId: admin.id, error, verifyError }, 'Status update failed (cannot verify state after ECONNRESET)')
        return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update status')
      }
    } else {
      logger.error({ userId, adminId: admin.id, error }, 'Status update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update status')
    }
  }

  const cacheUpdate: Record<string, unknown> = { status: body.data.status }
  if (body.data.status === 'SUSPENDED' || body.data.status === 'REJECTED') {
    cacheUpdate.mediaPermission = false
  }
  updateUserCache(userId, cacheUpdate)

  emitToUser(userId, 'user:status_changed', {
    userId,
    status: body.data.status,
    reason: body.data.reason,
    changedAt: now.getTime(),
    ...(body.data.status === 'SUSPENDED' || body.data.status === 'REJECTED'
      ? { mediaPermission: false }
      : {})
  })

  // Invalidate the super-admin stats cache so the pending-users badge clears immediately
  // on all connected admin clients without waiting for the TTL to expire.
  invalidateStatsCache()
  emitToAdmins('stats:invalidate', {})

  // Emit to all admins that reports were reviewed (if any were affected)
  if (body.data.status === 'APPROVED' && affectedReportIds.length > 0) {
    emitToAdmins('report:reviewed', {
      userId,
      reportIds: affectedReportIds,
      reviewedBy: admin.id,
      reviewedAt: now.getTime(),
      autoReviewed: true // Indicates this was automatic on user approval
    })
  }

  // Emit user_report:new to the approved user for each report that was just created
  // from their registration reports. Without this the user's report list only updates
  // on a manual page refresh — the socket handler is already wired, just no event was fired.
  for (const report of createdUserReports) {
    emitToUser(userId, 'user_report:new', {
      reportId: report.reportId,
      userId,
      subject: report.subject,
      createdAt: report.createdAt,
    })
  }

    if (body.data.status === 'REJECTED' || body.data.status === 'SUSPENDED') {
      forceLogout(userId, `Account ${body.data.status.toLowerCase()}`)
      invalidateAllUserSessions(userId)
    }

    try {
      if (body.data.status === 'APPROVED') {
        await queueHighPriorityEmail(userId, 'accountApproved')
      } else if (body.data.status === 'REJECTED' && body.data.reason) {
        await sendEmail({ type: 'accountRejected', userId, reason: body.data.reason })
      } else if (body.data.status === 'SUSPENDED' && body.data.reason) {
        await sendEmail({ type: 'accountSuspended', userId, reason: body.data.reason })
      }
    } catch (error) {
      logger.warn({ userId, status: body.data.status, error }, 'Failed to send status email')
    }

    return sendOk(reply, { message: 'Status updated' })
  })

  fastify.patch('/users/:userId/media-permission', { preHandler: requireAdmin }, async (request, reply) => {
    const admin = requireUser(request, reply)
    if (!admin) {
      return
    }

    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    const body = mediaPermissionSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    // Parallel: authorization check and target fetch are independent for SUPER_ADMIN
    let targetUser: Awaited<ReturnType<typeof db.query.users.findFirst>> | undefined
    if (admin.role !== 'SUPER_ADMIN') {
      const [conv, fetchedTarget] = await Promise.all([
        db.query.conversations.findFirst({
          where: and(
            eq(conversations.userId, userId),
            eq(conversations.assignedAdminId, admin.id),
            isNull(conversations.archivedAt),
            isNull(conversations.deletedAt)
          ),
          columns: { id: true }
        }),
        db.query.users.findFirst({ where: eq(users.id, userId) })
      ])
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
      targetUser = fetchedTarget
    } else {
      targetUser = await db.query.users.findFirst({ where: eq(users.id, userId) })
    }

    if (!targetUser) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    if (targetUser.role !== 'USER') {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Admins always have media permission')
    }

    if (body.data.mediaPermission && targetUser.status !== 'APPROVED') {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot grant media permission to a non-approved user')
    }

    const now = new Date()

    try {
      await db.transaction(async (tx) => {
        await tx.update(users)
          .set({
            mediaPermission: body.data.mediaPermission,
            updatedAt: now
          })
          .where(eq(users.id, userId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: admin.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.media_permission_change',
          entityType: 'user',
          entityId: userId,
          details: JSON.stringify({ mediaPermission: body.data.mediaPermission })
        })
      })
    } catch (error) {
      logger.error({ userId, error }, 'Media permission update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update media permission')
    }

    updateUserCache(userId, { mediaPermission: body.data.mediaPermission })

    emitToUser(userId, 'user:media_permission_changed', {
      mediaPermission: body.data.mediaPermission
    })

    return sendOk(reply, {
      user: {
        id: userId,
        mediaPermission: body.data.mediaPermission
      }
    })
  })

  fastify.post('/users/:userId/revoke-sessions', { preHandler: requireAdmin }, async (request, reply) => {
    const admin = requireUser(request, reply)
    if (!admin) {
      return
    }

    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    // FIX #1: assignment guard before target fetch
    if (admin.role !== 'SUPER_ADMIN') {
      const conv = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, userId),
          eq(conversations.assignedAdminId, admin.id),
          isNull(conversations.archivedAt),
          isNull(conversations.deletedAt)
        ),
        columns: { id: true }
      })
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
    }

    const target = await db.query.users.findFirst({
      where: eq(users.id, userId)
    })

    if (!target) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    const now = new Date()

    try {
      await db.transaction(async (tx) => {
        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(and(
            eq(sessions.userId, userId),
            isNull(sessions.revokedAt)
          ))

        await tx.update(refreshTokens)
          .set({ revokedAt: now })
          .where(and(
            eq(refreshTokens.userId, userId),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: admin.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.sessions_revoke',
          entityType: 'user',
          entityId: userId
        })
      })
    } catch (error) {
      logger.error({ userId, adminId: admin.id, error }, 'Session revocation failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to revoke sessions')
    }

    forceLogout(userId, 'Sessions revoked by administrator')

    return sendOk(reply, { message: 'Sessions revoked' })
  })

  // POST /admin/users/:userId/reset-password - Admin-initiated password reset
  // MEDIUM FIX: Add rate limiting (5 per hour per admin)
  fastify.post('/users/:userId/reset-password', { preHandler: [requireAdmin, rateLimiters.adminPasswordReset] }, async (request, reply) => {
    const admin = requireUser(request, reply)
    if (!admin) {
      return
    }

    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    if (userId === admin.id) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Use password change for your own account')
    }

    // SECURITY FIX (Critical): Assignment check BEFORE target fetch, with
    // archivedAt + deletedAt guards to prevent privilege escalation via
    // archived conversations. Prevents horizontal escalation to any user
    // the admin once had an archived conversation with.
    if (admin.role !== 'SUPER_ADMIN') {
      const conv = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, userId),
          eq(conversations.assignedAdminId, admin.id),
          isNull(conversations.archivedAt),
          isNull(conversations.deletedAt)
        ),
        columns: { id: true }
      })
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
    }

    const target = await db.query.users.findFirst({
      where: eq(users.id, userId)
    })

    if (!target) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    // Only SUPER_ADMIN can reset admin passwords
    if (target.role !== 'USER' && admin.role !== 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Only super admins can reset admin passwords')
    }

    if (target.role === 'SUPER_ADMIN') {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot reset super admin password')
    }

    const now = new Date()
    const tempPassword = crypto.randomBytes(16).toString('hex')
    const passwordHash = await hash(tempPassword)

    try {
      await db.transaction(async (tx) => {
        // Update password
        await tx.update(users)
          .set({
            passwordHash,
            updatedAt: now
          })
          .where(eq(users.id, userId))

        // Revoke all existing sessions
        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(and(
            eq(sessions.userId, userId),
            isNull(sessions.revokedAt)
          ))

        await tx.update(refreshTokens)
          .set({ revokedAt: now })
          .where(and(
            eq(refreshTokens.userId, userId),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: admin.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.password_reset_admin',
          entityType: 'user',
          entityId: userId
        })
      })
    } catch (error) {
      logger.error({ userId, adminId: admin.id, error }, 'Admin password reset failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to reset password')
    }

    forceLogout(userId, 'Password reset by administrator')

    // Send email with temporary password
    try {
      await queueHighPriorityEmail(userId, 'passwordResetAdmin', { tempPassword })
    } catch (error) {
      logger.warn({ userId, error }, 'Failed to send password reset email')
    }

    return sendOk(reply, {
      message: 'Password reset successful. User has been logged out and will receive an email with a temporary password.'
      // tempPassword is intentionally never returned in the response - it is emailed only
    })
  })

  fastify.post('/cleanup/media', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const admin = requireUser(request, reply)
    if (!admin) {
      return
    }

    try {
      const result = await mediaCleanupService.triggerManualCleanup()

      await db.insert(auditLogs).values({
        id: ulid(),
        userId: admin.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'admin.media_cleanup',
        entityType: 'system',
        entityId: 'media_cleanup_service',
        details: JSON.stringify({
          cleanedCount: result.cleanedCount,
          failedCount: result.failedCount,
          totalProcessed: result.cleanedCount + result.failedCount
        })
      })

      return sendOk(reply, {
        message: 'Media cleanup completed',
        results: {
          cleanedCount: result.cleanedCount,
          failedCount: result.failedCount,
          totalProcessed: result.cleanedCount + result.failedCount
        }
      })
    } catch (error) {
      logger.error({ error }, 'Media cleanup failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Media cleanup failed')
    }
  })

  fastify.get('/users/:userId', { preHandler: requireAdmin }, async (request, reply) => {
    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    // SECURITY FIX (Critical): Assignment check BEFORE user fetch to prevent
    // TOCTOU window, user-enumeration oracle, and privilege escalation.
    const actor = requireUser(request, reply)
    if (!actor) return

    if (actor.role !== 'SUPER_ADMIN') {
      const conv = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, userId),
          eq(conversations.assignedAdminId, actor.id),
          isNull(conversations.deletedAt)
        ),
        columns: { id: true }
      })
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
    }

    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        status: true,
        mediaPermission: true,
        emailNotifyOnMessage: true,
        rejectionReason: true,
        createdAt: true,
        updatedAt: true,
        lastSeenAt: true
      }
    })

    if (!user) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    return sendOk(reply, { user })
  })

  const statusHistorySchema = z.object({
    limit: z.coerce.number().int().min(1).max(100).default(50),
    before: z.string().optional()
  })

  fastify.get('/users/:userId/status-history', { preHandler: requireAdmin }, async (request, reply) => {
    const { userId } = request.params as { userId: string }

    if (!isValidId(userId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    }

    const query = statusHistorySchema.safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    // SECURITY FIX (High): Assignment check BEFORE existence check to prevent
    // user-enumeration oracle (200/404 leaks userId existence before 403 gate).
    const histActor = requireUser(request, reply)
    if (!histActor) return

    if (histActor.role !== 'SUPER_ADMIN') {
      const conv = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, userId),
          eq(conversations.assignedAdminId, histActor.id),
          isNull(conversations.deletedAt)
        ),
        columns: { id: true }
      })
      if (!conv) return sendError(reply, 403, 'FORBIDDEN', 'No access to this user')
    }

    const target = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: { id: true }
    })
    if (!target) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    const conditions = [eq(userStatusHistory.userId, userId)]
    if (query.data.before && isValidId(query.data.before)) {
      const beforeMs = decodeTime(query.data.before)
      conditions.push(lt(userStatusHistory.createdAt, new Date(beforeMs)))
    }

    const history = await db.query.userStatusHistory.findMany({
      where: and(...conditions),
      orderBy: [desc(userStatusHistory.createdAt)],
      limit: query.data.limit + 1,
      with: {
        changedByUser: {
          columns: { id: true, name: true, role: true }
        }
      }
    })

    const hasMore = history.length > query.data.limit
    const historyToReturn = hasMore ? history.slice(0, -1) : history

    return sendOk(reply, { history: historyToReturn, hasMore })
  })

  const auditLogSchema = z.object({
    action: z.string().max(100).optional(),
    entityType: z.string().max(50).optional(),
    userId: z.string().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    before: z.string().optional()
  })

  fastify.get('/audit-logs', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const query = auditLogSchema.safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    const conditions = []
    if (query.data.action) conditions.push(eq(auditLogs.action, query.data.action))
    if (query.data.entityType) conditions.push(eq(auditLogs.entityType, query.data.entityType))
    if (query.data.userId && isValidId(query.data.userId)) {
      conditions.push(eq(auditLogs.userId, query.data.userId))
    }
    if (query.data.before && isValidId(query.data.before)) {
      const beforeMs = decodeTime(query.data.before)
      conditions.push(lt(auditLogs.createdAt, new Date(beforeMs)))
    }

    const logs = await db.query.auditLogs.findMany({
      where: conditions.length ? and(...conditions) : undefined,
      orderBy: [desc(auditLogs.createdAt)],
      limit: query.data.limit + 1,
      with: {
        user: {
          columns: { id: true, name: true, role: true }
        }
      }
    })

    const hasMore = logs.length > query.data.limit
    const logsToReturn = hasMore ? logs.slice(0, -1) : logs

    return sendOk(reply, { logs: logsToReturn, hasMore })
  })
}