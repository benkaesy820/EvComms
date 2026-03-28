import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { and, desc, eq, isNull, lt, or } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { hash } from '@node-rs/argon2'
import { db } from '../db/index.js'
import { auditLogs, conversations, refreshTokens, sessions, userStatusHistory, users } from '../db/schema.js'
import { normalizeEmail, isValidId, sanitizeName, anonymizeIpAddress } from '../lib/utils.js'
import { requireAdmin, requireSuperAdmin, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { passwordSchema } from '../lib/passwordPolicy.js'
import { addUserToCache, updateUserCache } from '../state.js'
import { forceLogout, emitToAdmins } from '../socket/index.js'
import { logger } from '../lib/logger.js'
import { getPaginationConfig } from '../lib/config.js'
import { pickBestAdmin } from '../lib/assignmentEngine.js'

const createAdminSchema = z.object({
  email: z.string().email().max(255),
  password: passwordSchema,
  name: z.string().min(2).max(100).transform(s => sanitizeName(s))
}).strict()

function getListAdminsSchema() {
  const pagination = getPaginationConfig()
  return z.object({
    limit: z.coerce.number().int().min(1).max(pagination.admins.max).default(pagination.admins.default),
    before: z.string().optional()
  }).strict()
}


export async function adminAdminRoutes(fastify: FastifyInstance) {
  fastify.get('/admins', { preHandler: requireAdmin }, async (request, reply) => {
    const query = getListAdminsSchema().safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    let beforeCreatedAt: Date | undefined
    if (query.data.before) {
      if (!isValidId(query.data.before)) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid before cursor')
      }
      const beforeMs = decodeTime(query.data.before)
      beforeCreatedAt = new Date(beforeMs)
    }

    const statusFilter = or(eq(users.status, 'APPROVED'), eq(users.status, 'SUSPENDED'))
    const cols = {
      id: true, email: true, name: true, role: true,
      status: true, createdAt: true, lastSeenAt: true, subsidiaryIds: true
    } as const

    const adminWhere = beforeCreatedAt
      ? and(statusFilter, eq(users.role, 'ADMIN'), lt(users.createdAt, beforeCreatedAt))
      : and(statusFilter, eq(users.role, 'ADMIN'))

    const superAdminWhere = beforeCreatedAt
      ? and(statusFilter, eq(users.role, 'SUPER_ADMIN'), lt(users.createdAt, beforeCreatedAt))
      : and(statusFilter, eq(users.role, 'SUPER_ADMIN'))

    const [adminRows, superAdminRows] = await Promise.all([
      db.query.users.findMany({
        where: adminWhere,
        orderBy: [desc(users.createdAt)],
        limit: query.data.limit + 1,
        columns: cols
      }),
      db.query.users.findMany({
        where: superAdminWhere,
        orderBy: [desc(users.createdAt)],
        limit: query.data.limit + 1,
        columns: cols
      }),
    ])

    const hasMoreAdmins = adminRows.length > query.data.limit
    const hasMoreSuperAdmins = superAdminRows.length > query.data.limit

    const admins = hasMoreAdmins ? adminRows.slice(0, query.data.limit) : adminRows
    const superAdmins = hasMoreSuperAdmins ? superAdminRows.slice(0, query.data.limit) : superAdminRows

    return sendOk(reply, { admins, superAdmins, hasMoreAdmins, hasMoreSuperAdmins })
  })

  fastify.post('/admins', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const body = createAdminSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const email = normalizeEmail(body.data.email)
    const existing = await db.query.users.findFirst({
      where: eq(users.email, email),
      columns: { id: true }
    })

    if (existing) {
      return sendError(reply, 409, 'CONFLICT', 'Email already exists')
    }

    const userId = ulid()
    const passwordHash = await hash(body.data.password)
    const now = new Date()

    try {
      await db.transaction(async (tx) => {
        await tx.insert(users).values({
          id: userId,
          email,
          passwordHash,
          name: body.data.name,
          phone: null,
          role: 'ADMIN',
          status: 'APPROVED',
          mediaPermission: true,
          emailNotifyOnMessage: true,
          rejectionReason: null,
          createdAt: now,
          updatedAt: now,
          lastSeenAt: null
        })

        await tx.insert(userStatusHistory).values({
          id: ulid(),
          userId,
          previousStatus: 'PENDING',
          newStatus: 'APPROVED',
          changedBy: user.id,
          reason: 'admin_create'
        })

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'admin.create',
          entityType: 'user',
          entityId: userId,
          details: JSON.stringify({ role: 'ADMIN' })
        })
      })
    } catch (error) {
      logger.error({ email, error }, 'Admin creation failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to create admin')
    }

    addUserToCache(userId, {
      role: 'ADMIN',
      status: 'APPROVED',
      name: body.data.name,
      mediaPermission: true,
      emailNotifyOnMessage: true
    })

    reply.code(201)
    return sendOk(reply, {
      admin: {
        id: userId,
        email,
        name: body.data.name,
        role: 'ADMIN',
        status: 'APPROVED'
      }
    })
  })

  fastify.patch('/admins/:userId/suspend', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const { userId } = request.params as { userId: string }
    if (!isValidId(userId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    if (userId === actor.id) return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot suspend yourself')

    const target = await db.query.users.findFirst({ where: eq(users.id, userId), columns: { id: true, role: true, status: true, name: true } })
    if (!target) return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    if (!['ADMIN', 'SUPER_ADMIN'].includes(target.role)) return sendError(reply, 400, 'VALIDATION_ERROR', 'User is not an admin')
    if (target.status === 'SUSPENDED') return sendError(reply, 409, 'CONFLICT', 'Admin is already suspended')

    // FIX #4: Find conversations assigned to this admin BEFORE suspending so we can reassign them
    const orphanedConvs = await db.query.conversations.findMany({
      where: and(
        eq(conversations.assignedAdminId, userId),
        isNull(conversations.archivedAt),
        isNull(conversations.deletedAt)
      ),
      columns: { id: true, subsidiaryId: true, userId: true }
    })

    const now = new Date()
    try {
      await db.transaction(async (tx) => {
        // SECURITY FIX (High): Clear subsidiaryIds on suspend so that on re-activation
        // a super admin must explicitly re-configure routing — prevents stale routing
        // assignments from silently persisting through a suspension/reactivation cycle.
        await tx.update(users).set({ status: 'SUSPENDED', subsidiaryIds: null, updatedAt: now }).where(eq(users.id, userId))
        await tx.insert(userStatusHistory).values({ id: ulid(), userId, previousStatus: target.status, newStatus: 'SUSPENDED', changedBy: actor.id, reason: 'admin_suspend' })
        await tx.insert(auditLogs).values({ id: ulid(), userId: actor.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'), action: 'admin.suspend', entityType: 'user', entityId: userId, details: JSON.stringify({ name: target.name, role: target.role, subsidiaryIdsCleared: true }) })
        await tx.update(sessions).set({ revokedAt: now }).where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        await tx.update(refreshTokens).set({ revokedAt: now }).where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)))
        // Unassign all active conversations from the suspended admin atomically
        if (orphanedConvs.length > 0) {
          await tx.update(conversations)
            .set({ assignedAdminId: null, updatedAt: now })
            .where(and(
              eq(conversations.assignedAdminId, userId),
              isNull(conversations.archivedAt),
              isNull(conversations.deletedAt)
            ))
        }
      })
    } catch (error) {
      logger.error({ userId, error }, 'Admin suspend failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to suspend admin')
    }

    updateUserCache(userId, { status: 'SUSPENDED' })
    forceLogout(userId, 'Account suspended')

    // Reassign orphaned conversations sequentially after the main transaction commits.
    // Severless FIX: Ensure this remains awaited so PaaS containers don't freeze mid-execution.
    if (orphanedConvs.length > 0) {
      logger.info({ suspendedAdmin: userId, orphanCount: orphanedConvs.length }, 'Reassigning orphaned conversations after admin suspend')
      // HIGH FIX: Track failures and notify super admins so no conversation is silently lost.
      const failedConvIds: string[] = []
      for (const conv of orphanedConvs) {
        try {
          const newAdminId = await pickBestAdmin(conv.subsidiaryId)
          if (newAdminId) {
            await db.update(conversations)
              .set({ assignedAdminId: newAdminId, updatedAt: new Date() })
              .where(eq(conversations.id, conv.id))
            emitToAdmins('conversation:assigned', {
              conversationId: conv.id,
              assignedAdminId: newAdminId,
              oldAdminId: userId,
              reason: 'admin_suspended'
            })
          } else {
            emitToAdmins('conversation:unassigned', {
              conversationId: conv.id,
              oldAdminId: userId,
              reason: 'admin_suspended'
            })
          }
        } catch (err) {
          logger.warn({ convId: conv.id, err }, 'Failed to reassign conversation after admin suspend')
          failedConvIds.push(conv.id)
        }
      }
      // Notify super admins of any reassignment failures so they can manually review
      if (failedConvIds.length > 0) {
        logger.error({ suspendedAdmin: userId, failedConvIds }, 'Some conversations could not be reassigned after admin suspend — manual review required')
        emitToAdmins('admin:reassignment_failures', {
          suspendedAdminId: userId,
          failedConversationIds: failedConvIds,
          totalOrphaned: orphanedConvs.length,
          message: 'Some conversations could not be auto-reassigned. Please assign them manually.'
        })
      }
    }

    return sendOk(reply, { message: 'Admin suspended', orphanedConversations: orphanedConvs.length })
  })

  fastify.patch('/admins/:userId/reactivate', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const { userId } = request.params as { userId: string }
    if (!isValidId(userId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')

    const target = await db.query.users.findFirst({ where: eq(users.id, userId), columns: { id: true, role: true, status: true, name: true } })
    if (!target) return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    if (!['ADMIN', 'SUPER_ADMIN'].includes(target.role)) return sendError(reply, 400, 'VALIDATION_ERROR', 'User is not an admin')
    if (target.status !== 'SUSPENDED') return sendError(reply, 409, 'CONFLICT', 'Admin is not suspended')

    const now = new Date()
    try {
      await db.transaction(async (tx) => {
        await tx.update(users).set({ status: 'APPROVED', updatedAt: now }).where(eq(users.id, userId))
        await tx.insert(userStatusHistory).values({ id: ulid(), userId, previousStatus: 'SUSPENDED', newStatus: 'APPROVED', changedBy: actor.id, reason: 'admin_reactivate' })
        await tx.insert(auditLogs).values({ id: ulid(), userId: actor.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'), action: 'admin.reactivate', entityType: 'user', entityId: userId, details: JSON.stringify({ name: target.name, role: target.role }) })
      })
    } catch (error) {
      logger.error({ userId, error }, 'Admin reactivate failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to reactivate admin')
    }

    updateUserCache(userId, { status: 'APPROVED' })
    return sendOk(reply, { message: 'Admin reactivated' })
  })

  // PATCH /admin/admins/:userId/role - Change admin role (SUPER_ADMIN only)
  // SECURITY FIX (High): Removed SUPER_ADMIN from enum — promotion to SUPER_ADMIN
  // is intentionally blocked here to prevent silent privilege escalation via a
  // compromised super admin account. Use a dedicated out-of-band process to grant
  // SUPER_ADMIN (direct DB seed or a separate hardened endpoint with extra guards).
  const updateRoleSchema = z.object({
    role: z.enum(['ADMIN', 'USER'])
  }).strict()

  fastify.patch('/admins/:userId/role', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const { userId } = request.params as { userId: string }
    if (!isValidId(userId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')
    if (userId === actor.id) return sendError(reply, 400, 'VALIDATION_ERROR', 'Cannot change your own role')

    const body = updateRoleSchema.safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)

    const target = await db.query.users.findFirst({ where: eq(users.id, userId), columns: { id: true, role: true, status: true, name: true } })
    if (!target) return sendError(reply, 404, 'NOT_FOUND', 'User not found')

    if (target.role === 'SUPER_ADMIN') return sendError(reply, 403, 'FORBIDDEN', 'Cannot change role of another super admin')
    if (target.id === actor.id) return sendError(reply, 403, 'FORBIDDEN', 'Cannot change your own role')

    const now = new Date()
    const previousRole = target.role
    const isDemotingToUser = previousRole === 'ADMIN' && body.data.role === 'USER'

    // FIX #3: Find orphaned conversations before the transaction when demoting to USER
    let orphanedConvs: Array<{ id: string; subsidiaryId: string | null; userId: string }> = []
    if (isDemotingToUser) {
      orphanedConvs = await db.query.conversations.findMany({
        where: and(
          eq(conversations.assignedAdminId, userId),
          isNull(conversations.archivedAt),
          isNull(conversations.deletedAt)
        ),
        columns: { id: true, subsidiaryId: true, userId: true }
      })
    }

    try {
      await db.transaction(async (tx) => {
        await tx.update(users).set({ role: body.data.role, updatedAt: now }).where(eq(users.id, userId))
        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: actor.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'admin.role_change',
          entityType: 'user',
          entityId: userId,
          details: JSON.stringify({ name: target.name, previousRole, newRole: body.data.role })
        })

        if (isDemotingToUser) {
          await tx.update(sessions).set({ revokedAt: now }).where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
          await tx.update(refreshTokens).set({ revokedAt: now }).where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)))
          // FIX #3: Unassign all active conversations from the demoted admin
          if (orphanedConvs.length > 0) {
            await tx.update(conversations)
              .set({ assignedAdminId: null, updatedAt: now })
              .where(and(
                eq(conversations.assignedAdminId, userId),
                isNull(conversations.archivedAt),
                isNull(conversations.deletedAt)
              ))
          }
        }
      })
    } catch (error) {
      logger.error({ userId, error }, 'Admin role change failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to change admin role')
    }

    updateUserCache(userId, { role: body.data.role })

    if (isDemotingToUser) {
      forceLogout(userId, 'Role changed to regular user')

      if (orphanedConvs.length > 0) {
        logger.info({ demotedAdmin: userId, orphanCount: orphanedConvs.length }, 'Reassigning orphaned conversations after role demotion')
        // HIGH FIX: Track failures and notify super admins
        const demotionFailedIds: string[] = []
        for (const conv of orphanedConvs) {
          try {
            const newAdminId = await pickBestAdmin(conv.subsidiaryId)
            if (newAdminId) {
              await db.update(conversations)
                .set({ assignedAdminId: newAdminId, updatedAt: new Date() })
                .where(eq(conversations.id, conv.id))
              emitToAdmins('conversation:assigned', {
                conversationId: conv.id,
                assignedAdminId: newAdminId,
                oldAdminId: userId,
                reason: 'admin_demoted'
              })
            } else {
              emitToAdmins('conversation:unassigned', {
                conversationId: conv.id,
                oldAdminId: userId,
                reason: 'admin_demoted'
              })
            }
          } catch (err) {
            logger.warn({ convId: conv.id, err }, 'Failed to reassign conversation after role demotion')
            demotionFailedIds.push(conv.id)
          }
        }
        if (demotionFailedIds.length > 0) {
          logger.error({ demotedAdmin: userId, demotionFailedIds }, 'Some conversations could not be reassigned after role demotion — manual review required')
          emitToAdmins('admin:reassignment_failures', {
            suspendedAdminId: userId,
            failedConversationIds: demotionFailedIds,
            totalOrphaned: orphanedConvs.length,
            message: 'Some conversations could not be auto-reassigned after role demotion. Please assign them manually.'
          })
        }
      }
    }

    return sendOk(reply, { message: `Role changed from ${previousRole} to ${body.data.role}` })
  })

  // PATCH /admin/admins/:userId/subsidiaries
  fastify.patch('/admins/:userId/subsidiaries', { preHandler: requireSuperAdmin }, async (request, reply) => {
    const actor = requireUser(request, reply)
    if (!actor) return

    const { userId } = request.params as { userId: string }
    if (!isValidId(userId)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid user ID')

    const body = z.object({
      subsidiaryIds: z.array(z.string()).max(50),
    }).safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input')

    const target = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: { id: true, name: true, role: true, status: true, subsidiaryIds: true },
    })
    if (!target || (target.role !== 'ADMIN' && target.role !== 'SUPER_ADMIN')) {
      return sendError(reply, 404, 'NOT_FOUND', 'Admin not found')
    }

    // FIX #20: Capture previous subsidiaryIds for full audit trail
    let previousSubsidiaryIds: string[] = []
    if (target.subsidiaryIds) {
      try { previousSubsidiaryIds = JSON.parse(target.subsidiaryIds) } catch { /* ignore */ }
    }

    const raw = body.data.subsidiaryIds.length > 0 ? JSON.stringify(body.data.subsidiaryIds) : null

    try {
      await db.transaction(async (tx) => {
        await tx.update(users)
          .set({ subsidiaryIds: raw, updatedAt: new Date() })
          .where(eq(users.id, userId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: actor.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'admin.subsidiaries_update',
          entityType: 'user',
          entityId: userId,
          details: JSON.stringify({
            previousSubsidiaryIds,
            subsidiaryIds: body.data.subsidiaryIds
          }),
        })
      })
    } catch (error) {
      logger.error({ actorId: actor.id, targetId: userId, error }, 'Subsidiaries update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update subsidiaries')
    }

    updateUserCache(userId, { subsidiaryIds: raw })

    logger.info({ actor: actor.id, target: userId, subsidiaryIds: body.data.subsidiaryIds }, 'Admin subsidiaries updated')
    return sendOk(reply, { success: true, subsidiaryIds: body.data.subsidiaryIds })
  })

}
