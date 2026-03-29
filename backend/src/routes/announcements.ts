import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { desc, eq, and, isNull, gt, lt, sql, or, inArray, asc } from 'drizzle-orm'
import { ulid, decodeTime } from 'ulid'
import { db } from '../db/index.js'
import { announcements, announcementVotes, announcementReactions, announcementComments, auditLogs, media, users } from '../db/schema.js'
import { requireAdmin, requireApprovedUser, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { isAdmin } from '../lib/permissions.js'
import { emitToAdmins, emitToUsers } from '../socket/index.js'
import { sanitizeText, escapeHtml, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { serverState, getUserFromCache } from '../state.js'
import { createRateLimiters } from '../middleware/rateLimit.js'
import { sendPushToUser } from '../lib/webPush.js'

const reactionSchema = z.object({
  // NFC-normalise so encoding-equivalent emoji always map to the same DB value.
  emoji: z.string().min(1).max(10)
    .transform(s => s.normalize('NFC'))
    .pipe(z.string().regex(/^\p{Emoji}{1,10}$/u, 'Must be valid emoji')),
})

const createAnnouncementSchema = z.object({
  title: z.string().min(1).max(200).transform(s => escapeHtml(s.trim())),
  content: z.string().min(1).max(10000).transform(s => sanitizeText(s)),
  type: z.enum(['INFO', 'WARNING', 'IMPORTANT']).default('INFO'),
  template: z.enum(['DEFAULT', 'BANNER', 'CARD', 'MINIMAL']).default('DEFAULT'),
  mediaId: z.string().optional(),
  targetRoles: z.array(z.enum(['USER', 'ADMIN', 'SUPER_ADMIN'])).max(3).optional(),
  expiresAt: z.string().datetime().optional(),
  isPublic: z.boolean().optional().default(false),
})

const updateAnnouncementSchema = z.object({
  title: z.string().min(1).max(200).transform(s => escapeHtml(s.trim())).optional(),
  content: z.string().min(1).max(10000).transform(s => sanitizeText(s)).optional(),
  type: z.enum(['INFO', 'WARNING', 'IMPORTANT']).optional(),
  template: z.enum(['DEFAULT', 'BANNER', 'CARD', 'MINIMAL']).optional(),
  mediaId: z.string().nullable().optional(),
  targetRoles: z.array(z.enum(['USER', 'ADMIN', 'SUPER_ADMIN'])).nullable().optional(),
  expiresAt: z.string().datetime().nullable().optional(),
  isActive: z.boolean().optional(),
  isPublic: z.boolean().optional(),
})

const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(20),
  before: z.string().optional(),
  includeInactive: z.coerce.boolean().optional(),
})

const voteSchema = z.object({
  vote: z.enum(['UP', 'DOWN']),
})

type RoleTarget = 'USER' | 'ADMIN' | 'SUPER_ADMIN'

function parseTargetRoles(rawTargetRoles: string | null): RoleTarget[] | null {
  if (!rawTargetRoles) {
    return null
  }

  try {
    const parsed = JSON.parse(rawTargetRoles)
    if (!Array.isArray(parsed)) {
      return null
    }

    const roles = parsed.filter((role): role is RoleTarget => (
      role === 'USER' || role === 'ADMIN' || role === 'SUPER_ADMIN'
    ))

    return roles.length > 0 ? roles : null
  } catch {
    return null
  }
}

function canUserAccessAnnouncement(
  userRole: RoleTarget,
  announcement: { isActive: boolean; expiresAt: Date | null; targetRoles: string | null },
  now: Date
): boolean {
  if (!announcement.isActive) {
    return false
  }

  if (announcement.expiresAt && announcement.expiresAt <= now) {
    return false
  }

  const targetRoles = parseTargetRoles(announcement.targetRoles)
  if (!targetRoles) {
    return true
  }

  return targetRoles.includes(userRole)
}

async function validateAnnouncementMediaId(mediaId: string): Promise<boolean> {
  const mediaRecord = await db.query.media.findFirst({
    where: eq(media.id, mediaId),
    columns: { id: true, status: true }
  })
  return !!mediaRecord && mediaRecord.status === 'CONFIRMED'
}

export async function announcementRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  // GET /announcements/public — unauthenticated, only isPublic=true active announcements
  // MEDIUM FIX: Add rate limiting to public endpoint (60 requests per minute per IP)
  fastify.get('/public', { preHandler: rateLimiters.api }, async (_request, reply) => {
    const now = new Date()
    const result = await db.query.announcements.findMany({
      where: and(
        eq(announcements.isActive, true),
        eq(announcements.isPublic, true),
        or(
          isNull(announcements.expiresAt),
          gt(announcements.expiresAt, now)
        )
      ),
      orderBy: [desc(announcements.createdAt)],
      limit: 20,
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    const items = result.map(ann => ({
      id: ann.id,
      title: ann.title,
      content: ann.content,
      type: ann.type,
      template: ann.template,
      mediaAttachment: ann.mediaAttachment || null,
      author: { name: ann.author.name },
      upvoteCount: ann.upvoteCount,
      downvoteCount: ann.downvoteCount,
      createdAt: ann.createdAt,
    }))

    return sendOk(reply, { announcements: items })
  })
  fastify.get('/', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const query = listSchema.safeParse(request.query)
    if (!query.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query', query.error.issues)
    }

    const userIsAdmin = isAdmin(user)
    const now = new Date()

    const conditions = []

    if (!query.data.includeInactive || !userIsAdmin) {
      conditions.push(eq(announcements.isActive, true))
      conditions.push(or(
        isNull(announcements.expiresAt),
        gt(announcements.expiresAt, now)
      ))
    }

    if (query.data.before && isValidId(query.data.before)) {
      const beforeMs = decodeTime(query.data.before)
      conditions.push(lt(announcements.createdAt, new Date(beforeMs)))
    }

    // For non-admin users, filter targetRoles in SQL:
    // include rows where targetRoles is null (applies to all) OR where it contains the user's role.
    // This keeps the DB LIMIT accurate so hasMore is never misstated (#33).
    // SECURITY FIX: Validate role before using in SQL to prevent injection
    const validRoles = ['SUPER_ADMIN', 'ADMIN', 'USER'] as const
    const validatedRole = validRoles.find(r => r === user.role) || 'USER'
    
    if (!userIsAdmin || (userIsAdmin && !query.data.includeInactive)) {
      conditions.push(
        or(
          isNull(announcements.targetRoles),
          // SECURITY FIX: Use properly typed sql template with validated role
          sql`json_type(${announcements.targetRoles}) = 'array' AND EXISTS (
            SELECT 1 FROM json_each(${announcements.targetRoles}) WHERE value = ${validatedRole}
          )`
        )
      )
    }

    const result = await db.query.announcements.findMany({
      where: conditions.length > 0 ? and(...conditions.map(c => c)) : undefined,
      orderBy: [desc(announcements.createdAt)],
      limit: query.data.limit + 1,
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    const hasMore = result.length > query.data.limit
    const items = hasMore ? result.slice(0, -1) : result

    const annIds = items.map(a => a.id)
    const userVotes = annIds.length > 0
      ? await db.query.announcementVotes.findMany({
        where: and(
          eq(announcementVotes.userId, user.id),
          inArray(announcementVotes.announcementId, annIds)
        ),
        columns: { announcementId: true, vote: true }
      })
      : []

    const voteMap = new Map(userVotes.map(v => [v.announcementId, v.vote]))

    const enriched = items.map(ann => ({
      id: ann.id,
      title: ann.title,
      content: ann.content,
      type: ann.type,
      template: ann.template,
      targetRoles: parseTargetRoles(ann.targetRoles),
      mediaAttachment: ann.mediaAttachment || null,
      author: ann.author,
      upvoteCount: ann.upvoteCount,
      downvoteCount: ann.downvoteCount,
      userVote: voteMap.get(ann.id) || null,
      isActive: ann.isActive,
      ...(userIsAdmin ? { createdBy: ann.createdBy } : {}),
      createdAt: ann.createdAt,
      expiresAt: ann.expiresAt,
    }))

    return sendOk(reply, { announcements: enriched, hasMore })
  })

  fastify.post('/', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const body = createAnnouncementSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    if (body.data.mediaId) {
      if (!isValidId(body.data.mediaId)) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
      }

      const mediaIsValid = await validateAnnouncementMediaId(body.data.mediaId)
      if (!mediaIsValid) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid or unconfirmed media')
      }
    }

    if (user.role === 'ADMIN') {
      const requestedRoles = body.data.targetRoles || []
      const containsRestrictedTarget = requestedRoles.some(r => r !== 'USER')
      if (containsRestrictedTarget) {
        return sendError(reply, 403, 'FORBIDDEN', 'Admins can only target Users.')
      }
      // Default to ['USER'] if no roles specified — admins always target users only
      if (requestedRoles.length === 0) {
        body.data.targetRoles = ['USER']
      }
      // Admins cannot make announcements public
      if (body.data.isPublic) {
        return sendError(reply, 403, 'FORBIDDEN', 'Only Super Admins can publish public announcements.')
      }
    }

    const id = ulid()
    const now = new Date()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let announcement: any = null

    try {
      await db.transaction(async (tx) => {
        await tx.insert(announcements).values({
          id,
          title: body.data.title,
          content: body.data.content,
          type: body.data.type,
          template: body.data.template,
          mediaId: body.data.mediaId || null,
          targetRoles: body.data.targetRoles ? JSON.stringify(body.data.targetRoles) : null,
          createdBy: user.id,
          createdAt: now,
          expiresAt: body.data.expiresAt ? new Date(body.data.expiresAt) : null,
          isActive: true,
          isPublic: user.role === 'SUPER_ADMIN' ? (body.data.isPublic ?? false) : false,
        })

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.create',
          entityType: 'announcement',
          entityId: id,
          details: JSON.stringify({
            title: body.data.title,
            type: body.data.type,
          })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Announcement create failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to create announcement')
    }

    const raw = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    announcement = raw ? {
      ...raw,
      targetRoles: parseTargetRoles(raw.targetRoles),
      mediaAttachment: raw.mediaAttachment || null,
      userVote: null,
    } : null

    // C-1 FIX: Emit before sendOk — in serverless PaaS the process may halt the moment the
    // response is sent; emitting first guarantees connected clients receive the broadcast.
    try {
      const roles = parseTargetRoles(body.data.targetRoles ? JSON.stringify(body.data.targetRoles) : null)
      if (!roles) {
        emitToAdmins('announcement:new', { announcement })
        emitToUsers('announcement:new', { announcement })
      } else {
        if (roles.includes('ADMIN') || roles.includes('SUPER_ADMIN')) {
          emitToAdmins('announcement:new', { announcement })
        }
        if (roles.includes('USER')) {
          emitToUsers('announcement:new', { announcement })
        }
      }
    } catch (err) {
      logger.warn({ error: err instanceof Error ? err.message : String(err) }, 'Socket broadcast failed for announcement')
    }

    // Push notifications: fan-out to all offline users/admins in the target audience
    try {
      const roles = parseTargetRoles(body.data.targetRoles ? JSON.stringify(body.data.targetRoles) : null)
      const authorName = getUserFromCache(user.id)?.name ?? 'EvComms'
      const preview = announcement.content
        ? announcement.content.replace(/<[^>]+>/g, '').slice(0, 100)
        : announcement.title

      // Determine which DB roles to query
      const targetDbRoles: Array<'USER' | 'ADMIN' | 'SUPER_ADMIN'> = roles
        ? roles
        : ['USER', 'ADMIN', 'SUPER_ADMIN']

      const candidates = await db.query.users.findMany({
        where: and(
          eq(users.status, 'APPROVED'),
          inArray(users.role, targetDbRoles)
        ),
        columns: { id: true },
      })

      await Promise.allSettled(candidates.map(candidate => {
        if (!serverState.connectedUsers.has(candidate.id)) {
          return sendPushToUser(candidate.id, {
            title: `📢 ${announcement.title}`,
            body: preview,
            tag: `announcement:${announcement.id}`,
            data: { url: `/announcements/${announcement.id}` },
          })
        }
        return Promise.resolve()
      }))
    } catch (err) {
      logger.warn({ error: err instanceof Error ? err.message : String(err) }, 'Push fan-out failed for announcement')
    }

    return sendOk(reply, { announcement })
  })

  // GET /announcements/:id/public — unauthenticated, only isPublic=true active announcements
  fastify.get('/:id/public', { preHandler: rateLimiters.api }, async (request, reply) => {
    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')

    const now = new Date()
    const raw = await db.query.announcements.findFirst({
      where: and(
        eq(announcements.id, id),
        eq(announcements.isActive, true),
        eq(announcements.isPublic, true),
        or(
          isNull(announcements.expiresAt),
          gt(announcements.expiresAt, now)
        )
      ),
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    if (!raw) return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')

    // M-1 FIX: Removed spurious single-element Promise.all — semantically identical to a direct await.
    const reactionRows = await db.query.announcementReactions.findMany({
      where: eq(announcementReactions.announcementId, id),
      columns: { id: true, emoji: true, userId: true },
    })

    const announcement = {
      id: raw.id,
      title: raw.title,
      content: raw.content,
      type: raw.type,
      template: raw.template,
      targetRoles: parseTargetRoles(raw.targetRoles),
      mediaAttachment: raw.mediaAttachment || null,
      author: raw.author,
      upvoteCount: raw.upvoteCount,
      downvoteCount: raw.downvoteCount,
      userVote: null,
      isActive: raw.isActive,
      createdAt: raw.createdAt,
      expiresAt: raw.expiresAt,
      reactions: reactionRows,
      userReaction: null,
    }

    return sendOk(reply, { announcement })
  })

  fastify.get('/:id', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')

    const raw = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    if (!raw) return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')

    const userIsAdmin = isAdmin(user)
    const now = new Date()
    if (!userIsAdmin && !canUserAccessAnnouncement(user.role, raw, now)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    const [userVoteRow, reactionRows] = await Promise.all([
      db.query.announcementVotes.findFirst({
        where: and(eq(announcementVotes.userId, user.id), eq(announcementVotes.announcementId, id)),
        columns: { vote: true },
      }),
      db.query.announcementReactions.findMany({
        where: eq(announcementReactions.announcementId, id),
        columns: { id: true, emoji: true, userId: true },
      }),
    ])

    const userReaction = reactionRows.find((r) => r.userId === user.id) ?? null

    const announcement = {
      id: raw.id,
      title: raw.title,
      content: raw.content,
      type: raw.type,
      template: raw.template,
      targetRoles: parseTargetRoles(raw.targetRoles),
      mediaAttachment: raw.mediaAttachment || null,
      author: raw.author,
      upvoteCount: raw.upvoteCount,
      downvoteCount: raw.downvoteCount,
      userVote: userVoteRow?.vote ?? null,
      isActive: raw.isActive,
      ...(userIsAdmin ? { createdBy: raw.createdBy } : {}),
      createdAt: raw.createdAt,
      expiresAt: raw.expiresAt,
      reactions: reactionRows,
      userReaction,
    }

    return sendOk(reply, { announcement })
  })

  fastify.patch('/:id', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { id } = request.params as { id: string }

    if (!isValidId(id)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')
    }

    const body = updateAnnouncementSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const existing = await db.query.announcements.findFirst({
      where: eq(announcements.id, id)
    })
    if (!existing) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    if (user.role === 'ADMIN') {
      // ADMINs can only edit their own announcements
      if (existing.createdBy !== user.id) {
        return sendError(reply, 403, 'FORBIDDEN', 'You can only edit your own announcements.')
      }

      // ADMIN cannot edit announcements created by SUPER_ADMIN
      const creator = await db.query.users.findFirst({
        where: eq(users.id, existing.createdBy),
        columns: { role: true }
      })
      if (creator?.role === 'SUPER_ADMIN') {
        return sendError(reply, 403, 'FORBIDDEN', 'Cannot edit super admin announcements.')
      }

      // Must not edit an existing announcement that targets admins/super admins
      const existingRoles = parseTargetRoles(existing.targetRoles) || []
      const existingTargetsRestricted = existingRoles.some(r => r !== 'USER')
      if (existingTargetsRestricted) {
        return sendError(reply, 403, 'FORBIDDEN', 'You cannot edit an announcement that targets other admins.')
      }

      // Must not target admins/super admins in the new update
      if (body.data.targetRoles !== undefined) {
        const updateRoles = body.data.targetRoles || []
        const newTargetsRestricted = updateRoles.some(r => r !== 'USER')
        if (newTargetsRestricted) {
          return sendError(reply, 403, 'FORBIDDEN', 'Admins can only target Users.')
        }
        // Default empty targetRoles to ['USER'] for ADMIN updates
        if (updateRoles.length === 0) {
          body.data.targetRoles = ['USER']
        }
      }
      // Admins cannot set isPublic
      if (body.data.isPublic === true) {
        return sendError(reply, 403, 'FORBIDDEN', 'Only Super Admins can publish public announcements.')
      }
      // Admins cannot reactivate announcements (only SUPER_ADMIN can)
      if (body.data.isActive === true && !existing.isActive) {
        return sendError(reply, 403, 'FORBIDDEN', 'Only Super Admins can reactivate announcements.')
      }
    }

    const updates: Record<string, unknown> = {}
    if (body.data.title !== undefined) updates.title = body.data.title
    if (body.data.content !== undefined) updates.content = body.data.content
    if (body.data.type !== undefined) updates.type = body.data.type
    if (body.data.template !== undefined) updates.template = body.data.template
    if (body.data.mediaId !== undefined) {
      if (body.data.mediaId !== null) {
        if (!isValidId(body.data.mediaId)) {
          return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
        }

        const mediaIsValid = await validateAnnouncementMediaId(body.data.mediaId)
        if (!mediaIsValid) {
          return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid or unconfirmed media')
        }
      }

      updates.mediaId = body.data.mediaId
    }
    if (body.data.targetRoles !== undefined) {
      updates.targetRoles = body.data.targetRoles ? JSON.stringify(body.data.targetRoles) : null
    }
    if (body.data.expiresAt !== undefined) {
      updates.expiresAt = body.data.expiresAt ? new Date(body.data.expiresAt) : null
    }
    if (body.data.isActive !== undefined) {
      updates.isActive = body.data.isActive
    }
    if (body.data.isPublic !== undefined) {
      // Only SUPER_ADMIN can toggle isPublic
      if (user.role === 'SUPER_ADMIN') {
        updates.isPublic = body.data.isPublic
      } else {
        return sendError(reply, 403, 'FORBIDDEN', 'Only Super Admins can change public status.')
      }
    }

    if (Object.keys(updates).length > 0) {
      await db.transaction(async (tx) => {
        await tx.update(announcements).set(updates).where(eq(announcements.id, id))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.update',
          entityType: 'announcement',
          entityId: id,
          details: JSON.stringify({
            title: body.data.title ?? existing.title,
            changes: Object.keys(updates)
          })
        })
      })
    }

    const raw = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      with: {
        author: { columns: { id: true, name: true, role: true } },
        mediaAttachment: { columns: { id: true, type: true, cdnUrl: true, filename: true, size: true, mimeType: true } },
      }
    })

    const updated = raw ? {
      ...raw,
      targetRoles: parseTargetRoles(raw.targetRoles),
      mediaAttachment: raw.mediaAttachment || null,
      userVote: null,
    } : null

    // C-2 FIX: Emit before sendOk — prevents serverless SIGTERM race.
    try {
      emitToAdmins('announcement:updated', { announcement: updated })
      emitToUsers('announcement:updated', { announcement: updated })
    } catch { logger.debug('Socket not initialized, skipping announcement:updated broadcast') }

    return sendOk(reply, { announcement: updated })
  })

  // HIGH FIX: Add rate limiting to vote endpoint (10 votes per minute per user)
  fastify.post('/:id/vote', { preHandler: [requireApprovedUser, rateLimiters.vote] }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { id } = request.params as { id: string }

    if (!isValidId(id)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')
    }

    const body = voteSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id)
    })

    const now = new Date()
    const userIsAdmin = isAdmin(user)
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    try {
      const result = await db.transaction(async (tx) => {
        const existing = await tx.query.announcementVotes.findFirst({
          where: and(
            eq(announcementVotes.announcementId, id),
            eq(announcementVotes.userId, user.id),
          )
        })

        if (existing) {
          if (existing.vote === body.data.vote) {
            await tx.delete(announcementVotes).where(eq(announcementVotes.id, existing.id))

            // HIGH FIX: SQLite-compatible CASE syntax instead of MAX()
            if (body.data.vote === 'UP') {
              await tx.update(announcements)
                .set({ upvoteCount: sql`CASE WHEN upvote_count > 0 THEN upvote_count - 1 ELSE 0 END` })
                .where(eq(announcements.id, id))
            } else {
              await tx.update(announcements)
                .set({ downvoteCount: sql`CASE WHEN downvote_count > 0 THEN downvote_count - 1 ELSE 0 END` })
                .where(eq(announcements.id, id))
            }

            // HIGH FIX: Add audit log for vote removal
            await tx.insert(auditLogs).values({
              id: ulid(),
              userId: user.id,
              ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
              action: 'announcement.vote.removed',
              entityType: 'announcement',
              entityId: id,
              details: JSON.stringify({
                removedVote: existing.vote,
                announcementId: id
              })
            })

            return { vote: null }
          } else {
            await tx.update(announcementVotes)
              .set({ vote: body.data.vote, createdAt: new Date() })
              .where(eq(announcementVotes.id, existing.id))

            if (body.data.vote === 'UP') {
              await tx.update(announcements)
                .set({
                  upvoteCount: sql`upvote_count + 1`,
                  downvoteCount: sql`CASE WHEN downvote_count > 0 THEN downvote_count - 1 ELSE 0 END`,
                })
                .where(eq(announcements.id, id))
            } else {
              await tx.update(announcements)
                .set({
                  downvoteCount: sql`downvote_count + 1`,
                  upvoteCount: sql`CASE WHEN upvote_count > 0 THEN upvote_count - 1 ELSE 0 END`,
                })
                .where(eq(announcements.id, id))
            }

            // HIGH FIX: Add audit log for vote change
            await tx.insert(auditLogs).values({
              id: ulid(),
              userId: user.id,
              ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
              action: 'announcement.vote.changed',
              entityType: 'announcement',
              entityId: id,
              details: JSON.stringify({
                newVote: body.data.vote,
                previousVote: existing.vote,
                announcementId: id
              })
            })

            return { vote: body.data.vote }
          }
        }

        await tx.insert(announcementVotes).values({
          id: ulid(),
          announcementId: id,
          userId: user.id,
          vote: body.data.vote,
        })

        if (body.data.vote === 'UP') {
          await tx.update(announcements)
            .set({ upvoteCount: sql`upvote_count + 1` })
            .where(eq(announcements.id, id))
        } else {
          await tx.update(announcements)
            .set({ downvoteCount: sql`downvote_count + 1` })
            .where(eq(announcements.id, id))
        }

        // HIGH FIX: Add audit log for vote creation
        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.vote.cast',
          entityType: 'announcement',
          entityId: id,
          details: JSON.stringify({
            vote: body.data.vote,
            announcementId: id
          })
        })

        return { vote: body.data.vote }
      })

      // Fetch fresh counts and emit real-time update before returning
      let fresh: { upvoteCount: number; downvoteCount: number } | undefined
      try {
        fresh = await db.query.announcements.findFirst({
          where: eq(announcements.id, id),
          columns: { upvoteCount: true, downvoteCount: true }
        }) ?? undefined
      } catch (err) {
        logger.warn({ announcementId: id, error: err }, 'Failed to fetch fresh vote counts')
      }

      if (fresh != null) {
        const upvoteCount = fresh.upvoteCount
        const downvoteCount = fresh.downvoteCount
        emitToAdmins('announcement:vote:updated', { announcementId: id, upvoteCount, downvoteCount })
        emitToUsers('announcement:vote:updated', { announcementId: id, upvoteCount, downvoteCount })
      }

      return sendOk(reply, result)
    } catch (error) {
      logger.error({ userId: user.id, announcementId: id, error }, 'Vote failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to process vote')
    }
  })

  // HIGH FIX: Add rate limiting to vote deletion endpoint
  fastify.delete('/:id/vote', { preHandler: [requireApprovedUser, rateLimiters.vote] }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { id } = request.params as { id: string }

    if (!isValidId(id)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')
    }

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id)
    })

    const now = new Date()
    const userIsAdmin = isAdmin(user)
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    try {
      await db.transaction(async (tx) => {
        const existing = await tx.query.announcementVotes.findFirst({
          where: and(
            eq(announcementVotes.announcementId, id),
            eq(announcementVotes.userId, user.id),
          )
        })

        if (!existing) {
          return
        }

        await tx.delete(announcementVotes).where(eq(announcementVotes.id, existing.id))

        if (existing.vote === 'UP') {
          await tx.update(announcements)
            .set({ upvoteCount: sql`CASE WHEN upvote_count > 0 THEN upvote_count - 1 ELSE 0 END` })
            .where(eq(announcements.id, id))
        } else {
          await tx.update(announcements)
            .set({ downvoteCount: sql`CASE WHEN downvote_count > 0 THEN downvote_count - 1 ELSE 0 END` })
            .where(eq(announcements.id, id))
        }

        // SECURITY FIX: Add audit log for vote removal
        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.vote.removed',
          entityType: 'announcement_vote',
          entityId: existing.id,
          details: JSON.stringify({ announcementId: id, voteType: existing.vote })
        })
      })

      return sendOk(reply, { vote: null })
    } catch (error) {
      logger.error({ userId: user.id, announcementId: id, error }, 'Vote removal failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to remove vote')
    }
  })

  fastify.delete('/:id', { preHandler: requireAdmin }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) {
      return
    }

    const { id } = request.params as { id: string }

    if (!isValidId(id)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid announcement ID')
    }

    const existing = await db.query.announcements.findFirst({
      where: eq(announcements.id, id)
    })
    if (!existing) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    // ADMIN can only delete their own announcements
    if (user.role === 'ADMIN') {
      if (existing.createdBy !== user.id) {
        return sendError(reply, 403, 'FORBIDDEN', 'You can only delete your own announcements.')
      }
      // Must not delete an announcement that targets admins/super admins (consistent with PATCH)
      const existingRoles = parseTargetRoles(existing.targetRoles) || []
      const existingTargetsRestricted = existingRoles.some(r => r !== 'USER')
      if (existingTargetsRestricted) {
        return sendError(reply, 403, 'FORBIDDEN', 'You cannot delete an announcement that targets other admins.')
      }
    }

    await db.transaction(async (tx) => {
      await tx.update(announcements)
        .set({ isActive: false })
        .where(eq(announcements.id, id))

      await tx.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'announcement.delete',
        entityType: 'announcement',
        entityId: id,
        details: JSON.stringify({ title: existing.title })
      })
    })

    // C-3 FIX: Emit before sendOk — prevents serverless SIGTERM race.
    try {
      emitToAdmins('announcement:deleted', { announcementId: id })
      emitToUsers('announcement:deleted', { announcementId: id })
    } catch { /* non-fatal */ }

    return sendOk(reply, { message: 'Announcement removed' })
  })

  // ── Reactions ───────────────────────────────────────────────────────────────

  // POST /:id/reaction — add or replace the current user's emoji reaction
  fastify.post('/:id/reaction', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      columns: { id: true, isActive: true, targetRoles: true, expiresAt: true }
    })
    const userIsAdmin = isAdmin(user)
    const now = new Date()
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    const body = reactionSchema.safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid emoji')

    // Upsert: single INSERT OR REPLACE instead of DELETE + INSERT.
    // NOTE: the unique constraint must be on (announcementId, userId) only.
    // See migration 0003 — the original index incorrectly included emoji.
    const newId = ulid()
    try {
      await db.insert(announcementReactions).values({
        id: newId,
        announcementId: id,
        userId: user.id,
        emoji: body.data.emoji,
      }).onConflictDoUpdate({
        target: [announcementReactions.announcementId, announcementReactions.userId],
        set: { emoji: body.data.emoji, id: newId }
      })
    } catch (error) {
      logger.error({ userId: user.id, announcementId: id, error }, 'Announcement reaction upsert failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to save reaction')
    }

    // Audit log is best-effort — never fail the request over it
    try {
      await db.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'announcement.reaction.added',
        entityType: 'announcement_reaction',
        entityId: newId,
        details: JSON.stringify({ announcementId: id, emoji: body.data.emoji })
      })
    } catch (auditErr) {
      logger.warn({ error: auditErr, announcementId: id }, 'Failed to write reaction audit log')
    }

    const reaction = { id: newId, announcementId: id, userId: user.id, emoji: body.data.emoji }

    try {
      emitToAdmins('announcement:reaction:updated', { announcementId: id, userId: user.id, emoji: body.data.emoji })
      emitToUsers('announcement:reaction:updated', { announcementId: id, userId: user.id, emoji: body.data.emoji })
    } catch (err) {
      logger.warn({ error: err instanceof Error ? err.message : String(err), announcementId: id }, 'Socket broadcast failed for reaction update')
    }

    return sendOk(reply, { reaction })
  })

  // DELETE /:id/reaction — remove the current user's emoji reaction
  fastify.delete('/:id/reaction', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      columns: { id: true, isActive: true, targetRoles: true, expiresAt: true }
    })
    const userIsAdmin = isAdmin(user)
    const now = new Date()
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    const existing = await db.query.announcementReactions.findFirst({
      where: and(
        eq(announcementReactions.announcementId, id),
        eq(announcementReactions.userId, user.id)
      ),
      columns: { id: true, emoji: true }
    })

    if (!existing) {
      return sendError(reply, 404, 'NOT_FOUND', 'No reaction found')
    }

    await db.delete(announcementReactions).where(eq(announcementReactions.id, existing.id))

    await db.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
      action: 'announcement.reaction.removed',
      entityType: 'announcement_reaction',
      entityId: existing.id,
      details: JSON.stringify({ announcementId: id, emoji: existing.emoji })
    })

    try {
      emitToAdmins('announcement:reaction:removed', { announcementId: id, userId: user.id })
      emitToUsers('announcement:reaction:removed', { announcementId: id, userId: user.id })
    } catch (err) {
      logger.warn({ error: err instanceof Error ? err.message : String(err), announcementId: id }, 'Socket broadcast failed for reaction removal')
    }

    return sendOk(reply, { deleted: true })
  })

  // ── COMMENTS ──────────────────────────────────────────────────────────────

  // GET /:id/comments — paginated list of live comments (oldest-first)
  fastify.get('/:id/comments', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

    const query = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(30),
      before: z.string().optional(),
    }).safeParse(request.query)
    if (!query.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid query params')

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      columns: { id: true, isActive: true, targetRoles: true, expiresAt: true },
    })
    const userIsAdmin = isAdmin(user)
    const now = new Date()
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    const { limit, before } = query.data
    const conditions = [
      eq(announcementComments.announcementId, id),
      isNull(announcementComments.deletedAt),
      ...(before ? [lt(announcementComments.createdAt, new Date(Number(before)))] : []),
    ]

    const rows = await db.query.announcementComments.findMany({
      where: and(...conditions),
      orderBy: [asc(announcementComments.createdAt)],
      limit: limit + 1,
      with: { user: { columns: { id: true, name: true, role: true } } },
    })

    const hasMore = rows.length > limit
    const comments = rows.slice(0, limit).map((c) => ({
      id: c.id,
      announcementId: c.announcementId,
      content: c.content,
      createdAt: c.createdAt,
      user: c.user,
    }))

    return sendOk(reply, { comments, hasMore })
  })

  // POST /:id/comments — add a comment
  fastify.post('/:id/comments', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id } = request.params as { id: string }
    if (!isValidId(id)) return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')

    const ann = await db.query.announcements.findFirst({
      where: eq(announcements.id, id),
      columns: { id: true, isActive: true, targetRoles: true, expiresAt: true },
    })
    const userIsAdmin = isAdmin(user)
    const now = new Date()
    if (!ann || (!userIsAdmin && !canUserAccessAnnouncement(user.role, ann, now))) {
      return sendError(reply, 404, 'NOT_FOUND', 'Announcement not found')
    }

    const body = z.object({ content: z.string().min(1).max(2000) }).safeParse(request.body)
    if (!body.success) return sendError(reply, 400, 'VALIDATION_ERROR', 'Content required (max 2000 chars)')

    const commentId = ulid()
    const sanitized = sanitizeText(body.data.content)

    // H-1 FIX: Wrap INSERT + audit log in one transaction — a failure between the two
    // previously left an orphaned comment with no audit trail.
    try {
      await db.transaction(async (tx) => {
        await tx.insert(announcementComments).values({
          id: commentId,
          announcementId: id,
          userId: user.id,
          content: sanitized,
          createdAt: now,
        })

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.comment.added',
          entityType: 'announcement_comment',
          entityId: commentId,
          details: JSON.stringify({ announcementId: id }),
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, announcementId: id, error }, 'Comment insert failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to post comment')
    }

    const cachedUser = getUserFromCache(user.id)
    const comment = {
      id: commentId,
      announcementId: id,
      content: sanitized,
      createdAt: now,
      user: { id: user.id, name: cachedUser?.name ?? user.id, role: user.role },
    }

    try {
      emitToAdmins('announcement:comment:new', { announcementId: id, comment })
      emitToUsers('announcement:comment:new', { announcementId: id, comment })
    } catch (err) {
      logger.warn({ err, announcementId: id }, 'Socket broadcast failed for comment:new')
    }

    reply.code(201)
    return sendOk(reply, { comment })
  })

  // DELETE /:id/comments/:commentId — soft-delete a comment (owner or admin)
  fastify.delete('/:id/comments/:commentId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { id, commentId } = request.params as { id: string; commentId: string }
    if (!isValidId(id) || !isValidId(commentId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid ID')
    }

    const comment = await db.query.announcementComments.findFirst({
      where: and(
        eq(announcementComments.id, commentId),
        eq(announcementComments.announcementId, id),
        isNull(announcementComments.deletedAt),
      ),
      columns: { id: true, userId: true },
    })
    if (!comment) return sendError(reply, 404, 'NOT_FOUND', 'Comment not found')

    const userIsAdmin = isAdmin(user)
    if (comment.userId !== user.id && !userIsAdmin) {
      return sendError(reply, 403, 'FORBIDDEN', 'Not your comment')
    }

    // H-2 FIX: Wrap soft-delete + audit log in one transaction.
    try {
      await db.transaction(async (tx) => {
        await tx.update(announcementComments)
          .set({ deletedAt: new Date() })
          .where(eq(announcementComments.id, commentId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'announcement.comment.deleted',
          entityType: 'announcement_comment',
          entityId: commentId,
          details: JSON.stringify({ announcementId: id }),
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, commentId, error }, 'Comment delete failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to delete comment')
    }

    try {
      emitToAdmins('announcement:comment:deleted', { announcementId: id, commentId })
      emitToUsers('announcement:comment:deleted', { announcementId: id, commentId })
    } catch (err) {
      logger.warn({ err, announcementId: id }, 'Socket broadcast failed for comment:deleted')
    }

    return sendOk(reply, { deleted: true })
  })
}
