/**
 * User profile routes for the authenticated user
 * Handles: profile updates, media listing, etc.
 */
import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { eq, and, desc, lt } from 'drizzle-orm'
import { ulid } from 'ulid'
import { db } from '../db/index.js'
import { users, auditLogs, media, messages } from '../db/schema.js'
import { requireApprovedUser, requireAuthenticatedUser, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { normalizeEmail, sanitizeName, isValidId, anonymizeIpAddress } from '../lib/utils.js'
import { updateUserCache } from '../state.js'
import { emitToUser } from '../socket/index.js'
import { deleteFromR2 } from '../services/storage.js'
import { logger } from '../lib/logger.js'

const updateProfileSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().max(255).optional(),
  phone: z.string().max(50).optional().nullable(),
})

export async function userRoutes(fastify: FastifyInstance) {
  // GET /users/me - Get current user profile (available to any authenticated user, including PENDING)
  fastify.get('/me', { preHandler: requireAuthenticatedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const userRecord = await db.query.users.findFirst({
      where: eq(users.id, user.id),
      columns: {
        id: true,
        email: true,
        name: true,
        phone: true,
        role: true,
        status: true,
        mediaPermission: true,
        emailNotifyOnMessage: true,
        createdAt: true,
        updatedAt: true,
        lastSeenAt: true,
      }
    })

    if (!userRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    return sendOk(reply, { user: userRecord })
  })

  // PATCH /users/me - Update current user profile
  fastify.patch('/me', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const body = updateProfileSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    // Fetch current user data to compare
    const currentUser = await db.query.users.findFirst({
      where: eq(users.id, user.id),
      columns: { name: true, email: true, phone: true }
    })

    if (!currentUser) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    const updates: { name?: string; email?: string; phone?: string | null; updatedAt: Date } = {
      updatedAt: new Date()
    }
    const updateDetails: Record<string, unknown> = {}

    // Handle name update
    if (body.data.name !== undefined && body.data.name !== currentUser.name) {
      updates.name = sanitizeName(body.data.name)
      updateDetails.name = { from: currentUser.name, to: updates.name }
    }

    // Handle email update
    if (body.data.email !== undefined) {
      const normalizedEmail = normalizeEmail(body.data.email)
      if (normalizedEmail !== currentUser.email) {
        // Check if email is already taken
        const existing = await db.query.users.findFirst({
          where: eq(users.email, normalizedEmail),
          columns: { id: true }
        })
        if (existing && existing.id !== user.id) {
          return sendError(reply, 409, 'CONFLICT', 'Email already in use')
        }
        updates.email = normalizedEmail
        updateDetails.email = { from: currentUser.email, to: normalizedEmail }
      }
    }

    // Handle phone update
    if (body.data.phone !== undefined) {
      if (body.data.phone === null || body.data.phone === '') {
        // Explicit clear
        updates.phone = null
        updateDetails.phone = { from: currentUser.phone, to: null }
      } else {
        // Strip everything except digits, +, -, spaces, and parentheses
        const sanitizedPhone = body.data.phone.replace(/[^\d+\-\s().]/g, '').trim()
        // Basic international phone validation: optional leading +, then digits/separators, 7–20 chars total
        const phoneValid = /^\+?[\d\s\-().]{7,20}$/.test(sanitizedPhone)
        if (!phoneValid) {
          return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid phone number format')
        }
        if (sanitizedPhone !== currentUser.phone) {
          updates.phone = sanitizedPhone
          updateDetails.phone = { from: currentUser.phone, to: sanitizedPhone }
        }
      }
    }

    // If no changes, return early
    if (Object.keys(updateDetails).length === 0) {
      return sendOk(reply, { message: 'No changes made' })
    }

    try {
      await db.transaction(async (tx) => {
        await tx.update(users)
          .set(updates)
          .where(eq(users.id, user.id))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.profile_update',
          entityType: 'user',
          entityId: user.id,
          details: JSON.stringify(updateDetails)
        })
      })

      // Update cache — propagates to other pods via clusterBus.
      if (updates.name) updateUserCache(user.id, { name: updates.name })

      // M-5 FIX: Isolate socket emit in its own try-catch.
      // A Redis/socket adapter failure must not return 500 after a successful DB write.
      const socketPayload: Record<string, unknown> = { id: user.id }
      if (updates.name) socketPayload.name = updates.name
      if (updates.email) socketPayload.email = updates.email
      if (updates.phone !== undefined) socketPayload.phone = updates.phone
      try {
        emitToUser(user.id, 'user:updated', socketPayload)
      } catch (emitErr) {
        logger.warn({ userId: user.id, error: emitErr }, 'user:updated socket emit failed — non-fatal')
      }

      return sendOk(reply, {
        message: 'Profile updated successfully',
        updates: Object.keys(updateDetails)
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Profile update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update profile')
    }
  })

  // GET /users/me/media - Get current user's media files
  fastify.get('/me/media', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const query = request.query as { status?: string; limit?: string; before?: string }
    const limit = Math.min(parseInt(query.limit || '20', 10), 100)
    const status = query.status || 'CONFIRMED'

    const conditions: (ReturnType<typeof eq> | ReturnType<typeof and> | ReturnType<typeof lt>)[] = [
      eq(media.uploadedBy, user.id),
      eq(media.status, status as 'PENDING' | 'CONFIRMED' | 'FAILED')
    ]

    // Keyset pagination: find the cursor item's uploadedAt, then fetch all records
    // uploaded strictly before it. Using lt(uploadedAt) matches the desc ordering.
    if (query.before && isValidId(query.before)) {
      const cursorItem = await db.query.media.findFirst({
        where: and(eq(media.id, query.before), eq(media.uploadedBy, user.id)),
        columns: { uploadedAt: true },
      })
      if (cursorItem) {
        conditions.push(lt(media.uploadedAt, cursorItem.uploadedAt))
      }
    }

    const mediaRecords = await db.query.media.findMany({
      where: and(...conditions),
      orderBy: [desc(media.uploadedAt)],
      limit: limit + 1,
      columns: {
        id: true,
        type: true,
        mimeType: true,
        size: true,
        filename: true,
        status: true,
        uploadedAt: true,
        confirmedAt: true,
      }
    })

    const hasMore = mediaRecords.length > limit
    const items = hasMore ? mediaRecords.slice(0, -1) : mediaRecords

    return sendOk(reply, {
      media: items,
      hasMore,
      nextCursor: hasMore ? items[items.length - 1]?.id : undefined
    })
  })

  // DELETE /users/me/media/:mediaId - Delete user's own media
  fastify.delete('/me/media/:mediaId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { mediaId } = request.params as { mediaId: string }

    if (!isValidId(mediaId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
    }

    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, mediaId),
      columns: { 
        id: true, 
        uploadedBy: true, 
        r2Key: true, 
        type: true,
        filename: true,
        status: true 
      }
    })

    if (!mediaRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'Media not found')
    }

    if (mediaRecord.uploadedBy !== user.id) {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot delete media you did not upload')
    }

    // Check if attached to any message via forward FK
    const attached = await db.select({ id: messages.id }).from(messages).where(eq(messages.mediaId, mediaId)).limit(1)
    if (attached.length > 0) {
      return sendError(reply, 409, 'CONFLICT', 'Cannot delete media attached to a message')
    }

    try {
      await deleteFromR2(mediaRecord.r2Key)
    } catch (error) {
      logger.warn({ mediaId, r2Key: mediaRecord.r2Key, error }, 'R2 delete failed, continuing with DB delete')
    }

    try {
      await db.transaction(async (tx) => {
        await tx.delete(media).where(eq(media.id, mediaId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.media_delete',
          entityType: 'media',
          entityId: mediaId,
          details: JSON.stringify({ type: mediaRecord.type, filename: mediaRecord.filename })
        })
      })

      return sendOk(reply, { deleted: true })
    } catch (error) {
      logger.error({ mediaId, error }, 'Media delete failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to delete media')
    }
  })
}
