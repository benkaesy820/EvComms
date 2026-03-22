import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z } from 'zod'
import { sql } from 'drizzle-orm'
import crypto from 'crypto'
import { eq, and } from 'drizzle-orm'
import { ulid } from 'ulid'
import { LRUCache } from 'lru-cache'
import sharp from 'sharp'
import { db } from '../db/index.js'
import { media, auditLogs, messages, conversations } from '../db/schema.js'
import { requireApprovedUser, requireUser, sendError, sendOk } from '../middleware/auth.js'
import { canUploadMedia, isAdmin } from '../lib/permissions.js'
import { createRateLimiters } from '../middleware/rateLimit.js'
import { getConfig, isAllowedMimeType, getMaxFileSize, normalizeMimeType } from '../lib/config.js'
import { generateUploadUrl, getCdnUrl, deleteFromR2, uploadToR2, getSignedR2Url, deleteFromImageKit } from '../services/storage.js'
import { serverState } from '../state.js'
import { sanitizeFilename, isValidId, validateFileSignature, anonymizeIpAddress } from '../lib/utils.js'
import { env } from '../lib/env.js'
import { logger } from '../lib/logger.js'

// BOUNDED STREAM RATE LIMITER - uses config for sizes
function getStreamRateLimiter() {
  const cfg = getConfig().rateLimit.stream
  return new LRUCache<string, { count: number; resetAt: number }>({
    max: cfg?.maxEntries ?? 40000,
    maxSize: cfg?.maxSizeBytes ?? 2097152,
    sizeCalculation: () => 50,
    allowStale: false,
    updateAgeOnGet: false,
    dispose: (value, key) => {
      logger.debug({ key }, 'Stream rate limiter evicted')
    }
  })
}

const streamRateLimiters = getStreamRateLimiter()

function checkStreamRateLimit(userId: string): boolean {
  const config = getConfig().rateLimit.stream
  const windowMs = config?.windowMs ?? 60000
  const maxRequests = config?.maxRequests ?? 30
  const now = Date.now()
  
  const entry = streamRateLimiters.get(userId)

  if (!entry || entry.resetAt <= now) {
    streamRateLimiters.set(userId, { count: 1, resetAt: now + windowMs })
    return true
  }

  if (entry.count >= maxRequests) {
    return false
  }

  entry.count++
  streamRateLimiters.set(userId, entry)
  return true
}

export function stopStreamRateLimitCleanup(): void {
  // No-op - LRU auto-manages
}

export const uploadUrlSchema = z.object({
  type: z.enum(['IMAGE', 'DOCUMENT']),
  mimeType: z.string(),
  size: z.number().int().positive(),
  filename: z.string().min(1),
  hash: z.string().optional(),
  context: z.string().optional(),
})

const confirmSchema = z.object({
  mediaId: z.string().min(26).max(26).refine(isValidId, 'Invalid media ID format'),
  // ARCHITECTURE FIX: Include actual file metadata from ImageKit for validation
  actualSize: z.number().int().positive().optional(),
  actualMimeType: z.string().optional(),
  // The actual CDN URL returned by ImageKit upload — more accurate than pre-generated URL
  cdnUrl: z.string().url().optional(),
})

// Webhook payload schema for ImageKit
const imagekitWebhookSchema = z.object({
  type: z.enum(['upload']),
  file: z.object({
    fileId: z.string(),
    name: z.string(),
    size: z.number().int().positive(),
    filePath: z.string(),
    url: z.string(),
    fileType: z.enum(['image', 'non-image']),
    thumbnail: z.string().optional(),
    width: z.number().optional(),
    height: z.number().optional(),
  }),
  raw: z.record(z.unknown()).optional(),
})

async function canAccessMediaRecord(
  user: NonNullable<FastifyRequest['user']>,
  mediaRecord: { uploadedBy: string; id: string }
): Promise<boolean> {
  if (isAdmin(user) || mediaRecord.uploadedBy === user.id) {
    return true
  }

  // Check if this media is attached to a message in a conversation the user owns
  const row = await db.select({ userId: conversations.userId })
    .from(messages)
    .innerJoin(conversations, eq(messages.conversationId, conversations.id))
    .where(eq(messages.mediaId, mediaRecord.id))
    .limit(1)

  return row[0]?.userId === user.id
}

/**
 * ARCHITECTURE FIX: EXIF data stripping for privacy
 * Uses sharp to remove all metadata from images
 */
async function stripExifData(buffer: Buffer, mimeType: string): Promise<Buffer> {
  // Only process images
  if (!mimeType.startsWith('image/')) {
    return buffer
  }

  try {
    // ARCHITECTURE FIX: Use sharp to strip EXIF while keeping image quality
    const processed = await sharp(buffer)
      .rotate() // Auto-rotate based on EXIF orientation before stripping
      .withMetadata({}) // Strip all metadata (EXIF, ICC, IPTC, XMP)
      .toBuffer()
    
    logger.debug({ originalSize: buffer.length, processedSize: processed.length }, 'EXIF data stripped')
    return processed
  } catch (error) {
    logger.warn({ error, mimeType }, 'Failed to strip EXIF, using original')
    return buffer
  }
}

/**
 * ARCHITECTURE FIX: Validate file against declared metadata
 * Compares actual uploaded file with what was declared
 */
function validateUploadedFile(
  declared: { size: number; mimeType: string; type: string },
  actual: { size: number; mimeType: string },
  tolerance: number = 0.1 // 10% size tolerance
): { valid: boolean; reason?: string } {
  // Check size within tolerance (account for compression/exif stripping)
  const sizeDiff = Math.abs(actual.size - declared.size) / declared.size
  if (sizeDiff > tolerance && actual.size > declared.size * 1.5) {
    return { 
      valid: false, 
      reason: `Size mismatch: declared ${declared.size}, actual ${actual.size}` 
    }
  }

  // Check MIME type compatibility
  const declaredCategory = declared.type.toLowerCase()
  const actualCategory = actual.mimeType.split('/')[0] || ''
  
  const compatibleTypes: Record<string, string[]> = {
    'image': ['image'],
    'document': ['application', 'text', 'image'], // PDFs can be image/pdf
  }

  if (!compatibleTypes[declaredCategory]?.includes(actualCategory)) {
    return { 
      valid: false, 
      reason: `Type mismatch: declared ${declaredCategory}, actual ${actual.mimeType}` 
    }
  }

  return { valid: true }
}

export async function mediaRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  const uploadPreHandler = async (req: FastifyRequest, rep: FastifyReply) => {
    await requireApprovedUser(req, rep)
    if (rep.sent) return
    const u = req.user
    if (!u || u.role === 'ADMIN' || u.role === 'SUPER_ADMIN') return
    await rateLimiters.mediaUpload(req, rep)
  }

  // Standard upload endpoints...
  fastify.post('/upload-url', { preHandler: uploadPreHandler }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const config = getConfig()
    if (!config.features.mediaUpload) {
      return sendError(reply, 403, 'FORBIDDEN', 'Media uploads are disabled')
    }

    const body = uploadUrlSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const uploadContext = body.data.context || (request.headers['x-upload-context'] as string | undefined) || ''
    const isReportUpload = uploadContext === 'report'

    if (!isReportUpload && !canUploadMedia(user)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Media uploads not permitted')
    }

    if (config.limits.media.perDay) {
      const startOfDay = new Date()
      startOfDay.setUTCHours(0, 0, 0, 0)

      const countResult = await db.select({ count: sql<number>`count(*)` })
        .from(media)
        .where(
          and(
            eq(media.uploadedBy, user.id),
            sql`${media.uploadedAt} >= ${startOfDay}`
          )
        )

      const currentCount = countResult[0]?.count ?? 0
      if (currentCount >= config.limits.media.perDay) {
        return sendError(reply, 429, 'RATE_LIMITED', 'Daily media upload limit reached')
      }
    }

    const category = body.data.type.toLowerCase() as 'image' | 'document'
    const normalizedMime = normalizeMimeType(body.data.mimeType)

    if (!isAllowedMimeType(normalizedMime, category)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File type not allowed')
    }

    const maxSize = getMaxFileSize(category)
    if (body.data.size > maxSize) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File too large', {
        maxSize,
        actualSize: body.data.size
      })
    }

    try {
      const auth = await generateUploadUrl({
        type: body.data.type,
        mimeType: normalizedMime,
        size: body.data.size,
        filename: sanitizeFilename(body.data.filename)
      })

      await db.insert(media).values({
        id: auth.mediaId,
        uploadedBy: user.id,
        type: body.data.type,
        mimeType: normalizedMime,
        size: body.data.size,
        filename: sanitizeFilename(body.data.filename),
        r2Key: auth.r2Key,
        cdnUrl: body.data.type === 'DOCUMENT' ? null : getCdnUrl(auth.r2Key, body.data.type),
        hash: null,
        status: 'PENDING'
      })

      serverState.activeUploads.set(auth.mediaId, {
        userId: user.id,
        mediaId: auth.mediaId,
        type: body.data.type,
        startedAt: Date.now(),
        filename: body.data.filename,
        declaredSize: body.data.size,
        declaredMimeType: normalizedMime,
      })

      const config = getConfig()
      return sendOk(reply, {
        mediaId: auth.mediaId,
        uploadUrl: auth.uploadUrl,
        // Flat structure matches what the frontend checks:
        // authRes.provider, authRes.token, authRes.signature, authRes.expire, authRes.urlEndpoint
        provider: auth.provider,
        token: auth.token,
        expire: auth.expire,
        signature: auth.signature,
        urlEndpoint: auth.urlEndpoint,
        imagekitPublicKey: env.imagekitPublicKey ?? undefined,
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Upload URL generation failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to generate upload URL')
    }
  })

  // ARCHITECTURE FIX: Enhanced confirm endpoint with server-side validation
  fastify.post('/confirm', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const body = confirmSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, body.data.mediaId),
      columns: { 
        id: true, status: true, uploadedBy: true, type: true, 
        mimeType: true, cdnUrl: true, filename: true, size: true, r2Key: true 
      }
    })

    if (!mediaRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'Media not found')
    }

    if (mediaRecord.uploadedBy !== user.id && !isAdmin(user)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    if (mediaRecord.status !== 'PENDING') {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Media already confirmed or failed')
    }

    const activeUpload = serverState.activeUploads.get(body.data.mediaId)
    if (!activeUpload) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Upload session expired or invalid')
    }

    const uploadAge = Date.now() - activeUpload.startedAt
    const MAX_UPLOAD_AGE_MS = 30 * 60 * 1000
    if (uploadAge > MAX_UPLOAD_AGE_MS) {
      serverState.activeUploads.delete(body.data.mediaId)
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Upload session expired')
    }

    // ARCHITECTURE FIX: Validate actual uploaded file metadata
    if (body.data.actualSize && body.data.actualMimeType) {
      const validation = validateUploadedFile(
        { 
          size: activeUpload.declaredSize, 
          mimeType: activeUpload.declaredMimeType,
          type: activeUpload.type 
        },
        { 
          size: body.data.actualSize, 
          mimeType: body.data.actualMimeType 
        }
      )

      if (!validation.valid) {
        const reason = validation.reason || 'File validation failed'
        logger.warn({ 
          mediaId: body.data.mediaId, 
          userId: user.id, 
          reason 
        }, 'File validation failed')
        return sendError(reply, 400, 'VALIDATION_ERROR', reason)
      }
    }

    try {
      await db.transaction(async (tx) => {
        await tx.update(media)
          .set({
            status: 'CONFIRMED',
            confirmedAt: new Date(),
            // ARCHITECTURE FIX: Store actual size if different
            size: body.data.actualSize ?? mediaRecord.size,
            // Use the actual CDN URL returned by ImageKit (correct folder path)
            // Fall back to pre-generated URL if not provided
            ...(body.data.cdnUrl && { cdnUrl: body.data.cdnUrl }),
          })
          .where(eq(media.id, body.data.mediaId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'media.upload',
          entityType: 'media',
          entityId: mediaRecord.id,
          details: JSON.stringify({ 
            type: mediaRecord.type, 
            size: body.data.actualSize ?? mediaRecord.size,
            validated: !!body.data.actualSize
          })
        })
      })
      serverState.activeUploads.delete(body.data.mediaId)
    } catch (error) {
      logger.error({ mediaId: body.data.mediaId, error }, 'Confirm failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to confirm upload')
    }

    return sendOk(reply, {
      media: {
        id: mediaRecord.id,
        type: mediaRecord.type,
        mimeType: mediaRecord.mimeType,
        // Return the actual cdnUrl (from ImageKit response if provided, else what was in DB)
        cdnUrl: body.data.cdnUrl ?? mediaRecord.cdnUrl,
        filename: mediaRecord.filename,
        size: body.data.actualSize ?? mediaRecord.size
      }
    })
  })

  // ARCHITECTURE FIX: ImageKit Webhook Endpoint
  // This receives notifications from ImageKit when files are uploaded
  fastify.post('/webhooks/imagekit', async (request, reply) => {
    // Verify webhook signature
    const signature = request.headers['x-imagekit-signature'] as string
    const timestamp = request.headers['x-imagekit-timestamp'] as string
    
    if (!signature || !timestamp) {
      return sendError(reply, 401, 'UNAUTHORIZED', 'Missing signature')
    }

    // Validate timestamp (prevent replay attacks)
    const now = Math.floor(Date.now() / 1000)
    const webhookTime = parseInt(timestamp, 10)
    if (Math.abs(now - webhookTime) > 300) { // 5 minute tolerance
      return sendError(reply, 401, 'UNAUTHORIZED', 'Timestamp expired')
    }

    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha1', env.imagekitPrivateKey || '')
      .update(`${timestamp}.${JSON.stringify(request.body)}`)
      .digest('hex')

    if (signature !== expectedSignature) {
      logger.warn({ 
        received: signature, 
        expected: expectedSignature 
      }, 'ImageKit webhook signature mismatch')
      return sendError(reply, 401, 'UNAUTHORIZED', 'Invalid signature')
    }

    // Parse and validate webhook payload
    const parseResult = imagekitWebhookSchema.safeParse(request.body)
    if (!parseResult.success) {
      logger.debug({ body: request.body }, 'Invalid ImageKit webhook payload')
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid payload')
    }

    const { file } = parseResult.data

    // Extract mediaId from filePath (format: {type}/{mediaId}.{ext})
    const pathParts = file.filePath.split('/')
    const filename = pathParts[pathParts.length - 1]
    if (!filename) {
      logger.warn({ filePath: file.filePath }, 'Invalid filePath in webhook')
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid file path')
    }
    const mediaId = filename.split('.')[0] || ''

    if (!isValidId(mediaId)) {
      logger.warn({ filePath: file.filePath }, 'Invalid mediaId in webhook')
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
    }

    // Find the pending media record
    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, mediaId),
      columns: { 
        id: true, status: true, type: true, 
        size: true, mimeType: true, filename: true 
      }
    })

    if (!mediaRecord) {
      logger.warn({ mediaId }, 'Media not found in webhook')
      // Don't expose whether media exists - just acknowledge
      return sendOk(reply, { received: true })
    }

    if (mediaRecord.status !== 'PENDING') {
      return sendOk(reply, { received: true, status: mediaRecord.status })
    }

    // Validate file metadata
    const actualMimeType = file.fileType === 'image' ? 'image/jpeg' : 'application/octet-stream'

    const validation = validateUploadedFile(
      { 
        size: mediaRecord.size, 
        mimeType: mediaRecord.mimeType,
        type: mediaRecord.type 
      },
      { size: file.size, mimeType: actualMimeType }
    )

    if (!validation.valid) {
      logger.warn({ 
        mediaId, 
        reason: validation.reason,
        declared: { size: mediaRecord.size, type: mediaRecord.type },
        actual: { size: file.size, type: actualMimeType }
      }, 'ImageKit webhook validation failed')

      // Delete the invalid file from ImageKit
      try {
        await deleteFromImageKit(file.fileId)
      } catch (deleteError) {
        logger.error({ mediaId, error: deleteError }, 'Failed to delete invalid file')
      }

      // Mark as FAILED (no updatedAt column in media table)
      await db.update(media)
        .set({ status: 'FAILED' })
        .where(eq(media.id, mediaId))

      return sendOk(reply, { received: true, validated: false, reason: validation.reason })
    }

    // Validation passed - file is legitimate
    logger.info({ mediaId, fileId: file.fileId }, 'ImageKit webhook validation passed')
    
    // Don't auto-confirm here - let client call /confirm
    // But we could update metadata if needed
    
    return sendOk(reply, { 
      received: true, 
      validated: true,
      mediaId,
      actualSize: file.size,
      actualDimensions: file.width && file.height ? { width: file.width, height: file.height } : undefined
    })
  })

  // ARCHITECTURE FIX: Server-side upload with EXIF stripping
  // This endpoint accepts direct file uploads with processing
  fastify.post('/upload', { preHandler: uploadPreHandler }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const config = getConfig()
    if (!config.features.mediaUpload) {
      return sendError(reply, 403, 'FORBIDDEN', 'Media uploads are disabled')
    }

    const uploadContext = (request.headers['x-upload-context'] as string | undefined) || ''
    const isReportUpload = uploadContext === 'report'

    if (!isReportUpload && !canUploadMedia(user)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Media uploads not permitted')
    }

    const mediaType = request.headers['x-media-type'] as string
    const rawMime = request.headers['content-type'] || 'application/octet-stream'
    const mimeType = normalizeMimeType(rawMime)
    const rawFilename = request.headers['x-filename']
    
    let decodedFilename: string
    try {
      decodedFilename = decodeURIComponent((typeof rawFilename === 'string' ? rawFilename : 'upload') || 'upload')
    } catch {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid filename encoding')
    }
    
    const filename = sanitizeFilename(decodedFilename)
    const validMediaTypes = ['IMAGE', 'DOCUMENT'] as const
    
    if (!validMediaTypes.includes(mediaType as typeof validMediaTypes[number])) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media type')
    }

    const category = mediaType.toLowerCase() as 'image' | 'document'
    
    if (!isAllowedMimeType(mimeType, category)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File type not allowed')
    }

    const body = request.body as Buffer
    if (!body || body.length === 0) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Empty file')
    }

    const maxSize = getMaxFileSize(category)
    if (body.length > maxSize) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File too large', {
        maxSize,
        actualSize: body.length
      })
    }

    if (!validateFileSignature(body, mimeType)) {
      logger.warn({ userId: user.id, mimeType, size: body.length }, 'File signature validation failed')
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File content does not match declared type')
    }

    // ARCHITECTURE FIX: Strip EXIF data from images
    let processedBuffer = body
    if (category === 'image' && mimeType !== 'image/gif') {
      processedBuffer = await stripExifData(body, mimeType)
      logger.info({ 
        userId: user.id, 
        originalSize: body.length, 
        processedSize: processedBuffer.length,
        reduction: `${((1 - processedBuffer.length / body.length) * 100).toFixed(1)}%`
      }, 'EXIF stripped from image')
    }

    const fileHash = crypto.createHash('sha256').update(processedBuffer).digest('hex')

    // Deduplication check
    if (fileHash) {
      const existingMedia = await db.query.media.findFirst({
        where: and(
          eq(media.hash, fileHash),
          eq(media.status, 'CONFIRMED')
        ),
        columns: { id: true, filename: true, r2Key: true, cdnUrl: true }
      })

      if (existingMedia) {
        logger.info({ userId: user.id, hash: fileHash }, 'Bypassing upload via deduplication')
        const deduplicatedMediaId = ulid()
        
        await db.insert(media).values({
          id: deduplicatedMediaId,
          uploadedBy: user.id,
          type: mediaType as 'IMAGE' | 'DOCUMENT',
          mimeType,
          size: processedBuffer.length,
          filename: sanitizeFilename(decodedFilename),
          r2Key: existingMedia.r2Key,
          cdnUrl: existingMedia.cdnUrl,
          hash: fileHash,
          status: 'CONFIRMED',
          confirmedAt: new Date(),
        })

        return sendOk(reply, {
          media: {
            id: deduplicatedMediaId,
            type: mediaType,
            mimeType,
            size: processedBuffer.length,
            cdnUrl: existingMedia.cdnUrl,
            filename: existingMedia.filename,
          },
          deduplicated: true,
        })
      }
    }

    // Upload to storage
    const mediaId = ulid()
    const extension = filename.split('.').pop() || 'bin'
    const r2Key = `${category}/${mediaId}.${extension}`

    try {
      const cdnUrl = await uploadToR2({
        key: r2Key,
        data: processedBuffer,
        mimeType,
        metadata: {
          uploadedBy: user.id,
          originalName: filename,
        }
      })

      await db.insert(media).values({
        id: mediaId,
        uploadedBy: user.id,
        type: mediaType as 'IMAGE' | 'DOCUMENT',
        mimeType,
        size: processedBuffer.length,
        filename: sanitizeFilename(decodedFilename),
        r2Key,
        cdnUrl,
        hash: fileHash,
        status: 'CONFIRMED',
        confirmedAt: new Date(),
      })

      await db.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'media.upload',
        entityType: 'media',
        entityId: mediaId,
        details: JSON.stringify({ 
          type: mediaType, 
          size: processedBuffer.length,
          exifStripped: category === 'image' && mimeType !== 'image/gif'
        })
      })

      return sendOk(reply, {
        media: {
          id: mediaId,
          type: mediaType,
          mimeType,
          cdnUrl,
          filename: sanitizeFilename(decodedFilename),
          size: processedBuffer.length,
        }
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Processed upload failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to process upload')
    }
  })

  // Rest of the routes (delete, stream, etc.) remain the same...
  fastify.delete('/:mediaId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { mediaId } = request.params as { mediaId: string }

    if (!isValidId(mediaId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
    }

    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, mediaId),
      columns: { id: true, status: true, uploadedBy: true, r2Key: true, type: true }
    })

    if (!mediaRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'Media not found')
    }

    const userIsAdmin = isAdmin(user)
    const isOwner = mediaRecord.uploadedBy === user.id

    // Check if this media is attached to any message (via forward FK)
    const attachedMsg = await db.select({ id: messages.id })
      .from(messages)
      .where(eq(messages.mediaId, mediaId))
      .limit(1)
    const isAttachedToMessage = attachedMsg.length > 0

    if (!userIsAdmin && (!isOwner || isAttachedToMessage)) {
      return sendError(reply, 403, 'FORBIDDEN', 'Cannot delete this media')
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
          action: 'media.delete',
          entityType: 'media',
          entityId: mediaId,
          details: JSON.stringify({ type: mediaRecord.type })
        })
      })
    } catch (error) {
      logger.error({ mediaId, error }, 'Media delete failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to delete media')
    }

    return sendOk(reply, { deleted: true })
  })

  fastify.get('/stream/:mediaId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    if (!checkStreamRateLimit(user.id)) {
      return sendError(reply, 429, 'RATE_LIMITED', 'Stream rate limit exceeded')
    }

    const { mediaId } = request.params as { mediaId: string }

    if (!isValidId(mediaId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
    }

    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, mediaId),
      columns: { id: true, status: true, uploadedBy: true, r2Key: true, type: true, mimeType: true, size: true, filename: true }
    })

    if (!mediaRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'Media not found')
    }

    if (mediaRecord.status !== 'CONFIRMED') {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Media not ready')
    }

    const canAccess = await canAccessMediaRecord(user, mediaRecord)
    if (!canAccess) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    // Audit log media stream access
    await db.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
      action: 'media.stream',
      entityType: 'media',
      entityId: mediaId
    })

    try {
      const signedUrl = await getSignedR2Url(mediaRecord.r2Key, 60)
      return reply.redirect(signedUrl, 307)
    } catch (error) {
      logger.error({ mediaId, error }, 'Stream URL generation failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to generate stream URL')
    }
  })

  fastify.get('/:mediaId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { mediaId } = request.params as { mediaId: string }

    if (!isValidId(mediaId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid media ID')
    }

    const mediaRecord = await db.query.media.findFirst({
      where: eq(media.id, mediaId),
      columns: { id: true, status: true, uploadedBy: true, type: true, mimeType: true, size: true, filename: true, cdnUrl: true, uploadedAt: true, confirmedAt: true }
    })

    if (!mediaRecord) {
      return sendError(reply, 404, 'NOT_FOUND', 'Media not found')
    }

    const canAccess = await canAccessMediaRecord(user, mediaRecord)
    if (!canAccess) {
      return sendError(reply, 403, 'FORBIDDEN', 'Access denied')
    }

    // Audit log media access
    await db.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
      action: 'media.access',
      entityType: 'media',
      entityId: mediaId
    })

    return sendOk(reply, {
      media: {
        id: mediaRecord.id,
        type: mediaRecord.type,
        mimeType: mediaRecord.mimeType,
        size: mediaRecord.size,
        filename: mediaRecord.filename,
        cdnUrl: mediaRecord.cdnUrl,
        uploadedAt: mediaRecord.uploadedAt,
        confirmedAt: mediaRecord.confirmedAt,
      }
    })
  })
}
