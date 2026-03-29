import type { FastifyInstance, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { eq, and, isNull, desc, gt, ne, sql } from 'drizzle-orm'
import { ulid } from 'ulid'
import { hash, verify } from '@node-rs/argon2'
import { randomBytes, createHash } from 'crypto'
import { db } from '../db/index.js'
import { users, sessions, auditLogs, passwordResetTokens, refreshTokens, registrationReports, media } from '../db/schema.js'
import { normalizeEmail, extractDeviceInfo, hashEmail, hashResetToken, safeJsonParse, isValidId, sanitizeName, sanitizeFilename, sleep, anonymizeIpAddress, validateFileSignature } from '../lib/utils.js'
import { getConfig, isAllowedMimeType, getMaxFileSize, normalizeMimeType } from '../lib/config.js'
import { passwordSchema } from '../lib/passwordPolicy.js'
import { uploadToR2, getCdnUrl } from '../services/storage.js'
import { 
  requireApprovedUser, 
  requireUser, 
  sendError, 
  sendOk, 
  issueAuthCookies, 
  clearAuthCookies, 
  signToken, 
  signRefreshToken, 
  createRefreshToken, 
  hashRefreshToken 
} from '../middleware/auth.js'
import { checkLoginLockout, recordLoginAttempt, createRateLimiters } from '../middleware/rateLimit.js'
import { addUserToCache, getUserFromCache } from '../state.js'
import { invalidateStatsCache } from '../routes/stats.js'
import { queueHighPriorityEmail } from '../services/emailQueue.js'
import { emitToAdmins, forceLogout, forceLogoutSession } from '../socket/index.js'
import { logger } from '../lib/logger.js'

const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

interface LoginResult {
  success: true
  user: typeof users.$inferSelect
}

interface LoginError {
  success: false
  code: string
  message: string
  httpStatus: number
}

async function validateLoginCredentials(
  email: string,
  password: string,
  requestIp: string
): Promise<LoginResult | LoginError> {
  const emailHash = hashEmail(email)
  const user = await db.query.users.findFirst({
    where: eq(users.email, email)
  })

  if (!user) {
    await verify(DUMMY_HASH, password)
    await recordLoginAttempt(requestIp, false)
    await db.insert(auditLogs).values({
      id: ulid(),
      ipAddress: anonymizeIpAddress(requestIp, 'truncate'),
      action: 'auth.login_failed',
      entityType: 'email',
      entityId: emailHash,
      details: JSON.stringify({ reason: 'invalid_credentials', emailHash })
    })
    return { success: false, code: 'UNAUTHORIZED', message: 'Invalid credentials', httpStatus: 401 }
  }

  const passwordValid = await verify(user.passwordHash, password)
  if (!passwordValid) {
    await recordLoginAttempt(requestIp, false)
    await db.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(requestIp, 'truncate'),
      action: 'auth.login_failed',
      entityType: 'user',
      entityId: user.id,
      details: JSON.stringify({ reason: 'invalid_credentials', emailHash })
    })
    return { success: false, code: 'UNAUTHORIZED', message: 'Invalid credentials', httpStatus: 401 }
  }

  if (user.status !== 'APPROVED') {
    await db.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(requestIp, 'truncate'),
      action: 'auth.login_forbidden',
      entityType: 'user',
      entityId: user.id,
      details: JSON.stringify({ status: user.status, emailHash })
    })
    const message = user.status === 'REJECTED'
      ? `Account rejected: ${user.rejectionReason || 'No reason provided'}`
      : user.status === 'SUSPENDED'
        ? 'Account suspended'
        : 'Account pending approval'
    return { success: false, code: 'FORBIDDEN', message, httpStatus: 403 }
  }

  return { success: true, user }
}

async function evictOldestSession(
  userId: string,
  maxDevices: number,
  requestIp: string
): Promise<void> {
  const now = new Date()
  const activeSessions = await db.query.sessions.findMany({
    where: and(
      eq(sessions.userId, userId),
      isNull(sessions.revokedAt),
      gt(sessions.expiresAt, now)
    ),
    orderBy: [sessions.priority, sessions.createdAt],
    limit: maxDevices + 50,
    columns: { id: true, priority: true }
  })

  // To strictly enforce single-device logic, if we hit the limit, we sweep ALL the oldest excess devices.
  if (activeSessions.length >= maxDevices) {
    const excessCount = activeSessions.length - maxDevices + 1
    const sessionsToRevoke = activeSessions.slice(0, Math.max(0, excessCount))

    // Sequential eviction: SQLite serializes writes so parallel transactions can deadlock
    // and partial success on error leaves sessions in an inconsistent state.
    for (const sessionToRevoke of sessionsToRevoke) {
      await db.transaction(async (tx) => {
        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(eq(sessions.id, sessionToRevoke.id))

        await tx.update(refreshTokens)
          .set({ revokedAt: now, lastUsedAt: now })
          .where(and(
            eq(refreshTokens.sessionId, sessionToRevoke.id),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId,
          ipAddress: anonymizeIpAddress(requestIp, 'truncate'),
          action: 'session.evicted',
          entityType: 'session',
          entityId: sessionToRevoke.id,
          details: JSON.stringify({
            reason: 'max_devices',
            maxDevices,
            evictedPriority: sessionToRevoke.priority
          })
        })
      })

      forceLogoutSession(sessionToRevoke.id, 'Session evicted (max devices reached)')
    }
  }
}

async function createLoginSession(
  user: Pick<typeof users.$inferSelect, 'id' | 'email' | 'role' | 'status' | 'name' | 'mediaPermission' | 'emailNotifyOnMessage'>,
  requestIp: string,
  deviceInfo: string,
  sessionPriority: number
): Promise<{ sessionId: string; expiresAt: Date; emailHash: string }> {
  const config = getConfig()
  const now = new Date()
  const sessionId = ulid()
  const expiresAt = new Date(Date.now() + config.session.accessTokenDays * 24 * 60 * 60 * 1000)
  const emailHash = hashEmail(user.email)

  await db.transaction(async (tx) => {
    await tx.insert(sessions).values({
      id: sessionId,
      userId: user.id,
      deviceInfo,
      ipAddress: anonymizeIpAddress(requestIp, 'truncate'),
      priority: Math.min(sessionPriority, 10),
      expiresAt
    })

    await tx.insert(auditLogs).values({
      id: ulid(),
      userId: user.id,
      ipAddress: anonymizeIpAddress(requestIp, 'hash'),
      action: 'session.login',
      entityType: 'session',
      entityId: sessionId,
      details: JSON.stringify({ emailHash })
    })

    await tx.update(users)
      .set({ lastSeenAt: now, updatedAt: now })
      .where(eq(users.id, user.id))
  })

  return { sessionId, expiresAt, emailHash }
}

// Phone validation: smart parsing for Ghanaian numbers converting "0..." to "233..."
const registerSchema = z.object({
  email: z.string().email().max(255),
  password: passwordSchema,
  name: z.string().min(2).max(100).transform(s => sanitizeName(s)),
  phone: z.string().min(1, 'Phone number is required').transform(str => {
    let cleaned = str.replace(/[\s\-()]/g, '')
    if (cleaned.startsWith('+233')) cleaned = cleaned.substring(1)
    if (cleaned.startsWith('0')) cleaned = '233' + cleaned.substring(1)
    return cleaned
  }).refine(str => /^233[0-9]{9}$/.test(str), {
    message: 'Invalid Ghanaian phone number. Use format 05... or 233...'
  }),
  // Optional registration report (JSON mode - no media)
  reportSubject: z.string().min(1).max(200).optional(),
  reportDescription: z.string().min(1).max(2000).optional(),
})

const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(128)
})

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: passwordSchema
})

const passwordResetRequestSchema = z.object({
  email: z.string().email().max(255)
})

const passwordResetSchema = z.object({
  token: z.string().min(1),
  newPassword: passwordSchema
})

function calculateSessionPriority(deviceInfo: string, ipAddress: string): number {
  try {
    const device = JSON.parse(deviceInfo)
    let priority = 1

    const userAgent = device.userAgent || ''
    if (userAgent.includes('Chrome') || userAgent.includes('Firefox') || userAgent.includes('Safari')) {
      priority += 2
    }

    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
      priority += 1
    }

    // CRITICAL FIX: Properly validate private IP ranges
    // 127.0.0.0/8 (loopback), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    let isPrivateIp = false
    if (ipAddress === '127.0.0.1' || ipAddress === '::1') {
      isPrivateIp = true
    } else if (ipAddress.startsWith('10.') || ipAddress.startsWith('::ffff:10.')) {
      isPrivateIp = true
    } else if (ipAddress.startsWith('192.168.') || ipAddress.startsWith('::ffff:192.168.')) {
      isPrivateIp = true
    } else if (ipAddress.startsWith('172.')) {
      const secondOctet = parseInt(ipAddress.split('.')[1] || '0', 10)
      isPrivateIp = secondOctet >= 16 && secondOctet <= 31
    } else if (ipAddress.startsWith('::ffff:172.')) {
      const mappedIp = ipAddress.slice(7)
      const secondOctet = parseInt(mappedIp.split('.')[1] || '0', 10)
      isPrivateIp = secondOctet >= 16 && secondOctet <= 31
    }
    if (isPrivateIp) {
      priority += 1
    }

    return Math.min(priority, 5)
  } catch (error) {
    logger.debug({ error }, 'Failed to parse device info for session priority')
    return 1
  }
}

export async function authRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

fastify.post('/register', { preHandler: rateLimiters.registration }, async (request, reply) => {
    const config = getConfig()
    if (!config.features.userRegistration) {
      return sendError(reply, 403, 'FORBIDDEN', 'Registration is disabled')
    }

    let body: z.infer<typeof registerSchema>
    let mediaFile: Buffer | null = null
    let mediaMeta: { filename: string; mimetype: string; size: number } | null = null

    // Detect content type and parse accordingly
    const contentType = request.headers['content-type'] || ''
    const isMultipart = contentType.includes('multipart/form-data')

  if (isMultipart) {
    // Parse multipart form with file
    const parts = request.parts()
    const fields: Record<string, string> = {}

    for await (const part of parts) {
      if (part.type === 'file') {
        // SECURITY FIX: Read first, then validate size (bytesRead is not reliable before reading)
        const buffer = await part.toBuffer()
        const maxSize = Math.min(getMaxFileSize('image'), 10 * 1024 * 1024)

        if (buffer.length > maxSize) {
          return sendError(reply, 400, 'VALIDATION_ERROR', `File too large (max ${Math.round(maxSize / 1024 / 1024)}MB)`)
        }

        mediaFile = buffer
        mediaMeta = {
          filename: part.filename,
          mimetype: part.mimetype,
          size: buffer.length
        }
      } else {
        fields[part.fieldname] = String(await part.value)
      }
    }

      const parsed = registerSchema.safeParse(fields)
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', parsed.error.issues)
      }
      body = parsed.data
    } else {
      // Standard JSON registration (no media)
      const parsed = registerSchema.safeParse(request.body)
      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', parsed.error.issues)
      }
      body = parsed.data
    }

    const email = normalizeEmail(body.email)
    const userId = ulid()
    const hasReport = !!(body.reportSubject && body.reportDescription)
    const reportId = hasReport ? ulid() : null

    // Hash password before transaction
    const passwordHash = await hash(body.password)

    // Process media if provided
    let mediaId: string | null = null
    let mediaData: { r2Key: string; cdnUrl: string | null; type: 'IMAGE' | 'DOCUMENT'; mimeType: string; size: number; filename: string } | null = null

    if (hasReport && mediaFile && mediaMeta) {
      const normalizedMime = normalizeMimeType(mediaMeta.mimetype)
      let mediaType: 'IMAGE' | 'DOCUMENT'

      if (normalizedMime.startsWith('image/')) {
        mediaType = 'IMAGE'
      } else {
        mediaType = 'DOCUMENT'
      }

      const category = mediaType.toLowerCase() as 'image' | 'document'
    if (!isAllowedMimeType(normalizedMime, category)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File type not allowed')
    }

    // SECURITY FIX: Validate file content matches declared MIME type
    if (!validateFileSignature(mediaFile, normalizedMime)) {
      logger.warn({ mimetype: normalizedMime, size: mediaFile.length }, 'File signature validation failed during registration')
      return sendError(reply, 400, 'VALIDATION_ERROR', 'File content does not match declared type')
    }

    // File size already validated at lines 301-307 after reading buffer

      mediaId = ulid()
      const extension = mediaMeta.filename.split('.').pop() || 'bin'
      const r2Key = `${category}/${mediaId}.${extension}`
      const cdnUrl = mediaType === 'DOCUMENT' ? null : getCdnUrl(r2Key, mediaType)

      mediaData = {
        r2Key,
        cdnUrl,
        type: mediaType,
        mimeType: normalizedMime,
        size: mediaFile.length,
        filename: sanitizeFilename(mediaMeta.filename)
      }
    }

    try {
      // Upload media BEFORE the transaction so a DB failure doesn't orphan R2 objects.
      // If the upload itself fails we throw early and never touch the DB.
      // If the DB transaction fails after a successful upload we attempt a best-effort R2 delete.
      if (hasReport && mediaData && mediaFile && reportId) {
        try {
          await uploadToR2({
            key: mediaData.r2Key,
            data: mediaFile,
            mimeType: mediaData.mimeType,
            metadata: {
              uploadedBy: userId,
              originalName: mediaData.filename,
              reportId: reportId
            }
          })
        } catch (uploadError) {
          logger.error({ userId, error: uploadError }, 'Media upload failed during registration')
          return sendError(reply, 500, 'MEDIA_UPLOAD_FAILED', 'Failed to upload attachment')
        }
      }

      // ATOMIC TRANSACTION: user + report + media record (no R2 calls inside)
      try {
      await db.transaction(async (tx) => {
        // 1. Create user
        await tx.insert(users).values({
          id: userId,
          email,
          passwordHash,
          name: body.name,
          phone: body.phone || null,
          role: 'USER',
          status: 'PENDING',
          mediaPermission: false,
          emailNotifyOnMessage: true
        })

        // 2. Audit log
        await tx.insert(auditLogs).values({
          id: ulid(),
          userId,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.register',
          entityType: 'user',
          entityId: userId,
          details: JSON.stringify({ emailHash: hashEmail(email), hasReport, hasMedia: !!mediaData })
        })

        // 3. Create media record (upload already done above)
        if (hasReport && mediaData && mediaFile && reportId) {
          await tx.insert(media).values({
            id: mediaId!,
            uploadedBy: userId,
            type: mediaData.type,
            mimeType: mediaData.mimeType,
            size: mediaData.size,
            filename: mediaData.filename,
            r2Key: mediaData.r2Key,
            cdnUrl: mediaData.cdnUrl,
            hash: createHash('sha256').update(mediaFile).digest('hex'),
            status: 'CONFIRMED',
            confirmedAt: new Date()
          })

          // 4. Media audit log
          await tx.insert(auditLogs).values({
            id: ulid(),
            userId,
            ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
            action: 'media.upload',
            entityType: 'media',
            entityId: mediaId!,
            details: JSON.stringify({
              type: mediaData.type,
              size: mediaData.size,
              context: 'registration_report'
            })
          })
        }

        // 5. Create registration report
        if (hasReport && reportId) {
          await tx.insert(registrationReports).values({
            id: reportId,
            userId,
            subject: body.reportSubject!,
            description: body.reportDescription!,
            mediaId: mediaId,
            status: 'PENDING',
          })

          // 6. Report audit log
          await tx.insert(auditLogs).values({
            id: ulid(),
            userId,
            ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
            action: 'report.created',
            entityType: 'registration_report',
            entityId: reportId,
            details: JSON.stringify({ subject: body.reportSubject })
          })
        }
      })
      } catch (txError) {
        // DB transaction failed — attempt to clean up the already-uploaded R2 object
        if (hasReport && mediaData) {
          try {
            const { deleteFromR2 } = await import('../services/storage.js')
            await deleteFromR2(mediaData.r2Key)
          } catch (cleanupError) {
            logger.error({ userId, r2Key: mediaData.r2Key, error: cleanupError }, 'Failed to clean up R2 object after transaction failure')
          }
        }
        throw txError
      }

      addUserToCache(userId, {
        role: 'USER',
        status: 'PENDING',
        name: body.name,
        mediaPermission: false,
        emailNotifyOnMessage: true
      })

      invalidateStatsCache()
      emitToAdmins('stats:invalidate', {})
      emitToAdmins('admin:user_registered', {
        user: {
          id: userId,
          email,
          name: body.name,
          status: 'PENDING',
          createdAt: Date.now(),
          hasReport,
          reportId,
          reportSubject: hasReport ? body.reportSubject : undefined,
          hasMedia: !!mediaData
        }
      })

      reply.code(201)
      return sendOk(reply, {
        message: 'Registration successful. Your account is pending approval. You will be notified via email when approved.',
        user: {
          id: userId,
          email,
          name: body.name,
          role: 'USER',
          status: 'PENDING',
          mediaPermission: false,
          emailNotifyOnMessage: true
        },
        hasReport,
        hasMedia: !!mediaData
      })

    } catch (error: unknown) {
      const err = error as { message?: string; code?: string | number }

      if (err?.message?.includes('UNIQUE constraint failed') ||
          err?.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
          err?.code === 2067) {
        await sleep(300)
        return sendError(reply, 409, 'CONFLICT', 'Email already exists')
      }

      logger.error({ emailHash: hashEmail(email), error }, 'Registration failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Registration failed')
    }
  })

  fastify.post('/login', { preHandler: rateLimiters.login }, async (request, reply) => {
    const lockout = await checkLoginLockout(request.ip)
    if (lockout.locked) {
    reply.header('Retry-After', lockout.retryAfter!.toString())
    await db.insert(auditLogs).values({
      id: ulid(),
      ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
      action: 'auth.login_locked',
      entityType: 'ip',
      entityId: anonymizeIpAddress(request.ip, 'truncate'),
      details: JSON.stringify({ retryAfter: lockout.retryAfter })
    })
      return sendError(reply, 429, 'RATE_LIMITED', 'Too many failed attempts', {
        retryAfter: lockout.retryAfter
      })
    }

    const body = loginSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const email = normalizeEmail(body.data.email)
    const result = await validateLoginCredentials(email, body.data.password, request.ip)

    if (!result.success) {
      return sendError(reply, result.httpStatus, result.code, result.message)
    }

    const user = result.user
    await recordLoginAttempt(request.ip, true)

    // Enforce up to 5 active devices to allow mobile + desktop + tablet
    // Any pre-existing devices beyond this limit are targeted by evictOldestSession
    await evictOldestSession(user.id, 5, request.ip)

    const deviceInfo = extractDeviceInfo(request)
    let sessionPriority = calculateSessionPriority(deviceInfo, request.ip)

    if (user.role === 'ADMIN' || user.role === 'SUPER_ADMIN') {
      sessionPriority += 3
    }

    const { sessionId, expiresAt } = await createLoginSession(user, request.ip, deviceInfo, sessionPriority)

    const token = signToken({
      sub: user.id,
      email: user.email,
      role: user.role,
      status: user.status,
      sessionId
    })

    const refreshToken = await createRefreshToken(
      user.id,
      sessionId,
      request.ip,
      deviceInfo
    )

    // Issue cookies *after* refresh token generation to set both
    const cookies = issueAuthCookies(reply, token, refreshToken)

    addUserToCache(user.id, {
      role: user.role,
      status: user.status,
      name: user.name,
      mediaPermission: user.mediaPermission ?? false,
      emailNotifyOnMessage: user.emailNotifyOnMessage ?? true
    })

    return sendOk(reply, {
      token,
      csrfToken: cookies.csrfToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        mediaPermission: user.mediaPermission,
        emailNotifyOnMessage: user.emailNotifyOnMessage
      },
      session: {
        id: sessionId,
        expiresAt: expiresAt.getTime()
      }
    })
  })

  fastify.post('/password/forgot', { preHandler: rateLimiters.passwordReset }, async (request, reply) => {
    const body = passwordResetRequestSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const email = normalizeEmail(body.data.email)
    const emailHash = hashEmail(email)
    const user = await db.query.users.findFirst({
      where: eq(users.email, email),
      columns: { id: true, email: true }
    })

    if (user) {
      const config = getConfig()
      const rawToken = randomBytes(32).toString('hex')
      const tokenHash = hashResetToken(rawToken)
      const expiresAt = new Date(Date.now() + config.session.passwordResetTokenMinutes * 60 * 1000)

      try {
        await db.transaction(async (tx) => {
          await tx.delete(passwordResetTokens)
            .where(and(
              eq(passwordResetTokens.userId, user.id),
              isNull(passwordResetTokens.usedAt)
            ))

          await tx.insert(passwordResetTokens).values({
            id: ulid(),
            userId: user.id,
            tokenHash,
            ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
            expiresAt
          })

          await tx.insert(auditLogs).values({
            id: ulid(),
            userId: user.id,
            ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
            action: 'user.password_reset_request',
            entityType: 'user',
            entityId: user.id
          })
        })
      } catch (error) {
        logger.error({ userId: user.id, error }, 'Failed to create password reset token')
        return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to process reset request')
      }

      try {
        await queueHighPriorityEmail(user.id, 'passwordReset', { resetToken: rawToken })
      } catch (error) {
        logger.warn({ userId: user.id, error }, 'Failed to send reset email')
      }
    } else {
      await db.insert(auditLogs).values({
        id: ulid(),
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'auth.password_reset_request_unknown',
        entityType: 'email',
        entityId: emailHash,
        details: JSON.stringify({ emailHash })
      })
    }

    return sendOk(reply, { message: 'If an account exists, a reset link has been sent.' })
  })

  fastify.post('/password/reset', { preHandler: rateLimiters.passwordReset }, async (request, reply) => {
    const body = passwordResetSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    const tokenHash = hashResetToken(body.data.token)
    const now = new Date()

    // SECURITY FIX: Use atomic UPDATE with RETURNING to prevent race condition token reuse
    // This ensures only one request can consume the token
    const consumeResult = await db.update(passwordResetTokens)
      .set({ usedAt: now })
      .where(and(
        eq(passwordResetTokens.tokenHash, tokenHash),
        isNull(passwordResetTokens.usedAt),
        gt(passwordResetTokens.expiresAt, now)
      ))
      .returning({ id: passwordResetTokens.id, userId: passwordResetTokens.userId })

    if (!consumeResult || consumeResult.length === 0) {
      await db.insert(auditLogs).values({
        id: ulid(),
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'auth.password_reset_failed',
        entityType: 'token',
        entityId: tokenHash.substring(0, 16),
        details: JSON.stringify({ reason: 'invalid_or_expired' })
      })
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid or expired reset token')
    }

    const tokenRecord = consumeResult[0]!

    const user = await db.query.users.findFirst({
      where: eq(users.id, tokenRecord.userId),
      columns: { id: true, email: true }
    })

    if (!user) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    const newHash = await hash(body.data.newPassword)

    try {
      await db.transaction(async (tx) => {
        await tx.update(users)
          .set({ passwordHash: newHash, updatedAt: now })
          .where(eq(users.id, user.id))

        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(and(
            eq(sessions.userId, user.id),
            isNull(sessions.revokedAt)
          ))

        await tx.update(refreshTokens)
          .set({ revokedAt: now, lastUsedAt: now })
          .where(and(
            eq(refreshTokens.userId, user.id),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.password_reset',
          entityType: 'user',
          entityId: user.id,
          details: JSON.stringify({ tokenId: tokenRecord.id })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Failed to reset password')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to reset password')
    }

    forceLogout(user.id, 'Password reset')

    return sendOk(reply, { message: 'Password reset successful' })
  })

  fastify.post('/logout', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const now = new Date()
    try {
      await db.transaction(async (tx) => {
        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(eq(sessions.id, user.sessionId))

        await tx.update(refreshTokens)
          .set({ revokedAt: now })
          .where(and(
            eq(refreshTokens.sessionId, user.sessionId),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'session.logout',
          entityType: 'session',
          entityId: user.sessionId
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, sessionId: user.sessionId, error }, 'Failed to logout')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to logout')
    }

    forceLogoutSession(user.sessionId, 'Logged out')

    clearAuthCookies(reply)
    return sendOk(reply, { message: 'Logged out successfully' })
  })

  fastify.get('/me', { preHandler: requireApprovedUser }, async (request, reply) => {
    const authUser = requireUser(request, reply)
    if (!authUser) return

    const csrfToken = request.cookies['_csrf']

    const cached = getUserFromCache(authUser.id)
    if (cached) {
      return sendOk(reply, {
        csrfToken,
        user: {
          id: authUser.id,
          email: authUser.email,
          name: cached.name,
          role: authUser.role,
          status: authUser.status,
          mediaPermission: cached.mediaPermission,
          emailNotifyOnMessage: cached.emailNotifyOnMessage
        }
      })
    }

    const user = await db.query.users.findFirst({
      where: eq(users.id, authUser.id),
      columns: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        mediaPermission: true,
        emailNotifyOnMessage: true,
        createdAt: true
      }
    })

    if (!user) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    return sendOk(reply, { csrfToken, user })
  })

  fastify.get('/sessions', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const now = new Date()
    const userSessions = await db.query.sessions.findMany({
      where: and(
        eq(sessions.userId, user.id),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now)
      ),
      orderBy: [desc(sessions.createdAt)],
      columns: { id: true, deviceInfo: true, ipAddress: true, createdAt: true, lastActiveAt: true }
    })

    return sendOk(reply, {
      sessions: userSessions.map(s => ({
        id: s.id,
        deviceInfo: safeJsonParse(s.deviceInfo),
        ipAddress: s.ipAddress,
        createdAt: s.createdAt,
        lastActiveAt: s.lastActiveAt,
        isCurrent: s.id === user.sessionId
      }))
    })
  })

  fastify.delete('/sessions/:sessionId', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const { sessionId } = request.params as { sessionId: string }

    if (!isValidId(sessionId)) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid session ID')
    }

    const now = new Date()
    const session = await db.query.sessions.findFirst({
      where: and(
        eq(sessions.id, sessionId),
        eq(sessions.userId, user.id),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now)
      ),
      columns: { id: true }
    })

    if (!session) {
      return sendError(reply, 404, 'NOT_FOUND', 'Session not found')
    }

    const revokeNow = new Date()
    try {
      await db.transaction(async (tx) => {
        await tx.update(sessions)
          .set({ revokedAt: revokeNow })
          .where(eq(sessions.id, sessionId))

        await tx.update(refreshTokens)
          .set({ revokedAt: revokeNow })
          .where(and(
            eq(refreshTokens.sessionId, sessionId),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'session.revoke',
          entityType: 'session',
          entityId: sessionId,
          details: JSON.stringify({ reason: 'user_revoked' })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, sessionId, error }, 'Failed to revoke session')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to revoke session')
    }

    forceLogoutSession(sessionId, 'Session revoked')

    return sendOk(reply, { message: 'Session revoked' })
  })

  fastify.post('/sessions/revoke-all', { preHandler: requireApprovedUser }, async (request, reply) => {
    const user = requireUser(request, reply)
    if (!user) return

    const revokeNow = new Date()

    // Fetch all other active sessions to force-logout individually
    const otherSessions = await db.query.sessions.findMany({
      where: and(
        eq(sessions.userId, user.id),
        isNull(sessions.revokedAt),
        // Exclude the current session using type-safe ne() operator
        ...(user.sessionId ? [ne(sessions.id, user.sessionId)] : [])
      ),
      columns: { id: true }
    })

    try {
      await db.transaction(async (tx) => {
        // Revoke all sessions EXCEPT the current one — ne() is safer than raw sql (#8)
        await tx.update(sessions)
          .set({ revokedAt: revokeNow })
          .where(and(
            eq(sessions.userId, user.id),
            isNull(sessions.revokedAt),
            ne(sessions.id, user.sessionId!)
          ))

        await tx.update(refreshTokens)
          .set({ revokedAt: revokeNow })
          .where(and(
            eq(refreshTokens.userId, user.id),
            isNull(refreshTokens.revokedAt),
            ne(refreshTokens.sessionId, user.sessionId!)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'session.revoke_all',
          entityType: 'user',
          entityId: user.id,
          details: JSON.stringify({ excludedSessionId: user.sessionId, revokedCount: otherSessions.length })
        })
      })
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Failed to revoke all sessions')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to revoke sessions')
    }

    // Force-logout each revoked session individually
    for (const session of otherSessions) {
      forceLogoutSession(session.id, 'All other sessions revoked')
    }

    return sendOk(reply, { message: 'All other sessions revoked', revokedCount: otherSessions.length })
  })

  fastify.post('/password/change', {
    preHandler: [requireApprovedUser, rateLimiters.passwordChange]
  }, async (request, reply) => {
    const authUser = requireUser(request, reply)
    if (!authUser) return

    const body = passwordChangeSchema.safeParse(request.body)
    if (!body.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid input', body.error.issues)
    }

    if (body.data.currentPassword === body.data.newPassword) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'New password must be different')
    }

    const dbUser = await db.query.users.findFirst({
      where: eq(users.id, authUser.id),
      columns: { id: true, passwordHash: true, email: true, name: true, role: true, status: true, mediaPermission: true, emailNotifyOnMessage: true }
    })

    if (!dbUser) {
      return sendError(reply, 404, 'NOT_FOUND', 'User not found')
    }

    const valid = await verify(dbUser.passwordHash, body.data.currentPassword)
    if (!valid) {
      await db.insert(auditLogs).values({
        id: ulid(),
        userId: dbUser.id,
        ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
        action: 'auth.password_change_failed',
        entityType: 'user',
        entityId: dbUser.id,
        details: JSON.stringify({ reason: 'invalid_current_password' })
      })
      return sendError(reply, 401, 'UNAUTHORIZED', 'Invalid current password')
    }

    const newHash = await hash(body.data.newPassword)
    const now = new Date()
    const config = getConfig()
    const deviceInfo = extractDeviceInfo(request)
    const sessionPriority = calculateSessionPriority(deviceInfo, request.ip)

    // Collect old session IDs before the transaction so we can force-logout them below
    const oldSessions = await db.query.sessions.findMany({
      where: and(eq(sessions.userId, dbUser.id), isNull(sessions.revokedAt)),
      columns: { id: true }
    })

    // Revoke all existing sessions + refresh tokens in one transaction
    try {
      await db.transaction(async (tx) => {
        await tx.update(users)
          .set({ passwordHash: newHash, updatedAt: now })
          .where(eq(users.id, dbUser.id))

        await tx.update(sessions)
          .set({ revokedAt: now })
          .where(and(
            eq(sessions.userId, dbUser.id),
            isNull(sessions.revokedAt)
          ))

        await tx.update(refreshTokens)
          .set({ revokedAt: now, lastUsedAt: now })
          .where(and(
            eq(refreshTokens.userId, dbUser.id),
            isNull(refreshTokens.revokedAt)
          ))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId: dbUser.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'user.password_change',
          entityType: 'user',
          entityId: dbUser.id
        })
      })
    } catch (error) {
      logger.error({ userId: dbUser.id, error }, 'Failed to change password')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to change password')
    }

    // Force-logout only OLD sessions — NOT the brand-new session we are about to create (#4)
    for (const s of oldSessions) {
      forceLogoutSession(s.id, 'Password changed')
    }

    // Create new session using the canonical helper — ensures priority, audit log, lastSeenAt (#C)
    const { sessionId: newSessionId, expiresAt } = await createLoginSession(
      dbUser,
      request.ip,
      deviceInfo,
      sessionPriority
    )

    const token = signToken({
      sub: dbUser.id,
      email: dbUser.email,
      role: dbUser.role,
      status: dbUser.status,
      sessionId: newSessionId
    })

    const newRefreshToken = await createRefreshToken(
      dbUser.id,
      newSessionId,
      request.ip,
      deviceInfo
    )

    const { csrfToken } = issueAuthCookies(reply, token, newRefreshToken)

    return sendOk(reply, {
      message: 'Password updated',
      token,
      csrfToken,
      refreshToken: newRefreshToken,
    })
  })

  // SECURITY FIX: Refresh token read from httpOnly cookie or x-refresh-token header
  // Header fallback is strictly preserved for cross-origin private tabs.
  // Body parameter intentionally disabled.

  fastify.post('/refresh', { preHandler: rateLimiters.api }, async (request, reply) => {
    let rawToken = request.cookies.refresh_token
    
    // Fallback unconditionally for private tabs blocking third-party cookies
    if (!rawToken && request.headers['x-refresh-token']) {
      rawToken = request.headers['x-refresh-token'] as string
    }

    if (!rawToken) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Refresh token is required')
    }

    try {
      const now = new Date()
      const config = getConfig()

      const presentedTokenHash = hashRefreshToken(rawToken)

      // PERFORMANCE FIX: Single JOIN query instead of 3 separate queries
      const refreshResult = await db
        .select({
          userId: users.id,
          userEmail: users.email,
          userName: users.name,
          userRole: users.role,
          userStatus: users.status,
          userMediaPermission: users.mediaPermission,
          userEmailNotify: users.emailNotifyOnMessage,
          sessionId: sessions.id,
          tokenId: refreshTokens.id,
        })
        .from(refreshTokens)
        .innerJoin(sessions, eq(refreshTokens.sessionId, sessions.id))
        .innerJoin(users, eq(refreshTokens.userId, users.id))
        .where(and(
          eq(refreshTokens.tokenHash, presentedTokenHash),
          isNull(refreshTokens.revokedAt),
          gt(refreshTokens.expiresAt, now),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, now)
        ))
        .limit(1)

      if (refreshResult.length === 0) {
        return sendError(reply, 401, 'UNAUTHORIZED', 'Invalid or expired refresh token')
      }

      const tokenData = refreshResult[0]
      if (!tokenData) {
        return sendError(reply, 401, 'UNAUTHORIZED', 'Invalid or expired refresh token')
      }

      const { userId, userEmail, userName, userRole, userStatus, userMediaPermission, userEmailNotify, sessionId } = tokenData

      if (userStatus !== 'APPROVED') {
        return sendError(reply, 403, 'FORBIDDEN', 'Account not approved')
      }

      const newToken = signToken({
        sub: userId,
        email: userEmail,
        role: userRole,
        status: userStatus,
        sessionId
      })

      const newRefreshToken = signRefreshToken()
      const newRefreshTokenHash = hashRefreshToken(newRefreshToken)
      const refreshExpiresAt = new Date(now.getTime() + config.session.refreshTokenDays * 24 * 60 * 60 * 1000)

      let revokeRowsAffected = 0
      await db.transaction(async (tx) => {
        const revokeResult = await tx.update(refreshTokens)
          .set({ revokedAt: now, lastUsedAt: now })
          .where(and(
            eq(refreshTokens.tokenHash, presentedTokenHash),
            eq(refreshTokens.userId, userId),
            isNull(refreshTokens.revokedAt)
          ))
        revokeRowsAffected = revokeResult.rowsAffected ?? 0

        // Only proceed if WE were the one to revoke this token.
        // If rowsAffected === 0, a concurrent request already consumed it — abort.
        if (revokeRowsAffected === 0) return

        await tx.insert(refreshTokens).values({
          id: ulid(),
          userId,
          sessionId,
          tokenHash: newRefreshTokenHash,
          deviceInfo: extractDeviceInfo(request),
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          lastUsedAt: now,
          expiresAt: refreshExpiresAt
        })

        await tx.update(sessions)
          .set({ lastActiveAt: now })
          .where(eq(sessions.id, sessionId))

        await tx.insert(auditLogs).values({
          id: ulid(),
          userId,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'auth.token_refresh',
          entityType: 'session',
          entityId: sessionId
        })
      })

      if (revokeRowsAffected === 0) {
        // Token was already consumed — possible replay attack or race
        logger.warn({ userId, sessionId }, 'Refresh token already consumed — possible replay attack')
        return sendError(reply, 401, 'UNAUTHORIZED', 'Refresh token already used')
      }

      const cookies = issueAuthCookies(reply, newToken, newRefreshToken)
      return sendOk(reply, {
        token: newToken,
        csrfToken: cookies.csrfToken,
        refreshToken: newRefreshToken,
        user: {
          id: userId,
          email: userEmail,
          name: userName,
          role: userRole,
          status: userStatus,
          mediaPermission: userMediaPermission,
          emailNotifyOnMessage: userEmailNotify
        }
      })
    } catch (error) {
      logger.warn({ error }, 'Token refresh failed')
      return sendError(reply, 401, 'UNAUTHORIZED', 'Invalid refresh token')
    }
  })
}