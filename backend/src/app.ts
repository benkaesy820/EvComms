import Fastify from 'fastify'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import multipart from '@fastify/multipart'
import { createHmac } from 'node:crypto'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { serverState } from './state.js'
import { initSocket, closeIO, getIO } from './socket/index.js'
import { authRoutes } from './auth/index.js'
import { conversationRoutes, messageRoutes, reactionRoutes } from './routes/conversations.js'
import { mediaRoutes, stopStreamRateLimitCleanup } from './routes/media.js'
import { adminUserRoutes } from './routes/adminUsers.js'
import { adminAdminRoutes } from './routes/adminAdmins.js'
import { healthRoutes, markReady } from './routes/health.js'
import { preferencesRoutes } from './routes/preferences.js'
import { userRoutes } from './routes/users.js'
import { announcementRoutes } from './routes/announcements.js'
import { statsRoutes } from './routes/stats.js'
import { configRoutes } from './routes/config.js'
import { internalRoutes } from './routes/internal.js'
import { adminDMRoutes } from './routes/adminDM.js'
import { searchRoutes } from './routes/search.js'
import { reportsRoutes } from './routes/reports.js'
import { userReportsRoutes, adminUserReportsRoutes } from './routes/userReports.js'
import { queueRoutes } from './routes/queue.js'
import { notificationRoutes } from './routes/notifications.js'
import { mediaCleanupService } from './services/mediaCleanup.js'
import { drainEmailQueue } from './services/emailQueue.js'
import { closeDb, cleanupExpiredSessions, initDb } from './db/index.js'
import { env } from './lib/env.js'
import { getConfig } from './lib/config.js'
import { logger } from './lib/logger.js'
import { authenticateRequest, validateCsrf } from './middleware/auth.js'
import { stopRateLimitCleanup } from './middleware/rateLimit.js'

export async function buildApp(): Promise<FastifyInstance> {
  const config = getConfig()
  const maxBodySize = config.server?.maxBodySize ?? 100 * 1024 * 1024
  const requestTimeout = config.server?.requestTimeoutMs ?? 8000

  const fastify = Fastify({
    logger: false,
    trustProxy: true,
    bodyLimit: maxBodySize,
    requestTimeout,
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'reqId',
    disableRequestLogging: false,
    routerOptions: {
      ignoreTrailingSlash: true,
      maxParamLength: config.server?.maxParamLength ?? 100
    }
  })

  const cookieSecret = createHmac('sha256', env.jwtSecret).update('cookie-signing').digest('hex')
  await fastify.register(cookie, {
    secret: cookieSecret,
    hook: 'onRequest',
    parseOptions: {}
  })

  const corsOrigins = env.corsOrigin.split(',').map(o => o.trim())
await fastify.register(cors, {
  origin: corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-CSRF-Token',
    'X-Request-Id',
    'X-Media-Type',
    'X-Filename',
    'X-Duration-Seconds',
    'X-Refresh-Token'
  ],
  exposedHeaders: [
    'X-Request-Id',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'Retry-After'
  ],
  maxAge: 86400
})

// Register multipart for file uploads (used by registration with report)
await fastify.register(multipart, {
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
    files: 1, // Only 1 file per request
    fields: 10, // Max 10 form fields
  },
  attachFieldsToBody: false // We'll parse manually for more control
})

fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    reply.header('X-Content-Type-Options', 'nosniff')
    reply.header('X-Frame-Options', 'DENY')
    reply.header('X-XSS-Protection', '1; mode=block')
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin')
    reply.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')

    if (env.isProd) {
      reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }

    reply.header('Cache-Control', 'no-store')
    reply.header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; media-src 'self' blob: https:; connect-src 'self' wss: https:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")
  })

  // Register health BEFORE the auth hook so load-balancers never get 401 (#2)
  await fastify.register(healthRoutes)

  // sw.js must NOT get Cache-Control: no-store — the browser's SW registry
  // uses its own update algorithm (checks every 24 h or on navigation).
  // We serve it with no-cache so the browser always revalidates but can still
  // use a cached copy while offline. This must be registered BEFORE the global
  // security-headers hook which sets no-store on everything else.
  fastify.get('/sw.js', async (_req: FastifyRequest, reply: FastifyReply) => {
    reply
      .header('Content-Type', 'application/javascript; charset=utf-8')
      .header('Cache-Control', 'no-cache')
      .header('Service-Worker-Allowed', '/')
    // In production the frontend is served by a separate static host.
    // This route only matters when the backend itself serves the frontend
    // (e.g. a single-dyno PaaS setup). If the file is missing we return 404
    // rather than crashing so the health check stays green.
    const fs = await import('node:fs/promises')
    const path = await import('node:path')
    const swPath = path.join(process.cwd(), 'public', 'sw.js')
    try {
      const content = await fs.readFile(swPath, 'utf-8')
      return reply.send(content)
    } catch {
      return reply.code(404).send('Service worker not found')
    }
  })

  fastify.addHook('onRequest', authenticateRequest)

  const CSRF_EXEMPT_PREFIXES = ['/api/auth/login', '/api/auth/register', '/api/auth/password/forgot', '/api/auth/password/reset', '/api/auth/refresh', '/api/announcements/public']

  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      const isExempt = CSRF_EXEMPT_PREFIXES.some(p => request.url.startsWith(p))

      if (request.user && !isExempt && !validateCsrf(request)) {
        reply.code(403).send({
          success: false,
          error: { code: 'CSRF_ERROR', message: 'Invalid CSRF token' }
        })
        return
      }
    }
  })

  fastify.addHook('onRequest', async (request: FastifyRequest, _reply: FastifyReply) => {
    request.log.info({
      method: request.method,
      url: request.url,
      ip: request.ip,
      userAgent: request.headers['user-agent']
    }, 'Incoming request')
  })

  fastify.addHook('onResponse', async (request: FastifyRequest, reply: FastifyReply) => {
    const responseTime = reply.elapsedTime
    request.log.info({
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime
    }, 'Request completed')
  })

  fastify.addHook('onError', async (request: FastifyRequest, _reply: FastifyReply, error: Error) => {
    request.log.error({
      error: error.message,
      stack: error.stack,
      method: request.method,
      url: request.url
    }, 'Request error')
  })

  const ALLOWED_CONTENT_TYPES = [
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'application/octet-stream'
  ]

  // Dedicated JSON parser with configurable limit to prevent event-loop blocking
  // NOTE: Must use parseAs:'buffer' (not 'string') so Node decodes as UTF-8,
  // preserving multi-byte characters like emoji. Using 'string' defaults to
  // latin1 and corrupts any emoji before JSON.parse runs.
  fastify.addContentTypeParser('application/json', { parseAs: 'buffer', bodyLimit: config.server?.jsonBodyLimit ?? 1048576 }, (request: FastifyRequest, body: Buffer, done: (err: Error | null, body?: unknown) => void) => {
    try {
      done(null, JSON.parse(body.toString('utf-8')))
    } catch {
      const err = new Error('Invalid JSON body') as Error & { statusCode: number }
      err.statusCode = 400
      done(err)
    }
  })

  // Catch-all parser for binary media and form data (respects global 100MB limit from maxBodySize)
  fastify.addContentTypeParser('*', { parseAs: 'buffer' }, (request: FastifyRequest, body: Buffer, done: (err: Error | null, body?: unknown) => void) => {
    const contentType = request.headers['content-type']?.split(';')[0]?.trim() || ''
    const isBinaryMedia = /^(image|video|application)\//.test(contentType)

    if (!ALLOWED_CONTENT_TYPES.includes(contentType) && !isBinaryMedia) {
      const err = new Error(`Unsupported content type: ${contentType}`) as Error & { statusCode: number }
      err.statusCode = 415
      done(err)
      return
    }

    // Form-encoded bodies: parse key=value pairs into a plain object (#E)
    if (contentType === 'application/x-www-form-urlencoded') {
      try {
        const params = new URLSearchParams(body.toString('utf-8'))
        const obj: Record<string, string> = {}
        params.forEach((value, key) => { obj[key] = value })
        done(null, obj)
      } catch {
        const err = new Error('Invalid form body') as Error & { statusCode: number }
        err.statusCode = 400
        done(err)
      }
      return
    }

    // Pass raw Buffer for media uploads
    done(null, body)
  })

await fastify.register(authRoutes, { prefix: '/api/auth' })
await fastify.register(conversationRoutes, { prefix: '/api/conversations' })
  await fastify.register(messageRoutes, { prefix: '/api/messages' })
  await fastify.register(reactionRoutes, { prefix: '/api/messages' })
  await fastify.register(mediaRoutes, { prefix: '/api/media' })
  await fastify.register(adminUserRoutes, { prefix: '/api/admin' })
  await fastify.register(adminAdminRoutes, { prefix: '/api/admin' })
  await fastify.register(preferencesRoutes, { prefix: '/api/preferences' })
  await fastify.register(userRoutes, { prefix: '/api/users' })
  await fastify.register(announcementRoutes, { prefix: '/api/announcements' })
  await fastify.register(statsRoutes, { prefix: '/api/admin/stats' })
  await fastify.register(configRoutes, { prefix: '/api/config' })
  await fastify.register(internalRoutes, { prefix: '/api/admin/internal' })
  await fastify.register(adminDMRoutes, { prefix: '/api/admin' })
  await fastify.register(searchRoutes, { prefix: '/api/admin' })
  await fastify.register(reportsRoutes, { prefix: '/api/admin/reports' })
  await fastify.register(userReportsRoutes, { prefix: '/api/user-reports' })
  await fastify.register(adminUserReportsRoutes, { prefix: '/api/admin/user-reports' })
  await fastify.register(queueRoutes, { prefix: '/api/admin' })
  await fastify.register(notificationRoutes, { prefix: '/api/notifications' })
  // healthRoutes registered earlier (before auth hook)

  fastify.setNotFoundHandler((request: FastifyRequest, reply: FastifyReply) => {
    reply.code(404).send({
      success: false,
      error: { code: 'NOT_FOUND', message: 'Route not found' }
    })
  })

  fastify.setErrorHandler((error: Error, request: FastifyRequest, reply: FastifyReply) => {
    if (error.name === 'FastifyError') {
      const statusCode = (error as unknown as { statusCode?: number }).statusCode || 500
      reply.code(statusCode).send({
        success: false,
        error: { code: 'REQUEST_ERROR', message: error.message }
      })
      return
    }

    request.log.error({ error: error.message, stack: error.stack }, 'Unhandled error')
    reply.code(500).send({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    })
  })

  return fastify
}

export async function startServer(): Promise<FastifyInstance> {
  const config = getConfig()
  const statsLogIntervalMs = config.server?.statsLogIntervalMs ?? 60000

  serverState.init()

  // Ensure DB is up and PRAGMAs are applied before any request is served
  await initDb()

  const fastify = await buildApp()

  const address = await fastify.listen({ port: env.port, host: env.host })
  logger.info({ address, env: env.nodeEnv }, 'Server started')
  markReady()

  const httpServer = fastify.server
  initSocket(httpServer)

  mediaCleanupService.start()

  // Distributed lock: only one instance runs periodic cleanup at a time.
  // Prevents N instances from doing redundant work simultaneously.
  const INSTANCE_ID = `instance-${process.pid}-${Date.now()}`

  async function tryAcquireLock(key: string, ttlSeconds: number): Promise<boolean> {
    const redis = (await import('./redis.js')).getRedis()
    if (!redis) return true // No Redis = single-instance mode, always run
    try {
      const acquired = await redis.set(key, INSTANCE_ID, 'EX', ttlSeconds, 'NX')
      return acquired === 'OK'
    } catch {
      return true // Redis error = fall back to running locally
    }
  }

  const sessionCleanupInterval = setInterval(async () => {
    try {
      const lockTtl = Math.ceil(config.presence.sessionDbCleanupIntervalMs / 1000) + 30
      const hasLock = await tryAcquireLock('lock:session-cleanup', lockTtl)
      if (!hasLock) return // Another instance is handling it
      const result = await cleanupExpiredSessions()
      if (result.cleaned > 0) {
        logger.info({ cleaned: result.cleaned, usersAffected: result.expiredByUser.size }, 'Expired sessions cleaned')
        const io = getIO()
        if (io) {
          for (const [userId, sessionIds] of result.expiredByUser) {
            io.to(`user:${userId}`).emit('session:expired', { sessionIds })
          }
        }
      }
    } catch (error) {
      logger.error({ error }, 'Session cleanup failed')
    }
  }, config.presence.sessionDbCleanupIntervalMs)

  // Media cleanup: also use distributed lock
  const origMediaCleanupStart = mediaCleanupService.start.bind(mediaCleanupService)
  mediaCleanupService.start = async function() {
    const lockTtl = 3600 // 1 hour lock
    const hasLock = await tryAcquireLock('lock:media-cleanup', lockTtl)
    if (!hasLock) return // Another instance holds the lock
    return origMediaCleanupStart()
  }

  let statsInterval: NodeJS.Timeout | undefined

  statsInterval = setInterval(() => {
    const stats = serverState.getStats()
    const memUsage = process.memoryUsage()

    logger.debug({
      stats,
      memory: {
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
        rss: Math.round(memUsage.rss / 1024 / 1024)
      }
    }, 'Server stats')
  }, statsLogIntervalMs)

  const gracefulShutdown = async (signal: string) => {
    logger.info({ signal }, 'Starting graceful shutdown')

    const shutdownTimeoutMs = config.server?.shutdownTimeoutMs ?? 10000
    const shutdownTimeout = setTimeout(() => {
      logger.warn('Forcing shutdown after timeout')
      process.exit(1)
    }, shutdownTimeoutMs)

    try {
      mediaCleanupService.stop()
      clearInterval(sessionCleanupInterval)
      if (statsInterval) clearInterval(statsInterval)
      stopStreamRateLimitCleanup()
      stopRateLimitCleanup()
      await drainEmailQueue(3000)
      serverState.stop()

      await closeIO()

      // Close Redis connection gracefully
      const { closeRedis } = await import('./redis.js')
      await closeRedis()

      await fastify.close()
      await closeDb()

      clearTimeout(shutdownTimeout)
      logger.info('Graceful shutdown complete')
      process.exit(0)
    } catch (error) {
      logger.error({ error }, 'Error during shutdown')
      process.exit(1)
    }
  }

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
  process.on('SIGINT', () => gracefulShutdown('SIGINT'))

  process.on('uncaughtException', (error) => {
    logger.fatal({ error: error.message, stack: error.stack }, 'Uncaught exception')
    gracefulShutdown('uncaughtException')
  })

  // Transient infrastructure failures (Redis reconnecting, DB stream expiry)
  // should NOT crash the entire server — they have their own fallback paths.
  const TRANSIENT_ERROR_PATTERNS = [
    'MaxRetriesPerRequestError',
    'ETIMEDOUT',
    'ECONNREFUSED',
    'ECONNRESET',
    'STREAM_EXPIRED',
    'stream has expired',
    'WebSocket was closed',
    'SERVER_ERROR',
    '503',
  ]

  function isTransientError(reason: unknown): boolean {
    if (reason instanceof Error) {
      return TRANSIENT_ERROR_PATTERNS.some(p =>
        reason.message.includes(p) || reason.name.includes(p)
      )
    }
    if (typeof reason === 'string') {
      return TRANSIENT_ERROR_PATTERNS.some(p => reason.includes(p))
    }
    return false
  }

  process.on('unhandledRejection', (reason) => {
    if (isTransientError(reason)) {
      logger.warn({
        reason: reason instanceof Error ? { message: reason.message, stack: reason.stack } : reason,
        type: typeof reason
      }, 'Unhandled transient rejection — not shutting down (has fallback path)')
      return
    }
    logger.fatal({
      reason: reason instanceof Error ? { message: reason.message, stack: reason.stack } : reason,
      type: typeof reason
    }, 'Unhandled rejection')
    gracefulShutdown('unhandledRejection')
  })

  return fastify
}
