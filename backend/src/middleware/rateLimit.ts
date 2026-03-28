import type { FastifyRequest, FastifyReply } from 'fastify'
import { LRUCache } from 'lru-cache'
import { getConfig } from '../lib/config.js'
import { logger } from '../lib/logger.js'
import { getRedis } from '../redis.js'

// BOUNDED RATE LIMITING - Total 10MB budget across all stores
// Each store: 1MB, ~20,000 entries

interface RateLimitEntry {
  count: number
  resetAt: number
}

interface LoginAttempt {
  attempts: number
  firstAttemptAt: number
  lockedUntil: number | null
}

// LRU-based Rate Limit Store - uses config for sizes
class RateLimitStore {
  private store: LRUCache<string, RateLimitEntry>
  private name: string

  constructor(name: string) {
    this.name = name
    const cfg = getConfig().rateLimit.store
    this.store = new LRUCache({
      max: cfg?.maxEntries ?? 20000,
      maxSize: cfg?.maxSizeBytes ?? 1048576,
      sizeCalculation: () => 50,
      allowStale: false,
      updateAgeOnGet: false,
      dispose: (value, key) => {
        logger.debug({ name, key }, 'Rate limit entry evicted')
      }
    })
  }

  async increment(key: string, windowMs: number, maxRequests: number): Promise<{ count: number; resetAt: number; blocked: boolean }> {
    const now = Date.now()
    const resetAt = now + windowMs

    const redis = getRedis()
    if (redis) {
       try {
         const redisKey = `ratelimit:${this.name}:${key}`
         // Atomic INCR and EXPIRE pipeline if key didn't exist
         const currentStr = await redis.incr(redisKey)
         if (currentStr === 1) {
           await redis.pexpire(redisKey, windowMs)
         }
         const blocked = currentStr > maxRequests
         return { count: currentStr, resetAt, blocked }
       } catch (err) {
         logger.warn({ err: err instanceof Error ? err.message : String(err) }, 'Redis Rate Limit increment failed, falling back to local memory')
       }
    }

    const entry = this.store.get(key)

    if (!entry || entry.resetAt <= now || entry.resetAt > now + windowMs) {
      this.store.set(key, { count: 1, resetAt })
      return { count: 1, resetAt, blocked: false }
    }

    entry.count++
    this.store.set(key, entry) // Update LRU position
    const blocked = entry.count > maxRequests
    return { count: entry.count, resetAt: entry.resetAt, blocked }
  }

  async reset(key: string): Promise<void> {
    const redis = getRedis()
    if (redis) await redis.del(`ratelimit:${this.name}:${key}`).catch(() => {})
    this.store.delete(key)
  }

  async stop(): Promise<void> {
    this.store.clear()
  }

  getStats(): { size: number; max: number } {
    return { size: this.store.size, max: this.store.max }
  }
}

// LRU-based Login Lockout Store - uses config for sizes
class LoginLockoutStore {
  private attempts: LRUCache<string, LoginAttempt>

  constructor() {
    const cfg = getConfig().rateLimit.store
    this.attempts = new LRUCache({
      max: cfg?.loginLockoutMaxEntries ?? 40000,
      maxSize: cfg?.loginLockoutMaxSizeBytes ?? 2097152,
      sizeCalculation: () => 50,
      allowStale: false,
      updateAgeOnGet: false
    })
  }

  async recordAttempt(ip: string, success: boolean): Promise<void> {
    const now = Date.now()
    const config = getConfig()
    const windowMs = config.rateLimit.login.windowMinutes * 60 * 1000
    const lockoutMs = config.rateLimit.login.lockoutMinutes * 60 * 1000

    const redis = getRedis()
    if (redis) {
       try {
         const attemptsKey = `login_attempts:${ip}`
         const lockoutKey = `login_lockout:${ip}`

         if (success) {
           await redis.del(attemptsKey, lockoutKey)
           this.attempts.delete(ip)
           return
         }

         const isLocked = await redis.exists(lockoutKey)
         if (isLocked) return

         const attempts = await redis.incr(attemptsKey)
         if (attempts === 1) {
            await redis.pexpire(attemptsKey, windowMs)
         }

         if (attempts >= config.rateLimit.login.maxAttempts) {
            await redis.set(lockoutKey, '1', 'PX', lockoutMs)
         }
         return
       } catch (err) {
         logger.warn({ err: err instanceof Error ? err.message : String(err) }, 'Redis Login Lockout recording failed, falling back to local memory')
       }
    }

    const entry = this.attempts.get(ip)

    if (!entry || entry.firstAttemptAt + windowMs <= now || entry.firstAttemptAt > now) {
      if (success) {
        this.attempts.delete(ip)
        return
      }
      this.attempts.set(ip, {
        attempts: 1,
        firstAttemptAt: now,
        lockedUntil: null
      })
      return
    }

    if (success) {
      this.attempts.delete(ip)
      return
    }

    entry.attempts++
    this.attempts.set(ip, entry) // Update LRU position

    if (entry.attempts >= config.rateLimit.login.maxAttempts && !entry.lockedUntil) {
      entry.lockedUntil = now + lockoutMs
      this.attempts.set(ip, entry)
    }
  }

  async checkLockout(ip: string): Promise<{ locked: boolean; retryAfter?: number }> {
    const redis = getRedis()
    if (redis) {
      try {
        const pttl = await redis.pttl(`login_lockout:${ip}`)
        if (pttl > 0) return { locked: true, retryAfter: Math.ceil(pttl / 1000) }
        return { locked: false }
      } catch (err) {
        logger.warn('Redis Login Lockout check failed')
      }
    }

    const entry = this.attempts.get(ip)
    if (!entry || !entry.lockedUntil) {
      return { locked: false }
    }

    const now = Date.now()
    const config = getConfig()
    const configuredLockoutMs = config.rateLimit.login.lockoutMinutes * 60 * 1000

    // If the configured timeout shrank dynamically, existing locks might be floating too far in the future
    if (entry.lockedUntil > now && entry.lockedUntil <= now + configuredLockoutMs) {
      return { locked: true, retryAfter: Math.ceil((entry.lockedUntil - now) / 1000) }
    }

    this.attempts.delete(ip)
    return { locked: false }
  }

  async stop(): Promise<void> {
    this.attempts.clear()
  }

  getStats(): { size: number; max: number } {
    return { size: this.attempts.size, max: this.attempts.max }
  }
}

// Store instances - Total ~10MB
const apiStore = new RateLimitStore('api')
const loginStore = new RateLimitStore('login')
const registrationStore = new RateLimitStore('registration')
const passwordResetStore = new RateLimitStore('passwordReset')
const passwordChangeStore = new RateLimitStore('passwordChange')
const mediaUploadStore = new RateLimitStore('mediaUpload')
const messageMinuteStore = new RateLimitStore('messageMinute')
const messageHourStore = new RateLimitStore('messageHour')
const reportCreateStore = new RateLimitStore('reportCreate')
const voteStore = new RateLimitStore('vote')
const adminPasswordResetStore = new RateLimitStore('adminPasswordReset')
const loginLockoutStore = new LoginLockoutStore()

export async function checkLoginLockout(ip: string): Promise<{ locked: boolean; retryAfter?: number }> {
  return loginLockoutStore.checkLockout(ip)
}

export async function recordLoginAttempt(ip: string, success: boolean): Promise<void> {
  await loginLockoutStore.recordAttempt(ip, success)
}

// MEDIUM FIX: Get IP with validation to prevent spoofing
// In production behind a proxy, trust proxy settings should be configured in Fastify
function getClientIp(req: FastifyRequest): string {
  // Use req.ip (respects Fastify trust proxy settings)
  const ip = req.ip

  // Validate IP format (IPv4 or IPv6)
  const isValidIp = ip && (
    // IPv4
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) ||
    // IPv6 (basic check)
    /^[0-9a-fA-F:]+$/.test(ip)
  )

  if (isValidIp && ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
    return ip
  }

  // Fallback for local development
  const fallbackIp = req.socket?.remoteAddress
  if (fallbackIp && (fallbackIp !== '127.0.0.1' && fallbackIp !== '::1')) {
    return fallbackIp
  }

  return 'unknown'
}

function createRateLimiter(
  store: RateLimitStore,
  configGetter: () => { windowMs: number; maxRequests: number },
  keyFn: (req: FastifyRequest) => string = (req) => getClientIp(req)
) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const key = keyFn(request)
    const { windowMs, maxRequests } = configGetter()
    const { count, resetAt, blocked } = await store.increment(key, windowMs, maxRequests)

    reply.header('X-RateLimit-Limit', maxRequests.toString())
    reply.header('X-RateLimit-Remaining', Math.max(0, maxRequests - count).toString())
    reply.header('X-RateLimit-Reset', new Date(resetAt).toISOString())

    if (blocked) {
      const retryAfter = Math.ceil((resetAt - Date.now()) / 1000)
      reply.header('Retry-After', retryAfter.toString())
      reply.code(429).send({
        success: false,
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests, please try again later',
          retryAfter
        }
      })
      return
    }
  }
}

export interface RateLimiters {
  api: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  login: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  registration: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  passwordReset: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  passwordChange: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  mediaUpload: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  message: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  reportCreate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  vote: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  adminPasswordReset: (req: FastifyRequest, reply: FastifyReply) => Promise<void>
  socketMessage: (userId: string) => Promise<boolean>
}

export function createRateLimiters(): RateLimiters {
  const messageRateLimiter = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const config = getConfig()
    const role = request.user?.role
    if (role === 'ADMIN' || role === 'SUPER_ADMIN') return
    const key = request.user?.id ?? request.ip
    const [minuteResult, hourResult] = await Promise.all([
      messageMinuteStore.increment(key, 60 * 1000, config.limits.message.perMinute),
      messageHourStore.increment(key, 60 * 60 * 1000, config.limits.message.perHour)
    ])

    reply.header('X-RateLimit-Limit', `${config.limits.message.perMinute}/min, ${config.limits.message.perHour}/hour`)
    reply.header('X-RateLimit-Remaining', Math.max(0, config.limits.message.perMinute - minuteResult.count).toString())
    reply.header('X-RateLimit-Reset', new Date(minuteResult.resetAt).toISOString())

    const blocked = minuteResult.blocked || hourResult.blocked
    if (blocked) {
      const retryAfter = Math.ceil((Math.max(minuteResult.resetAt, hourResult.resetAt) - Date.now()) / 1000)
      reply.header('Retry-After', retryAfter.toString())
      reply.code(429).send({
        success: false,
        error: {
          code: 'RATE_LIMITED',
          message: 'Message rate limit exceeded',
          retryAfter
        }
      })
      return
    }
  }

  return {
    api: createRateLimiter(apiStore, () => {
      const cfg = getConfig().rateLimit.api
      return { windowMs: 60 * 1000, maxRequests: cfg.requestsPerMinute }
    }),
    login: createRateLimiter(loginStore, () => {
      const cfg = getConfig().rateLimit.login
      return { windowMs: cfg.windowMinutes * 60 * 1000, maxRequests: cfg.maxAttempts }
    }),
    registration: createRateLimiter(registrationStore, () => {
      const cfg = getConfig().rateLimit.registration
      return { windowMs: cfg.windowHours * 60 * 60 * 1000, maxRequests: cfg.maxAttempts }
    }),
    passwordReset: createRateLimiter(passwordResetStore, () => {
      const cfg = getConfig().rateLimit.passwordReset
      return { windowMs: cfg.windowMinutes * 60 * 1000, maxRequests: cfg.maxAttempts }
    }),
    passwordChange: createRateLimiter(passwordChangeStore, () => {
      const cfg = getConfig().rateLimit.passwordChange
      return { windowMs: cfg.windowMinutes * 60 * 1000, maxRequests: cfg.maxAttempts }
    }),
    mediaUpload: createRateLimiter(mediaUploadStore, () => {
      // Use API rate limit for media uploads
      const cfg = getConfig().rateLimit.api
      return { windowMs: 60 * 1000, maxRequests: cfg.requestsPerMinute }
    }, (req) => req.user?.id ?? req.ip),
    message: messageRateLimiter,
    // HIGH FIX: Add rate limiting for report creation (10 per hour per user)
    reportCreate: createRateLimiter(reportCreateStore, () => ({
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 10
    }), (req) => req.user?.id ?? req.ip),
    // HIGH FIX: Add rate limiting for votes (10 per minute per user per announcement)
    vote: createRateLimiter(voteStore, () => ({
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 10
    }), (req) => req.user?.id ?? req.ip),
    // MEDIUM FIX: Add rate limiting for admin password reset (5 per hour per admin)
    adminPasswordReset: createRateLimiter(adminPasswordResetStore, () => ({
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 5
    }), (req) => req.user?.id ?? req.ip),
    socketMessage: async (userId: string) => {
      const config = getConfig()
      const [minuteResult, hourResult] = await Promise.all([
        messageMinuteStore.increment(userId, 60 * 1000, config.limits.message.perMinute),
        messageHourStore.increment(userId, 60 * 60 * 1000, config.limits.message.perHour)
      ])
      return !minuteResult.blocked && !hourResult.blocked
    }
  }
}

export function stopRateLimitCleanup(): void {
  // No-op - LRU caches auto-manage
  apiStore.stop()
  loginStore.stop()
  registrationStore.stop()
  passwordResetStore.stop()
  passwordChangeStore.stop()
  mediaUploadStore.stop()
  messageMinuteStore.stop()
  messageHourStore.stop()
  reportCreateStore.stop()
  voteStore.stop()
  adminPasswordResetStore.stop()
  loginLockoutStore.stop()
}

// Export store stats for monitoring
export function getRateLimitStats(): object {
  return {
    api: apiStore.getStats(),
    login: loginStore.getStats(),
    registration: registrationStore.getStats(),
    passwordReset: passwordResetStore.getStats(),
    passwordChange: passwordChangeStore.getStats(),
    mediaUpload: mediaUploadStore.getStats(),
    messageMinute: messageMinuteStore.getStats(),
    messageHour: messageHourStore.getStats(),
    reportCreate: reportCreateStore.getStats(),
    vote: voteStore.getStats(),
    adminPasswordReset: adminPasswordResetStore.getStats(),
    loginLockout: loginLockoutStore.getStats()
  }
}
