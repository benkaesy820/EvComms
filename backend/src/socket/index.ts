import { Server as HttpServer } from 'http'
import { Server, Socket } from 'socket.io'
import jwt from 'jsonwebtoken'
import { ulid } from 'ulid'
import { eq, and, isNull, gt, ne, sql } from 'drizzle-orm'
import { db } from '../db/index.js'
import { users, messages, conversations, auditLogs, sessions, media, internalMessages, announcements } from '../db/schema.js'
import { env } from '../lib/env.js'
import { getConfig, getCacheConfig, getSessionConfig } from '../lib/config.js'
import { clusterBus, serverState, addUserToCache, getUserFromCache, removeUserFromCache, getUserConversationId, touchConversationOwner, invalidateSessionCache, getSessionValidationCache, setSessionValidationCache } from '../state.js'
import { logger } from '../lib/logger.js'
import { createAdapter } from '@socket.io/redis-adapter'
import { getRedis } from '../redis.js'
import { canUploadMedia, isAdmin, canAccessConversation } from '../lib/permissions.js'
import {
  socketMessageSchema,
  socketPresenceSchema,
  socketInternalMessageSchema,
  socketTypingSchema,
  socketMarkReadSchema,
  socketDMTypingSchema,
  SocketMessageInput,
  SocketPresenceInput,
  SocketTypingInput,
  SocketMarkReadInput,
  SocketDMTypingInput
} from '../lib/socketSchemas.js'
import { sanitizeText } from '../lib/utils.js'
import { queueEmailNotification } from '../services/emailQueue.js'
import { sendPushToUser } from '../lib/webPush.js'

interface DecodedToken {
  sub: string
  email: string
  role: 'USER' | 'ADMIN' | 'SUPER_ADMIN'
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'SUSPENDED'
  sid: string
  exp: number
  iat: number
}

interface AuthError {
  message: string
  code: string
}

interface SocketUser {
  id: string
  email: string
  role: 'USER' | 'ADMIN' | 'SUPER_ADMIN'
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'SUSPENDED'
  sessionId: string
  mediaPermission?: boolean
}

interface SocketRateLimitEntry {
  minuteCount: number
  minuteResetAt: number
  hourCount: number
  hourResetAt: number
}

interface SocketAuthAttemptEntry {
  count: number
  resetAt: number
}

import { LRUCache } from 'lru-cache'

function getConnectionRateConfig() {
  const cfg = getConfig().socket
  return {
    maxPerIp: cfg.maxConnectionsPerIp ?? 10,
    windowMs: cfg.connectionWindowMs ?? 60000
  }
}

// BOUNDED SOCKET RATE LIMITERS - use config for sizes
const cacheConfig = getCacheConfig()

const socketRateLimiters = new LRUCache<string, SocketRateLimitEntry>({
  max: cacheConfig.maxSocketRateLimiters,
  allowStale: false,
  updateAgeOnGet: false
})

const socketAuthAttempts = new LRUCache<string, SocketAuthAttemptEntry>({
  max: cacheConfig.maxSocketRateLimiters,
  allowStale: false,
  updateAgeOnGet: false
})

const connectionAttempts = new LRUCache<string, { count: number; resetAt: number }>({
  max: cacheConfig.maxSocketRateLimiters,
  allowStale: false,
  updateAgeOnGet: false
})

class SocketValidationError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message)
    this.name = 'SocketValidationError'
  }
}

function checkSocketRateLimit(userId: string, maxPerMinute: number, maxPerHour: number): boolean {
  const now = Date.now()
  const minuteWindowMs = 60 * 1000
  const hourWindowMs = 60 * 60 * 1000

  const entry = socketRateLimiters.get(userId)

  if (!entry || entry.hourResetAt <= now) {
    // No entry or hour window fully expired — start fresh
    socketRateLimiters.set(userId, {
      minuteCount: 1,
      minuteResetAt: now + minuteWindowMs,
      hourCount: 1,
      hourResetAt: now + hourWindowMs
    })
    return true
  }

  // Minute window rolled over but hour window is still active — reset minute counter only,
  // keeping the accumulated hour count intact so the hourly budget is not silently wiped.
  const minuteExpired = entry.minuteResetAt <= now
  const currentMinuteCount = minuteExpired ? 1 : entry.minuteCount + 1
  const currentMinuteReset = minuteExpired ? now + minuteWindowMs : entry.minuteResetAt
  const currentHourCount = entry.hourCount + 1

  if (currentMinuteCount > maxPerMinute || currentHourCount > maxPerHour) {
    return false
  }

  socketRateLimiters.set(userId, {
    minuteCount: currentMinuteCount,
    minuteResetAt: currentMinuteReset,
    hourCount: currentHourCount,
    hourResetAt: entry.hourResetAt
  })
  return true
}

function getSocketClientIp(socket: Socket): string {
  const forwarded = socket.handshake.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const ips = forwarded.split(',').map(ip => ip.trim()).filter(Boolean)
    if (ips.length > 0) {
      return ips[0] || socket.handshake.address || 'unknown'
    }
  }

  if (Array.isArray(forwarded) && forwarded.length > 0) {
    const firstIp = forwarded[0]
    return firstIp ? firstIp.trim() : socket.handshake.address || 'unknown'
  }

  return socket.handshake.address || 'unknown'
}

function getSocketAuthTokenFromCookie(socket: Socket): string | null {
  const cookieHeader = socket.handshake.headers.cookie
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return null
  }

  const tokenPair = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('token='))

  if (!tokenPair) {
    return null
  }

  const rawToken = tokenPair.slice('token='.length)
  if (!rawToken) {
    return null
  }

  try {
    return decodeURIComponent(rawToken)
  } catch {
    return rawToken
  }
}

function isSocketAuthRateLimited(ip: string): boolean {
  const now = Date.now()
  const config = getConfig()

  const entry = socketAuthAttempts.get(ip)
  if (!entry || entry.resetAt <= now) {
    return false
  }

  return entry.count >= config.socket.authMaxAttempts
}

function recordSocketAuthAttempt(ip: string, success: boolean): void {
  const now = Date.now()
  const config = getConfig()

  if (success) {
    socketAuthAttempts.delete(ip)
    return
  }

  const entry = socketAuthAttempts.get(ip)
  if (!entry || entry.resetAt <= now) {
    socketAuthAttempts.set(ip, {
      count: 1,
      resetAt: now + config.socket.authWindowMs
    })
    return
  }

  socketAuthAttempts.set(ip, { count: entry.count + 1, resetAt: entry.resetAt })
}

function checkConnectionRateLimit(ip: string): boolean {
  const now = Date.now()
  const { maxPerIp, windowMs } = getConnectionRateConfig()

  const entry = connectionAttempts.get(ip)
  if (!entry || entry.resetAt <= now) {
    connectionAttempts.set(ip, { count: 1, resetAt: now + windowMs })
    return true
  }

  if (entry.count >= maxPerIp) {
    return false
  }

  connectionAttempts.set(ip, { count: entry.count + 1, resetAt: entry.resetAt })
  return true
}

let io: Server | null = null

export function initSocket(httpServer: HttpServer): Server {
  if (io) return io

  const config = getConfig()
  const corsOrigins = env.corsOrigin.split(',').map(o => o.trim())

  io = new Server(httpServer, {
    cors: {
      origin: corsOrigins,
      credentials: true,
      methods: ['GET', 'POST']
    },
    pingTimeout: config.socket.pingTimeoutMs,
    pingInterval: config.socket.pingIntervalMs,
    maxHttpBufferSize: 1e6,
    connectTimeout: config.socket.authWindowMs
  })

  const redisClient = getRedis()
  if (redisClient) {
    const subClient = redisClient.duplicate()
    subClient.on('error', (err) => {
      logger.error({ err: err.message }, 'Redis subClient error')
    })
    io.adapter(createAdapter(redisClient, subClient))
    logger.info('Socket.IO successfully bridged to Upstash Redis Adapter')

    // --------------------------------------------------------------------------
    // CLUSTER CACHE SYNCHRONIZATION
    // --------------------------------------------------------------------------
    // 1. Broadcast Local Mutations to Cluster
    clusterBus.on('cache:update_user', (payload) => io?.serverSideEmit('cache:update_user', payload))
    clusterBus.on('cache:remove_user', (payload) => io?.serverSideEmit('cache:remove_user', payload))
    clusterBus.on('cache:invalidate_status', (payload) => io?.serverSideEmit('cache:invalidate_status', payload))
    clusterBus.on('cache:invalidate_session', (payload) => io?.serverSideEmit('cache:invalidate_session', payload))
    clusterBus.on('cache:invalidate_all_sessions', (payload) => io?.serverSideEmit('cache:invalidate_all_sessions', payload))

    // 2. Receive Cluster Mutations (apply locally without re-emitting to prevent loops)
    io.on('cache:update_user', (payload: any) => serverState.updateUserCache(payload.userId, payload.updates, false))
    io.on('cache:remove_user', (payload: any) => serverState.removeUserFromCache(payload.userId, false))
    io.on('cache:invalidate_status', (payload: any) => serverState.invalidateUsersByStatus(payload.status, false))
    io.on('cache:invalidate_session', (payload: any) => serverState.invalidateSessionCache(payload.userId, payload.sessionId, false))
    io.on('cache:invalidate_all_sessions', (payload: any) => serverState.invalidateAllUserSessions(payload.userId, false))
    
    // 3. Respond to multi-pod presence snapshots
    io.on('presence:snapshot_request', (cb) => {
      if (typeof cb === 'function') {
        cb(Array.from(serverState.connectedUsers.keys()))
      }
    })
  }

  io.use((socket, next) => {
    const clientIp = getSocketClientIp(socket)
    if (!checkConnectionRateLimit(clientIp)) {
      logger.warn({ ip: clientIp }, 'Socket connection rate limited')
      return next(new Error('CONNECTION_RATE_LIMITED'))
    }
    next()
  })

  io.use(async (socket, next) => {
    try {
      await authenticateSocket(socket)
      next()
    } catch (err) {
      const authError = err as AuthError
      logger.warn({ reason: authError.message }, 'Socket auth failed')
      next(new Error(authError.code || 'AUTH_FAILED'))
    }
  })

  io.on('connection', (socket) => {
    handleConnection(socket)
  })

  logger.info('Socket.IO server initialized')
  return io
}

async function authenticateSocket(socket: Socket): Promise<void> {
  const clientIp = getSocketClientIp(socket)

  if (isSocketAuthRateLimited(clientIp)) {
    throw { message: 'Too many authentication attempts', code: 'AUTH_RATE_LIMITED' } as AuthError
  }

  try {
    let token = getSocketAuthTokenFromCookie(socket)

    if (!token && socket.handshake.auth?.token) {
      token = socket.handshake.auth.token
    }

    if (!token) {
      throw { message: 'No token provided', code: 'NO_TOKEN' } as AuthError
    }

    let decoded: DecodedToken
    try {
      decoded = jwt.verify(token, env.jwtSecret, {
        issuer: env.jwtIssuer,
        audience: env.jwtAudience
      }) as DecodedToken
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        throw { message: 'Token expired', code: 'TOKEN_EXPIRED' } as AuthError
      }
      throw { message: 'Invalid token', code: 'INVALID_TOKEN' } as AuthError
    }

    if (decoded.status !== 'APPROVED') {
      throw { message: 'Account not approved', code: 'NOT_APPROVED' } as AuthError
    }

    // SHORT-CIRCUIT: If we already know from cache this session is invalid, bail immediately.
    // But ONLY skip bypass if the token isn't freshly issued — a recently issued token could
    // arrive at the socket before Turso edge replication propagates the write (race condition).
    const cachedSessionValid = getSessionValidationCache(decoded.sub, decoded.sid)
    const tokenIssuedAt = decoded.iat ? (decoded.iat as number) * 1000 : 0
    const isFreshToken = Date.now() - tokenIssuedAt < 10_000 // 10s grace for replication lag

    if (cachedSessionValid === false && !isFreshToken) {
      throw { message: 'Session invalid', code: 'SESSION_INVALID' } as AuthError
    }

    if (cachedSessionValid === undefined || (cachedSessionValid === false && isFreshToken)) {
      const sessionConfig = getSessionConfig()

      if (isFreshToken) {
        // Turso replication lag mitigation: The token was signed crypto-graphically <10s ago. 
        // It is physically impossible to forge. Bypass the DB read replica check entirely
        // to prevent connection drops while waiting for the master write to propagate.
        setSessionValidationCache(decoded.sub, decoded.sid, true, sessionConfig.validationTTLMs)
      } else {
        // Cache miss: validate against DB read replica.
        const sessionRow = await db.query.sessions.findFirst({
          where: and(
            eq(sessions.id, decoded.sid),
            eq(sessions.userId, decoded.sub),
            isNull(sessions.revokedAt),
            gt(sessions.expiresAt, new Date())
          ),
          columns: { id: true }
        })

        if (sessionRow) {
          setSessionValidationCache(decoded.sub, decoded.sid, true, sessionConfig.validationTTLMs)
        } else {
          setSessionValidationCache(decoded.sub, decoded.sid, false, sessionConfig.validationTTLMs)
          throw { message: 'Session invalid', code: 'SESSION_INVALID' } as AuthError
        }
      }
    }

    const cachedUser = getUserFromCache(decoded.sub)
    if (cachedUser) {
      // Verify token claims match cached user (prevent stale token usage after role/status change)
      if (cachedUser.status !== decoded.status || cachedUser.role !== decoded.role) {
        throw { message: 'Token stale', code: 'TOKEN_STALE' } as AuthError
      }
    } else {
      const user = await db.query.users.findFirst({
        where: eq(users.id, decoded.sub),
        columns: {
          id: true,
          email: true,
          role: true,
          status: true,
          name: true,
          mediaPermission: true,
          emailNotifyOnMessage: true,
          subsidiaryIds: true,
        }
      })

      if (!user) {
        throw { message: 'User not found', code: 'USER_NOT_FOUND' } as AuthError
      }

      // Verify token claims match database (prevent stale token usage)
      if (user.status !== decoded.status || user.role !== decoded.role) {
        throw { message: 'Token stale', code: 'TOKEN_STALE' } as AuthError
      }

      addUserToCache(user.id, {
        role: user.role,
        status: user.status,
        name: user.name,
        mediaPermission: user.mediaPermission ?? false,
        emailNotifyOnMessage: user.emailNotifyOnMessage ?? true,
        subsidiaryIds: user.subsidiaryIds ?? null,
      })
    }

    socket.data.user = {
      id: decoded.sub,
      email: decoded.email,
      role: decoded.role,
      status: decoded.status,
      sessionId: decoded.sid
    }

    socket.join(`user:${decoded.sub}`)
    socket.join(`session:${decoded.sid}`)

    if (isAdmin({ role: decoded.role })) {
      socket.join('admins')
      if (decoded.role === 'SUPER_ADMIN') {
        socket.join('super_admins')
      }
    } else {
      socket.join('users')
    }

    recordSocketAuthAttempt(clientIp, true)
  } catch (error) {
    recordSocketAuthAttempt(clientIp, false)
    throw error
  }
}

function handleConnection(socket: Socket): void {
  const user = socket.data.user as SocketUser
  if (!user) {
    socket.disconnect(true)
    return
  }

  const config = getConfig()

  // HIGH FIX: Enforce maximum concurrent socket connections per user (10)
  const MAX_SOCKETS_PER_USER = 10
  const existingConnection = serverState.connectedUsers.get(user.id)
  const currentSocketCount = existingConnection?.socketIds.size ?? 0

  if (currentSocketCount >= MAX_SOCKETS_PER_USER) {
    logger.warn({ userId: user.id, currentSockets: currentSocketCount }, 'Max socket connections reached, rejecting new connection')
    socket.emit('error', { code: 'CONNECTION_LIMIT', message: 'Too many concurrent connections' })
    socket.disconnect(true)
    return
  }

  if (existingConnection) {
    existingConnection.socketIds.add(socket.id)
    existingConnection.lastActivity = Date.now()
  } else {
    serverState.connectedUsers.set(user.id, {
      socketIds: new Set([socket.id]),
      userId: user.id,
      connectedAt: Date.now(),
      lastActivity: Date.now()
    })
  }

  serverState.userPresence.set(user.id, {
    status: 'online',
    lastSeen: Date.now()
  })

  const cachedUser = getUserFromCache(user.id)
  if (cachedUser) {
    serverState.emailPreferences.set(user.id, cachedUser.emailNotifyOnMessage)
    serverState.userNames.set(user.id, cachedUser.name)
  }

  logger.info({ userId: user.id, socketId: socket.id }, 'User connected')

  emitToUser(user.id, 'presence:update', {
    userId: user.id,
    status: 'online'
  })

  const onlineUserCache = getUserFromCache(user.id)
  emitToAdmins('user:online', {
    userId: user.id,
    userName: onlineUserCache?.name ?? 'Unknown',
    status: 'online'
  })

  socket.on('disconnect', (reason) => {
    handleDisconnect(socket, user, reason)
  })

  socket.on('error', (err) => {
    logger.error({ userId: user.id, error: err.message }, 'Socket error')
  })

  const clientIp = getSocketClientIp(socket)

  const wrapAsyncHandler = (handler: () => Promise<void>) => {
    handler().catch((err) => {
      logger.error({ userId: user.id, error: err instanceof Error ? err.message : String(err) }, 'Async handler error')
      socket.emit('error', { code: 'INTERNAL_ERROR', message: 'Operation failed' })
    })
  }

  // HIGH FIX: Apply rate limits to ALL users including admins (higher limit for admins)
  socket.on('message:send', (data: unknown) => {
    const isUserAdmin = isAdmin({ role: user.role })
    const perMinute = isUserAdmin ? config.limits.message.perMinute * 2 : config.limits.message.perMinute
    const perHour = isUserAdmin ? config.limits.message.perHour * 2 : config.limits.message.perHour
    if (!checkSocketRateLimit(user.id, perMinute, perHour)) {
      socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many messages' })
      return
    }
    wrapAsyncHandler(() => handleMessageSend(socket, user, data, clientIp))
  })

  if (isAdmin({ role: user.role })) {
    socket.on('internal:message:send', (data: unknown) => {
      if (!checkSocketRateLimit(user.id, config.limits.message.perMinute, config.limits.message.perHour)) {
        socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many messages' })
        return
      }
      wrapAsyncHandler(() => handleInternalMessageSend(socket, user, data))
    })

    socket.on('internal:typing', (data: unknown) => {
      if (!checkSocketRateLimit(user.id, 30, 300)) {
        socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many typing updates' })
        return
      }
      const parsed = (typeof data === 'object' && data !== null && 'isTyping' in data)
        ? { isTyping: !!(data as { isTyping: unknown }).isTyping }
        : null
      if (!parsed) return
      const cachedUser = getUserFromCache(user.id)
      const userName = cachedUser?.name ?? 'Admin'
      // Broadcast to all other admins (excluding sender)
      socket.to('admins').emit('internal:typing', {
        userId: user.id,
        userName,
        isTyping: parsed.isTyping,
      })
    })
  }

  socket.on('messages:mark_read', (data: unknown) => {
    // FIX: Add rate limiting for mark_read (60 per minute)
    if (!checkSocketRateLimit(user.id, 60, 300)) {
      socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many mark_read events' })
      return
    }
    wrapAsyncHandler(() => handleMessagesMarkRead(socket, user, data))
  })

  socket.on('typing:start', (data: unknown) => {
    // Typing uses its own namespaced key so it never shares the message budget.
    // 30/min is realistic for active typists; 180/hr prevents sustained abuse.
    if (!checkSocketRateLimit(`typing:${user.id}`, 30, 180)) {
      socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many typing events' })
      return
    }
    const parsed = socketTypingSchema.safeParse(data)
    if (!parsed.success) {
      socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Invalid typing data', issues: parsed.error.issues })
      return
    }
    wrapAsyncHandler(() => handleTypingStart(socket, user, parsed.data.conversationId))
  })

  socket.on('typing:stop', (data: unknown) => {
    // Same namespaced key as typing:start — they share one budget
    if (!checkSocketRateLimit(`typing:${user.id}`, 30, 180)) {
      socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many typing events' })
      return
    }
    const parsed = socketTypingSchema.safeParse(data)
    if (!parsed.success) {
      socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Invalid typing data', issues: parsed.error.issues })
      return
    }
    wrapAsyncHandler(() => handleTypingStop(socket, user, parsed.data.conversationId))
  })

  socket.on('dm:typing', (data: unknown) => {
    wrapAsyncHandler(async () => {
      // FIX: Add rate limiting for DM typing (10 per minute)
      if (!checkSocketRateLimit(user.id, 10, 50)) {
        socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many DM typing events' })
        return
      }

      if (!isAdmin({ role: user.role })) {
        socket.emit('error', { code: 'FORBIDDEN', message: 'Admin access required' })
        return
      }

      const parsed = socketDMTypingSchema.safeParse(data)
      if (!parsed.success) {
        socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Invalid DM typing data', issues: parsed.error.issues })
        return
      }

      const { partnerId, isTyping } = parsed.data

      // Verify admin has access to this user (has an assigned conversation)
      const conversation = await db.query.conversations.findFirst({
        where: and(
          eq(conversations.userId, partnerId),
          eq(conversations.assignedAdminId, user.id)
        ),
        columns: { id: true }
      })
      // SUPER_ADMIN can DM any user, regular ADMIN only their assigned users
      if (user.role === 'ADMIN' && !conversation) {
        socket.emit('error', { code: 'FORBIDDEN', message: 'No access to this user' })
        return
      }

      const cachedUser = getUserFromCache(user.id)
      const userName = cachedUser?.name ?? 'Admin'
      emitToUser(partnerId, 'dm:typing', {
        userId: user.id,
        userName,
        isTyping,
      })
    })
  })

  socket.on('presence:update', (data: unknown) => {
    // FIX: Add rate limiting for presence updates (12 per minute = every 5 seconds)
    if (!checkSocketRateLimit(user.id, 12, 60)) {
      socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many presence updates' })
      return
    }
    handlePresenceUpdate(socket, user, data)
  })

  // FIX #17: Respond to presence:get with a snapshot of all currently online user IDs
  // This allows admin DM and Internal Chat pages to populate presence dots on mount
  socket.on('presence:get', async () => {
    if (user.role !== 'ADMIN' && user.role !== 'SUPER_ADMIN') return
    
    let onlineUserIds = Array.from(serverState.connectedUsers.keys())
    const redisClient = getRedis()
    
    if (redisClient && io) {
      try {
        const responses = await new Promise<string[][]>((resolve, reject) => {
          ;(io!.timeout(2000) as any).serverSideEmit('presence:snapshot_request', (err: Error | null, res: string[][]) => {
            if (err) reject(err)
            else resolve(res || [])
          })
        })
        const allSets = [onlineUserIds, ...(responses || [])]
        onlineUserIds = Array.from(new Set(allSets.flat()))
      } catch (err) {
        logger.error({ err: err instanceof Error ? err.message : String(err) }, 'Cluster presence fetch failed, falling back to local pod map')
      }
    }
    
    socket.emit('presence:snapshot', { onlineUserIds })
  })

  socket.on('ping', () => {
    // FIX: Add rate limiting for ping (60 per minute = every 1 second)
    if (!checkSocketRateLimit(`ping:${user.id}`, 60, 120)) {
      return
    }
    const userData = serverState.connectedUsers.get(user.id)
    if (userData) {
      userData.lastActivity = Date.now()
    }
    socket.emit('pong')
  })
}

function handleDisconnect(socket: Socket, user: SocketUser, reason: string): void {
  logger.info({ userId: user.id, socketId: socket.id, reason }, 'Socket disconnected')

  const existing = serverState.connectedUsers.get(user.id)
  if (existing) {
    existing.socketIds.delete(socket.id)
    if (existing.socketIds.size > 0) {
      return // User still has other active tabs natively running
    }
  }

  serverState.connectedUsers.delete(user.id)

  serverState.userPresence.set(user.id, {
    status: 'offline',
    lastSeen: Date.now()
  })

  const conversationId = getUserConversationId(user.id)
  if (conversationId) {
    const typingKey = `${conversationId}:${user.id}`
    const typingEntry = serverState.typingIndicators.get(typingKey)
    if (typingEntry?.userId === user.id) {
      serverState.typingIndicators.delete(typingKey)
      const disconnectedUser = getUserFromCache(user.id)
      const userName = disconnectedUser?.name ?? 'Unknown'
      const stopPayload = { conversationId, userId: user.id, userName }
      if (isAdmin({ role: user.role })) {
        // Admin was typing — notify the conversation user and other admins
        const conversationOwner = serverState.conversationOwners.get(conversationId)?.userId
        if (conversationOwner) emitToUser(conversationOwner, 'typing:stop', stopPayload)
        emitToAdmins('typing:stop', stopPayload)
      } else {
        // User was typing — notify the assigned admin and super admins
        db.query.conversations.findFirst({
          where: eq(conversations.id, conversationId),
          columns: { assignedAdminId: true }
        }).then(conv => {
          if (conv?.assignedAdminId) emitToUser(conv.assignedAdminId, 'typing:stop', stopPayload)
          emitToSuperAdmins('typing:stop', stopPayload, conv?.assignedAdminId || undefined)
        }).catch(() => { /* best-effort */ })
      }
    }
  }

  const offlineUserCache = getUserFromCache(user.id)
  emitToAdmins('user:offline', {
    userId: user.id,
    userName: offlineUserCache?.name ?? 'Unknown',
    status: 'offline',
    lastSeenAt: Date.now()
  })
}

interface MessageContext {
  conversationId: string
  type: 'TEXT' | 'IMAGE' | 'DOCUMENT'
  content?: string | undefined
  mediaId?: string | undefined
  tempId?: string | undefined
  replyToId?: string | undefined
  announcementId?: string | undefined
}

/**
 * Validates incoming socket message data and returns conversation context.
 * Checks conversation access, message length limits, and media permissions.
 * @param socket - Socket.IO socket instance
 * @param user - Authenticated socket user
 * @param data - Raw message data from client
 * @returns Validation result with context on success, or valid: false on failure
 */
async function validateMessageContext(
  socket: Socket,
  user: SocketUser,
  data: unknown
): Promise<{ valid: true; context: MessageContext; conversation: { id: string; userId: string; assignedAdminId: string | null; unreadCount: number; adminUnreadCount: number; lastMessageAt: Date | null; subsidiaryId: string | null }; isAdminSending: boolean } | { valid: false }> {
  const config = getConfig()

  const parsed = socketMessageSchema.safeParse(data)
  if (!parsed.success) {
    const issues = parsed.error.issues.map(i => i.message).join(', ')
    socket.emit('error', { code: 'VALIDATION_ERROR', message: issues })
    return { valid: false }
  }

  const validatedData: SocketMessageInput = parsed.data

  const conversation = await db.query.conversations.findFirst({
    where: eq(conversations.id, validatedData.conversationId),
    columns: { id: true, userId: true, assignedAdminId: true, unreadCount: true, adminUnreadCount: true, lastMessageAt: true, subsidiaryId: true }
  })

  if (!conversation) {
    socket.emit('error', { code: 'NOT_FOUND', message: 'Conversation not found' })
    return { valid: false }
  }

  const userIsAdmin = isAdmin({ role: user.role })
  // Use centralized permission check for consistency with HTTP routes
  if (!canAccessConversation(user, conversation)) {
    socket.emit('error', { code: 'FORBIDDEN', message: 'Access denied' })
    return { valid: false }
  }

  if (validatedData.type === 'TEXT' && validatedData.content && validatedData.content.length > config.limits.message.textMaxLength) {
    socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Message too long' })
    return { valid: false }
  }

  if (validatedData.type !== 'TEXT' && !config.features.mediaUpload) {
    socket.emit('error', { code: 'FORBIDDEN', message: 'Media uploads are disabled' })
    return { valid: false }
  }

  if (validatedData.type !== 'TEXT') {
    const cachedUser = getUserFromCache(user.id)
    const mediaPermission = cachedUser?.mediaPermission ?? false

    if (!canUploadMedia({ role: user.role, status: user.status, mediaPermission })) {
      socket.emit('error', { code: 'FORBIDDEN', message: 'Media uploads not permitted' })
      return { valid: false }
    }
  }

  return {
    valid: true,
    context: validatedData,
    conversation,
    isAdminSending: userIsAdmin && conversation.userId !== user.id
  }
}

type MediaPayload = { id: string; type: string; cdnUrl: string | null; filename: string; size: number; mimeType: string; metadata?: string | null }

async function validateMediaForMessage(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  mediaId: string,
  messageType: string,
  userId: string,
  userRole: 'USER' | 'ADMIN' | 'SUPER_ADMIN'
): Promise<MediaPayload> {
  const mediaRecord = await tx.query.media.findFirst({
    where: eq(media.id, mediaId),
    columns: { id: true, status: true, type: true, uploadedBy: true, cdnUrl: true, filename: true, size: true, mimeType: true, metadata: true }
  })

  if (!mediaRecord) throw new SocketValidationError('VALIDATION_ERROR', 'Invalid media')
  if (mediaRecord.status !== 'CONFIRMED') throw new SocketValidationError('VALIDATION_ERROR', 'Invalid or unconfirmed media')
  if (mediaRecord.type !== messageType) throw new SocketValidationError('VALIDATION_ERROR', 'Media type does not match message type')
  if (mediaRecord.uploadedBy !== userId && !isAdmin({ role: userRole })) throw new SocketValidationError('FORBIDDEN', 'Media does not belong to you')

  return { id: mediaRecord.id, type: mediaRecord.type, cdnUrl: mediaRecord.cdnUrl, filename: mediaRecord.filename, size: mediaRecord.size, mimeType: mediaRecord.mimeType, metadata: mediaRecord.metadata }
}

async function handleMessageSend(socket: Socket, user: SocketUser, data: unknown, clientIp: string): Promise<void> {
  const validation = await validateMessageContext(socket, user, data)
  if (!validation.valid) return

  const { context, conversation, isAdminSending } = validation
  const wasAlreadyAssigned = !!conversation.assignedAdminId
  const messageId = ulid()
  const now = new Date()
  const sanitizedContent = context.content ? sanitizeText(context.content) : null
  let mediaPayloadRef: MediaPayload | null = null

  try {
    await db.transaction(async (tx) => {
      if (context.mediaId) {
        const validated = await validateMediaForMessage(tx, context.mediaId, context.type, user.id, user.role)
        mediaPayloadRef = validated
      }

      await tx.insert(messages).values({
        id: messageId,
        conversationId: context.conversationId,
        senderId: user.id,
        type: context.type,
        content: sanitizedContent,
        mediaId: context.mediaId || null,
        replyToId: context.replyToId || null,
        announcementId: context.announcementId || null,
      })

      // Smart workload-based auto-assign: pick least-loaded online admin
      if (!isAdminSending && !conversation.assignedAdminId) {
        const { pickBestAdmin } = await import('../lib/assignmentEngine.js')
        const assignedId = await pickBestAdmin(conversation.subsidiaryId)
        if (assignedId) {
          const result = await tx.update(conversations)
            .set({ assignedAdminId: assignedId })
            .where(and(eq(conversations.id, context.conversationId), isNull(conversations.assignedAdminId)))
          if (result.rowsAffected > 0) {
            conversation.assignedAdminId = assignedId
          }
        }
      }

      // Track waiting state: user sent → waiting; admin replied → no longer waiting
      if (!isAdminSending) {
        await tx.update(conversations)
          .set({ waitingSince: now })
          .where(and(eq(conversations.id, context.conversationId), isNull(conversations.waitingSince)))
      } else {
        await tx.update(conversations)
          .set({ waitingSince: null, lastAdminReplyAt: now })
          .where(eq(conversations.id, context.conversationId))
      }

      await tx.update(conversations)
        .set({
          lastMessageAt: now,
          ...(isAdminSending
            ? { unreadCount: sql`unread_count + 1` }
            : { adminUnreadCount: sql`admin_unread_count + 1` })
        })
        .where(eq(conversations.id, context.conversationId))

      await tx.insert(auditLogs).values({
        id: ulid(),
        userId: user.id,
        ipAddress: clientIp,
        action: 'message.send',
        entityType: 'message',
        entityId: messageId,
        details: JSON.stringify({ conversationId: context.conversationId, type: context.type })
      })
    })
  } catch (error) {
    if (error instanceof SocketValidationError) {
      socket.emit('error', { code: error.code, message: error.message })
      return
    }

    logger.error({ userId: user.id, conversationId: context.conversationId, error }, 'Message transaction failed')
    socket.emit('error', { code: 'INTERNAL_ERROR', message: 'Failed to send message' })
    return
  }

  // Re-read conversation after transaction for accurate unread counts (prevents race conditions)
  const [updatedConv, replyToRow, linkedAnnouncementRow] = await Promise.all([
    db.query.conversations.findFirst({
      where: eq(conversations.id, context.conversationId),
      columns: { unreadCount: true, adminUnreadCount: true, assignedAdminId: true }
    }),
    context.replyToId
      ? db.query.messages.findFirst({
        where: eq(messages.id, context.replyToId),
        columns: { id: true, type: true, content: true, deletedAt: true },
        with: { sender: { columns: { name: true } } },
      })
      : Promise.resolve(null),
    context.announcementId
      ? db.query.announcements.findFirst({
        where: eq(announcements.id, context.announcementId),
        columns: { id: true, title: true, type: true, template: true },
      })
      : Promise.resolve(null),
  ])

  const cachedSender = getUserFromCache(user.id)
  const freshUnreadCount = updatedConv?.unreadCount ?? (isAdminSending ? conversation.unreadCount + 1 : conversation.unreadCount)
  const freshAdminUnreadCount = updatedConv?.adminUnreadCount ?? (isAdminSending ? conversation.adminUnreadCount : conversation.adminUnreadCount + 1)
  touchConversationOwner(context.conversationId)

  const messagePayload = {
    id: messageId,
    conversationId: context.conversationId,
    senderId: user.id,
    sender: { id: user.id, name: cachedSender?.name ?? user.id, role: user.role },
    type: context.type,
    content: sanitizedContent,
    status: 'SENT',
    createdAt: now,
    media: mediaPayloadRef,
    replyToId: context.replyToId ?? null,
    replyTo: replyToRow ?? null,
    announcementId: context.announcementId ?? null,
    linkedAnnouncement: linkedAnnouncementRow ?? null,
    assignedAdminId: conversation.assignedAdminId,
  }

  const updatePayload = {
    conversationId: context.conversationId,
    userId: conversation.userId,
    unreadCount: freshUnreadCount,
    adminUnreadCount: freshAdminUnreadCount,
    lastMessageAt: now.getTime(),
    lastMessage: messagePayload,
    assignedAdminId: conversation.assignedAdminId,
    subsidiaryId: conversation.subsidiaryId,
    // When admin replies, waitingSince is cleared — push that to frontend so badge disappears
    // When admin replies, clear the waiting badge; when user sends, start the clock
    waitingSince: isAdminSending ? null : now.getTime(),
  }

  if (isAdmin({ role: user.role })) {
    emitToUser(conversation.userId, 'message:new', { message: messagePayload })
    // Update the sending admin's own conversation list sidebar
    emitToUser(user.id, 'conversation:updated', updatePayload)
    // Super admins get conversation:updated for oversight (unless they are the sender)
    emitToSuperAdmins('message:new', { message: messagePayload }, user.id)
    emitToSuperAdmins('conversation:updated', updatePayload, user.id)
  } else {
    // Only emit to assigned admin (and super admins), not all admins - privacy fix
    if (conversation.assignedAdminId) {
      emitToUser(conversation.assignedAdminId, 'message:new', { message: messagePayload })
      emitToUser(conversation.assignedAdminId, 'conversation:updated', updatePayload)
      // Notify newly auto-assigned admin so their sidebar updates immediately
      if (!wasAlreadyAssigned) {
        const targetUserInfo = getUserFromCache(conversation.userId)
        emitToUser(conversation.assignedAdminId, 'conversation:assigned_to_you', {
          conversationId: context.conversationId,
          userName: targetUserInfo?.name ?? 'a user',
        })
      }
    }
    // Emit to SUPER_ADMINs for oversight — cross-pod native Redis room broadcast
    emitToSuperAdmins('message:new', { message: messagePayload }, conversation.assignedAdminId || undefined)
    emitToSuperAdmins('conversation:updated', updatePayload, conversation.assignedAdminId || undefined)
    
    // Super admins get the assignment toast for unassigned conversations
    if (!conversation.assignedAdminId && !wasAlreadyAssigned) {
      const targetUserInfo = getUserFromCache(conversation.userId)
      emitToSuperAdmins('conversation:assigned_to_you', {
        conversationId: context.conversationId,
        userName: targetUserInfo?.name ?? 'a user',
      }, conversation.assignedAdminId || undefined)
    }
  }

  if (isAdminSending) {
    // Email notification for user
    await queueEmailNotification(conversation.userId).catch(e => logger.error({ e }, 'Socket Email enqueue failed'))

    // Web push: notify the user if they are NOT currently connected via WebSocket
    if (!serverState.connectedUsers.has(conversation.userId)) {
      const senderName = getUserFromCache(user.id)?.name ?? 'Support'
      const preview = sanitizedContent
        ? sanitizedContent.slice(0, 80) + (sanitizedContent.length > 80 ? '…' : '')
        : context.type === 'IMAGE' ? '📷 Image' : '📎 File'
      sendPushToUser(conversation.userId, {
        title: senderName,
        body: preview,
        tag: `conv:${context.conversationId}`,
        data: { conversationId: context.conversationId, url: '/' },
      }).catch(e => logger.warn({ e }, 'Push to user failed'))
    }
  } else {
    // User sent a message — push to the assigned admin if they are offline
    const targetAdminId = conversation.assignedAdminId
    if (targetAdminId && !serverState.connectedUsers.has(targetAdminId)) {
      const userInfo = getUserFromCache(conversation.userId)
      const preview = sanitizedContent
        ? sanitizedContent.slice(0, 80) + (sanitizedContent.length > 80 ? '…' : '')
        : context.type === 'IMAGE' ? '📷 Image' : '📎 File'
      sendPushToUser(targetAdminId, {
        title: userInfo?.name ?? 'New Message',
        body: preview,
        tag: `conv:${context.conversationId}`,
        data: { conversationId: context.conversationId, url: '/admin/conversations' },
      }).catch(e => logger.warn({ e }, 'Push to admin failed'))
    }
  }

  socket.emit('message:sent', { tempId: context.tempId, message: messagePayload })
}

async function handleInternalMessageSend(socket: Socket, user: SocketUser, data: unknown): Promise<void> {
  const config = getConfig()
  const parsed = socketInternalMessageSchema.safeParse(data)
  if (!parsed.success) {
    socket.emit('error', { code: 'VALIDATION_ERROR', message: parsed.error.issues.map(i => i.message).join(', ') })
    return
  }

  const { type, content, mediaId, tempId, replyToId } = parsed.data
  const teamMax = config.limits.message.teamTextMaxLength ?? 5000
  if (type === 'TEXT' && content && content.length > teamMax) {
    socket.emit('error', { code: 'VALIDATION_ERROR', message: `Message too long (max ${teamMax} characters)` })
    return
  }

  const id = ulid()
  const now = new Date()
  const sanitized = content ? sanitizeText(content) : null

  // Pre-fetch related data before the transaction so we can build the payload without a post-insert SELECT
  const [mediaRecord, replyToRow] = await Promise.all([
    mediaId
      ? db.query.media.findFirst({
        where: eq(media.id, mediaId),
        columns: { id: true, status: true, type: true, uploadedBy: true, cdnUrl: true, filename: true, size: true, mimeType: true },
      })
      : Promise.resolve(null),
    replyToId
      ? db.query.internalMessages.findFirst({
        where: eq(internalMessages.id, replyToId),
        columns: { id: true, type: true, content: true, deletedAt: true },
        with: { sender: { columns: { name: true } } },
      })
      : Promise.resolve(null),
  ])

  if (mediaId) {
    if (!mediaRecord) {
      socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Invalid media' })
      return
    }
    if (mediaRecord.status !== 'CONFIRMED') {
      socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Invalid or unconfirmed media' })
      return
    }
    if (mediaRecord.type !== type) {
      socket.emit('error', { code: 'VALIDATION_ERROR', message: 'Media type does not match message type' })
      return
    }
    if (mediaRecord.uploadedBy !== user.id && !isAdmin({ role: user.role })) {
      socket.emit('error', { code: 'FORBIDDEN', message: 'Media does not belong to you' })
      return
    }
  }

  try {
    await db.transaction(async (tx) => {
      await tx.insert(internalMessages).values({
        id,
        senderId: user.id,
        type,
        content: sanitized,
        mediaId: mediaId ?? null,
        replyToId: replyToId ?? null,
      })
    })
  } catch (err) {
    if (err instanceof SocketValidationError) {
      socket.emit('error', { code: err.code, message: err.message })
      return
    }
    logger.error({ userId: user.id, error: err }, 'Internal message send failed')
    socket.emit('error', { code: 'INTERNAL_ERROR', message: 'Failed to send message' })
    return
  }

  const cachedSender = getUserFromCache(user.id)
  const mediaPayload = mediaRecord
    ? { id: mediaRecord.id, type: mediaRecord.type, cdnUrl: mediaRecord.cdnUrl, filename: mediaRecord.filename, size: mediaRecord.size, mimeType: mediaRecord.mimeType }
    : null

  const payload = {
    id,
    senderId: user.id,
    sender: { id: user.id, name: cachedSender?.name ?? user.id, role: user.role },
    type,
    content: sanitized,
    media: mediaPayload,
    replyToId: replyToId ?? null,
    replyTo: replyToRow ?? null,
    createdAt: now,
  }

  // Broadcast to all admins in the team chat room
  emitToAdmins('internal:message', { message: payload })
  socket.emit('internal:message:sent', { tempId, message: payload })

  // Web push: notify offline admins about the new team message
  try {
    const allAdminRows = await db.query.users.findMany({
      where: eq(users.role, 'ADMIN'),
      columns: { id: true },
    })
    const superAdminRows = await db.query.users.findMany({
      where: eq(users.role, 'SUPER_ADMIN'),
      columns: { id: true },
    })
    const senderName = getUserFromCache(user.id)?.name ?? 'Team'
    const preview = sanitized
      ? sanitized.slice(0, 80) + (sanitized.length > 80 ? '…' : '')
      : type === 'IMAGE' ? '📷 Image' : '📎 File'
    const targets = [...allAdminRows, ...superAdminRows].filter(a => a.id !== user.id)
    await Promise.allSettled(targets.map(admin => {
      if (!serverState.connectedUsers.has(admin.id)) {
        return sendPushToUser(admin.id, {
          title: `${senderName} (Team Chat)`,
          body: preview,
          tag: 'internal-chat',
          data: { url: '/admin/internal' },
        })
      }
      return Promise.resolve()
    }))
  } catch (e) {
    logger.warn({ e }, 'Push to admins (internal) failed')
  }
}

async function handleMessagesMarkRead(_socket: Socket, user: SocketUser, data: unknown): Promise<void> {
  if (!data || typeof data !== 'object' || !('conversationId' in data)) return
  const conversationId = (data as { conversationId: unknown }).conversationId
  if (typeof conversationId !== 'string' || !conversationId) return

  const conversation = await db.query.conversations.findFirst({
    where: eq(conversations.id, conversationId),
    columns: { id: true, userId: true, assignedAdminId: true }
  })
  if (!conversation) return

  // Use centralized permission check for consistency with HTTP routes
  if (!canAccessConversation(user, conversation)) return

  const now = Date.now()

  if (isAdmin({ role: user.role })) {
    // Admin reads user messages — both UPDATEs in one transaction (#36)
    let rowsAffected = 0
    await db.transaction(async (tx) => {
      const result = await tx.update(messages)
        .set({ status: 'READ', readAt: new Date(now), updatedAt: new Date(now) })
        .where(and(
          eq(messages.conversationId, conversationId),
          eq(messages.senderId, conversation.userId),
          eq(messages.status, 'SENT'),
          isNull(messages.deletedAt)
        ))
      rowsAffected = result.rowsAffected ?? 0
      if (rowsAffected > 0) {
        await tx.update(conversations)
          .set({ adminUnreadCount: 0 })
          .where(eq(conversations.id, conversationId))
      }
    })
    if (rowsAffected > 0) {
      emitToAdmins('conversation:updated', { conversationId, adminUnreadCount: 0 })
      emitToUser(conversation.userId, 'messages:read', { conversationId, readBy: user.id, readAt: now })
    }
  } else {
    // User reads admin messages — both UPDATEs in one transaction (#36)
    let rowsAffected = 0
    await db.transaction(async (tx) => {
      const result = await tx.update(messages)
        .set({ status: 'READ', readAt: new Date(now), updatedAt: new Date(now) })
        .where(and(
          eq(messages.conversationId, conversationId),
          ne(messages.senderId, user.id),
          eq(messages.status, 'SENT'),
          isNull(messages.deletedAt)
        ))
      rowsAffected = result.rowsAffected ?? 0
      if (rowsAffected > 0) {
        await tx.update(conversations)
          .set({ unreadCount: 0 })
          .where(eq(conversations.id, conversationId))
      }
    })
    if (rowsAffected > 0) {
      const readPayload = { conversationId, readBy: user.id, readAt: now }
      // Emit only to assigned admin (privacy fix)
      if (conversation.assignedAdminId) {
        emitToUser(conversation.assignedAdminId, 'messages:read', readPayload)
        emitToUser(conversation.assignedAdminId, 'conversation:updated', { conversationId, unreadCount: 0 })
      }
      emitToUser(user.id, 'messages:read', readPayload)
    }
  }
}

async function handleTypingStart(socket: Socket, user: SocketUser, providedConvId?: string): Promise<void> {
  const conversationId = providedConvId || getUserConversationId(user.id)
  if (!conversationId) return

  // Validate access and fetch assignedAdminId in one query
  const conversation = await db.query.conversations.findFirst({
    where: eq(conversations.id, conversationId),
    columns: { id: true, userId: true, assignedAdminId: true }
  })
  if (!conversation || !canAccessConversation(user, conversation)) return

  const cachedUser = getUserFromCache(user.id)
  const userName = cachedUser?.name ?? 'Unknown'

  serverState.typingIndicators.set(`${conversationId}:${user.id}`, {
    userId: user.id,
    conversationId,
    updatedAt: Date.now()
  })

  if (isAdmin({ role: user.role })) {
    // Admin typing → send directly to the conversation owner (already fetched from DB above)
    emitToUser(conversation.userId, 'typing:start', { conversationId, userId: user.id, userName })
    // Sister-Tab Echo: Echo admin typing to other admin tabs
    socket.broadcast.to('admins').emit('typing:start', { conversationId, userId: user.id, userName })
  } else {
    // User typing → send to the assigned admin + all SUPER_ADMINs.
    if (conversation.assignedAdminId) {
      emitToUser(conversation.assignedAdminId, 'typing:start', { conversationId, userId: user.id, userName })
    }
    emitToSuperAdmins('typing:start', { conversationId, userId: user.id, userName }, conversation.assignedAdminId || undefined)
  }

  // Sister-Tab Echo: Reflect typing state to user's other open tabs
  socket.broadcast.to(`user:${user.id}`).emit('typing:start', { conversationId, userId: user.id, userName })
}

async function handleTypingStop(socket: Socket, user: SocketUser, providedConvId?: string): Promise<void> {
  const conversationId = providedConvId || getUserConversationId(user.id)
  if (!conversationId) return

  // Validate access and fetch assignedAdminId in one query
  const conversation = await db.query.conversations.findFirst({
    where: eq(conversations.id, conversationId),
    columns: { id: true, userId: true, assignedAdminId: true }
  })
  if (!conversation || !canAccessConversation(user, conversation)) return

  const cachedUser = getUserFromCache(user.id)
  const userName = cachedUser?.name ?? 'Unknown'

  serverState.typingIndicators.delete(`${conversationId}:${user.id}`)

  if (isAdmin({ role: user.role })) {
    // Admin stopped typing → tell the conversation owner directly
    emitToUser(conversation.userId, 'typing:stop', { conversationId, userId: user.id, userName })
    // Sister-Tab Echo
    socket.broadcast.to('admins').emit('typing:stop', { conversationId, userId: user.id, userName })
  } else {
    // User stopped typing → tell the assigned admin + all SUPER_ADMINs.
    if (conversation.assignedAdminId) {
      emitToUser(conversation.assignedAdminId, 'typing:stop', { conversationId, userId: user.id, userName })
    }
    emitToSuperAdmins('typing:stop', { conversationId, userId: user.id, userName }, conversation.assignedAdminId || undefined)
  }

  // Sister-Tab Echo: Reflect typing stop to user's other open tabs
  socket.broadcast.to(`user:${user.id}`).emit('typing:stop', { conversationId, userId: user.id, userName })
}

function handlePresenceUpdate(_socket: Socket, user: SocketUser, data: unknown): void {
  const parsed = socketPresenceSchema.safeParse(data)
  if (!parsed.success) return

  const validatedData: SocketPresenceInput = parsed.data

  serverState.userPresence.set(user.id, {
    status: validatedData.status,
    lastSeen: Date.now()
  })

  emitToAdmins('presence:update', {
    userId: user.id,
    status: validatedData.status,
    lastSeen: Date.now()
  })

  // Sister-Tab Echo: update presence visually across all your own admin tabs
  _socket.broadcast.to(`user:${user.id}`).emit('presence:update', {
    userId: user.id,
    status: validatedData.status,
    lastSeen: Date.now()
  })
}

export function getIO(): Server {
  if (!io) {
    throw new Error('Socket.IO not initialized')
  }
  return io
}

export function closeIO(): Promise<void> {
  return new Promise((resolve) => {
    if (io) {
      io.close(() => resolve())
    } else {
      resolve()
    }
  })
}

export function emitToSuperAdmins(event: string, data: unknown, exceptUserId?: string): void {
  if (!io) return
  if (exceptUserId) {
    io.to('super_admins').except(`user:${exceptUserId}`).emit(event, data)
  } else {
    io.to('super_admins').emit(event, data)
  }
}

export async function getOnlineAdminIdsGlobally(): Promise<string[]> {
  if (!io) return getLocalOnlineAdmins()
  try {
    const sockets = await io.in('admins').fetchSockets()
    const ids = new Set<string>()
    for (const s of sockets) {
      if (s.data?.user?.id) ids.add(s.data.user.id)
    }
    return Array.from(ids)
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : String(err) }, 'Redis fetchSockets failed, falling back to local memory')
    return getLocalOnlineAdmins()
  }
}

function getLocalOnlineAdmins(): string[] {
  const ids: string[] = []
  for (const [userId] of serverState.connectedUsers.entries()) {
    const cached = getUserFromCache(userId) as { role?: string } | null
    if (cached && (cached.role === 'ADMIN' || cached.role === 'SUPER_ADMIN')) {
      ids.push(userId)
    }
  }
  return ids
}

export async function isUserOnlineGlobally(userId: string): Promise<boolean> {
  if (!io) return serverState.isUserConnected(userId)
  try {
    const sockets = await io.in(`user:${userId}`).fetchSockets()
    return sockets.length > 0
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : String(err) }, 'Redis fetchSockets failed, falling back to local memory')
    return serverState.isUserConnected(userId)
  }
}

export function emitToUser(userId: string, event: string, data: unknown): void {
  if (!io) return
  io.to(`user:${userId}`).emit(event, data)
}

export function emitToAdmins(event: string, data: unknown): void {
  if (!io) return
  io.to('admins').emit(event, data)
}

export function emitToUsers(event: string, data: unknown): void {
  if (!io) return
  io.to('users').emit(event, data)
}

export function forceLogout(userId: string, reason: string): void {
  if (!io) return

  emitToUser(userId, 'force_logout', { reason })

  // Instantly sever all socket connections mapped to this user across the entire cluster
  io.in(`user:${userId}`).disconnectSockets(true)

  removeUserFromCache(userId)
}

export function forceLogoutSession(sessionId: string, reason: string): void {
  if (!io) return

  io.to(`session:${sessionId}`).emit('force_logout', { reason })
  // Instantly sever all socket connections mapped to this specific session cluster-wide
  io.in(`session:${sessionId}`).disconnectSockets(true)
}

export function getConnectedUsersCount(): number {
  return serverState.connectedUsers.size
}

export function getConnectedUsers(): Array<{ userId: string; connectedAt: number }> {
  return Array.from(serverState.connectedUsers.values()).map(u => ({
    userId: u.userId,
    connectedAt: u.connectedAt
  }))
}
