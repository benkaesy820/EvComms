/**
 * PERFECTED State Manager - Single Server Optimized
 * 
 * Features:
 * - 200MB total memory limit enforced
 * - Immediate invalidation on change (no TTL)
 * - Single-server optimized (no distributed overhead)
 * - Automatic size-based eviction
 * - Memory-efficient serialization
 * 
 * Memory Budget (200MB):
 * - User Cache: 80MB (40%)
 * - Session Validation: 40MB (20%)
 * - Connected Users: 20MB (10%)
 * - Conversation Owners: 20MB (10%)
 * - Other Maps: 20MB (10%)
 * - Buffer/Overhead: 20MB (10%)
 */

import { LRUCache } from 'lru-cache'
import { EventEmitter } from 'events'
import { getConfig, getMemoryConfig, getCleanupConfig } from './lib/config.js'
import { logger } from './lib/logger.js'

export const clusterBus = new EventEmitter()

// ============================================================================
// INTERFACES
// ============================================================================

interface CachedUser {
  role: 'USER' | 'ADMIN' | 'SUPER_ADMIN'
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'SUSPENDED'
  name: string
  mediaPermission: boolean
  emailNotifyOnMessage: boolean
  /** Raw JSON string of subsidiary IDs this admin handles. NULL = generalist. */
  subsidiaryIds?: string | null
}

interface ConnectedUser {
  socketIds: Set<string>
  userId: string
  connectedAt: number
  lastActivity: number
}

interface UserPresence {
  status: 'online' | 'away' | 'offline'
  lastSeen: number
}

interface TypingIndicator {
  userId: string
  conversationId: string
  updatedAt: number
}

interface PendingEmail {
  userId: string
  messageCount: number
  firstMessageAt: number
  timer: NodeJS.Timeout
}

interface ActiveUpload {
  userId: string
  mediaId: string
  type: string
  startedAt: number
  filename: string
  // ARCHITECTURE FIX: Track declared metadata for validation
  declaredSize: number
  declaredMimeType: string
}

interface ConversationOwner {
  userId: string
  lastActivityAt: number
}

interface SessionValidationEntry {
  valid: boolean
  userId: string
  sessionId: string
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

const memoryConfig = getMemoryConfig()
const MEMORY_LIMIT_MB = memoryConfig.totalBudgetMB
const MEMORY_LIMIT_BYTES = MEMORY_LIMIT_MB * 1024 * 1024

// Size calculation helpers
// NOTE: Uses a WeakSet to detect and break circular references (e.g. NodeJS.Timeout internals).
// Without cycle detection, storing objects like PendingEmail (which contains a NodeJS.Timeout)
// in an LRU cache with sizeCalculation would cause infinite recursion → "Maximum call stack
// size exceeded".
function estimateObjectSize(obj: unknown, seen?: WeakSet<object>): number {
  if (obj === null || obj === undefined) return 0
  if (typeof obj === 'boolean') return 4
  if (typeof obj === 'number') return 8
  if (typeof obj === 'string') return obj.length * 2 + 4
  if (obj instanceof Set) return (obj as Set<unknown>).size * 8
  if (Array.isArray(obj)) {
    const tracker = seen ?? new WeakSet<object>()
    return obj.reduce((sum: number, item) => sum + estimateObjectSize(item, tracker), 0)
  }
  if (typeof obj === 'object') {
    const tracker = seen ?? new WeakSet<object>()
    // Break circular reference cycles — return 0 for already-visited objects
    if (tracker.has(obj)) return 0
    tracker.add(obj)
    return Object.entries(obj).reduce((sum, [key, val]) => {
      return sum + key.length * 2 + estimateObjectSize(val, tracker)
    }, 0)
  }
  return 8
}

// ============================================================================
// STATE MANAGER
// ============================================================================

class StateManager {
  private initialized = false
  private initLock = false
  private cleanupInterval: NodeJS.Timeout | null = null
  private memoryCheckInterval: NodeJS.Timeout | null = null

  // Track memory usage
  private currentMemoryUsage = 0
  private memoryStats = {
    userCache: 0,
    sessionCache: 0,
    connectedUsers: 0,
    conversationOwners: 0,
    other: 0
  }

  /**
   * USER CACHE - 80MB budget
   * ~200KB per user entry (generous)
   * ~400,000 users max
   */
  readonly userCache: LRUCache<string, CachedUser>

  /**
   * SESSION VALIDATION - 40MB budget
   * ~100 bytes per entry
   * ~400,000 sessions max
   */
  readonly sessionValidationCache: LRUCache<string, boolean>

  /**
   * CONNECTED USERS - 20MB budget
   * Maps userId to connection info
   */
  readonly connectedUsers: LRUCache<string, ConnectedUser>

  /**
   * USER PRESENCE - 10MB budget
   */
  readonly userPresence: LRUCache<string, UserPresence>

  /**
   * TYPING INDICATORS - 5MB budget
   * Auto-cleanup via LRU eviction
   */
  readonly typingIndicators: LRUCache<string, TypingIndicator>

  /**
   * EMAIL PREFERENCES - 5MB budget
   */
  readonly emailPreferences: LRUCache<string, boolean>

  /**
   * PENDING EMAILS - 10MB budget
   */
  readonly pendingEmails: LRUCache<string, PendingEmail>

  /**
   * USER NAMES - 5MB budget
   */
  readonly userNames: LRUCache<string, string>

  /**
   * ACTIVE UPLOADS - 10MB budget
   */
  readonly activeUploads: LRUCache<string, ActiveUpload>

  /**
   * CONVERSATION OWNERS - 20MB budget
   */
  readonly conversationOwners: LRUCache<string, ConversationOwner>

  /**
   * USER TO CONVERSATION MAPPING - 10MB budget
   */
  readonly userToConversation: LRUCache<string, string>

  /**
   * USER SESSION KEYS - 10MB budget
   */
  readonly userSessionKeys: LRUCache<string, Set<string>>

  constructor() {
    const memCfg = getMemoryConfig()
    
    // Initialize LRU caches with size-based limits from config
    this.userCache = new LRUCache({
      max: memCfg.userCache.max,
      maxSize: memCfg.userCache.maxSizeBytes,
      sizeCalculation: (value) => estimateObjectSize(value),
      allowStale: false,
      updateAgeOnGet: false, // No TTL
      dispose: (value, key, reason) => {
        this.memoryStats.userCache -= estimateObjectSize(value)
        logger.debug({ userId: key, reason, freed: estimateObjectSize(value) }, 'User evicted')
      }
    })

    this.sessionValidationCache = new LRUCache({
      max: memCfg.sessionCache.max,
      maxSize: memCfg.sessionCache.maxSizeBytes,
      sizeCalculation: () => memCfg.sessionCache.entrySizeBytes,
      allowStale: false,
      updateAgeOnGet: false, // No TTL
      dispose: (value, key) => {
        this.memoryStats.sessionCache -= memCfg.sessionCache.entrySizeBytes
        logger.debug({ key }, 'Session validation evicted')
      }
    })

    // Initialize remaining LRU caches
    this.connectedUsers = new LRUCache({
      max: memCfg.connectedUsers.max,
      maxSize: memCfg.connectedUsers.maxSizeBytes,
      sizeCalculation: (value) => estimateObjectSize(value),
      allowStale: false,
      updateAgeOnGet: false
    })

    this.userPresence = new LRUCache({
      max: memCfg.userPresence.max,
      maxSize: memCfg.userPresence.maxSizeBytes,
      sizeCalculation: () => memCfg.userPresence.entrySizeBytes,
      allowStale: false,
      updateAgeOnGet: false
    })

    this.typingIndicators = new LRUCache({
      max: memCfg.typingIndicators.max,
      maxSize: memCfg.typingIndicators.maxSizeBytes,
      sizeCalculation: () => memCfg.typingIndicators.entrySizeBytes,
      allowStale: true,
      updateAgeOnGet: false
    })

    this.emailPreferences = new LRUCache({
      max: memCfg.emailPreferences.max,
      maxSize: memCfg.emailPreferences.maxSizeBytes,
      sizeCalculation: () => memCfg.emailPreferences.entrySizeBytes,
      allowStale: false,
      updateAgeOnGet: false
    })

    this.pendingEmails = new LRUCache({
      max: memCfg.pendingEmails.max,
      maxSize: memCfg.pendingEmails.maxSizeBytes,
      sizeCalculation: () => 200, // FIX: Fixed size — PendingEmail contains a NodeJS.Timeout (circular refs), estimateObjectSize would recurse infinitely on it
      allowStale: false,
      updateAgeOnGet: false
    })

    this.userNames = new LRUCache({
      max: memCfg.userNames.max,
      maxSize: memCfg.userNames.maxSizeBytes,
      sizeCalculation: (value) => value.length * 2 + 50,
      allowStale: false,
      updateAgeOnGet: false
    })

    this.activeUploads = new LRUCache({
      max: memCfg.activeUploads.max,
      maxSize: memCfg.activeUploads.maxSizeBytes,
      sizeCalculation: (value) => estimateObjectSize(value),
      allowStale: false,
      updateAgeOnGet: false
    })

    this.conversationOwners = new LRUCache({
      max: memCfg.conversationOwners.max,
      maxSize: memCfg.conversationOwners.maxSizeBytes,
      sizeCalculation: () => memCfg.conversationOwners.entrySizeBytes,
      allowStale: false,
      updateAgeOnGet: false
    })

    this.userToConversation = new LRUCache({
      max: memCfg.userToConversation.max,
      maxSize: memCfg.userToConversation.maxSizeBytes,
      sizeCalculation: () => memCfg.userToConversation.entrySizeBytes,
      allowStale: false,
      updateAgeOnGet: false
    })

    this.userSessionKeys = new LRUCache({
      max: memCfg.userSessionKeys.max,
      maxSize: memCfg.userSessionKeys.maxSizeBytes,
      sizeCalculation: (value) => estimateObjectSize(value),
      allowStale: false,
      updateAgeOnGet: false
    })

    logger.info({ 
      userCacheMax: this.userCache.max,
      userCacheMaxSizeMB: memCfg.userCache.maxSizeBytes / (1024 * 1024),
      sessionCacheMax: this.sessionValidationCache.max,
      sessionCacheMaxSizeMB: memCfg.sessionCache.maxSizeBytes / (1024 * 1024),
      connectedUsersMax: this.connectedUsers.max,
      totalBudgetMB: memCfg.totalBudgetMB
    }, 'State manager initialized with configured memory limits')
  }

  // ==========================================================================
  // LIFECYCLE
  // ==========================================================================

  init(): void {
    if (this.initLock || this.initialized) {
      logger.warn('State manager already initialized')
      return
    }

    this.initLock = true
    const cfg = getConfig()
    const cleanupCfg = getCleanupConfig()

    // Cleanup interval for non-LRU maps
    this.cleanupInterval = setInterval(() => {
      this.runCleanup()
    }, cleanupCfg.intervalMs)

    // Memory monitoring
    this.memoryCheckInterval = setInterval(() => {
      this.checkMemoryUsage()
    }, cleanupCfg.memoryCheckIntervalMs)

    this.initialized = true
    this.initLock = false

    logger.info('State manager initialized with immediate invalidation')
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    if (this.memoryCheckInterval) {
      clearInterval(this.memoryCheckInterval)
      this.memoryCheckInterval = null
    }

    this.clearAll()
    this.initialized = false
    logger.info('State manager stopped')
  }

  // ==========================================================================
  // USER CACHE - IMMEDIATE INVALIDATION
  // ==========================================================================

  addUserToCache(userId: string, user: CachedUser): void {
    const size = estimateObjectSize(user)
    this.userCache.set(userId, user)
    this.memoryStats.userCache += size
    logger.debug({ userId, size }, 'User added to cache')
  }

  getUserFromCache(userId: string): CachedUser | undefined {
    return this.userCache.get(userId)
  }

  updateUserCache(userId: string, updates: Partial<CachedUser>, emit = true): void {
    const existing = this.userCache.get(userId)
    if (existing) {
      const oldSize = estimateObjectSize(existing)
      const updated = { ...existing, ...updates }
      const newSize = estimateObjectSize(updated)
      
      this.userCache.set(userId, updated)
      this.memoryStats.userCache += newSize - oldSize
      
      logger.debug({ userId, updates: Object.keys(updates) }, 'User cache updated')
      if (emit) clusterBus.emit('cache:update_user', { userId, updates })
    }
  }

  removeUserFromCache(userId: string, emit = true): void {
    const existing = this.userCache.get(userId)
    if (existing) {
      this.memoryStats.userCache -= estimateObjectSize(existing)
      this.userCache.delete(userId)
      logger.debug({ userId }, 'User removed from cache')
      if (emit) clusterBus.emit('cache:remove_user', { userId })
    }
  }

  // Bulk invalidation for admin operations
  invalidateUsersByStatus(status: string, emit = true): void {
    let count = 0
    for (const [userId, user] of this.userCache.entries()) {
      if (user.status === status) {
        this.userCache.delete(userId)
        count++
      }
    }
    if (count > 0) {
      logger.info({ count, status }, 'Invalidated users from cache by status')
      if (emit) clusterBus.emit('cache:invalidate_status', { status })
    }
  }

  // ==========================================================================
  // SESSION VALIDATION - IMMEDIATE INVALIDATION
  // ==========================================================================

  getSessionValidationCache(userId: string, sessionId: string): boolean | undefined {
    return this.sessionValidationCache.get(`${userId}:${sessionId}`)
  }

  setSessionValidationCache(userId: string, sessionId: string, valid: boolean, _ttlMs?: number): void {
    const key = `${userId}:${sessionId}`
    this.sessionValidationCache.set(key, valid)
    this.memoryStats.sessionCache += 100
    logger.debug({ userId, sessionId, valid }, 'Session validation cached')
  }

  invalidateSessionCache(userId: string, sessionId: string, emit = true): void {
    const key = `${userId}:${sessionId}`
    if (this.sessionValidationCache.has(key)) {
      this.sessionValidationCache.delete(key)
      this.memoryStats.sessionCache -= 100
      logger.debug({ userId, sessionId }, 'Session validation invalidated')
      if (emit) clusterBus.emit('cache:invalidate_session', { userId, sessionId })
    }
  }

  invalidateAllUserSessions(userId: string, emit = true): void {
    let count = 0
    for (const key of this.sessionValidationCache.keys()) {
      if (key.startsWith(`${userId}:`)) {
        this.sessionValidationCache.delete(key)
        count++
      }
    }
    if (count > 0) {
      this.memoryStats.sessionCache -= count * 100
      logger.debug({ userId, count }, 'All user sessions invalidated from cache')
      if (emit) clusterBus.emit('cache:invalidate_all_sessions', { userId })
    }
  }

  // ==========================================================================
  // CONNECTED USERS
  // ==========================================================================

  addConnectedUser(userId: string, socketId: string): void {
    const existing = this.connectedUsers.get(userId)
    if (existing) {
      existing.socketIds.add(socketId)
      existing.lastActivity = Date.now()
    } else {
      this.connectedUsers.set(userId, {
        socketIds: new Set([socketId]),
        userId,
        connectedAt: Date.now(),
        lastActivity: Date.now()
      })
      logger.debug({ userId, socketId }, 'User connected')
    }
  }

  removeConnectedUser(userId: string, socketId: string): void {
    const existing = this.connectedUsers.get(userId)
    if (existing) {
      existing.socketIds.delete(socketId)
      if (existing.socketIds.size === 0) {
        this.connectedUsers.delete(userId)
        logger.debug({ userId }, 'User fully disconnected')
      }
    }
  }

  isUserConnected(userId: string): boolean {
    return this.connectedUsers.has(userId)
  }

  getUserSocketCount(userId: string): number {
    return this.connectedUsers.get(userId)?.socketIds.size ?? 0
  }

  // ==========================================================================
  // CONVERSATION OWNERS
  // ==========================================================================

  setConversationOwner(conversationId: string, userId: string): void {
    this.conversationOwners.set(conversationId, {
      userId,
      lastActivityAt: Date.now()
    })
    this.userToConversation.set(userId, conversationId)
  }

  getConversationOwner(conversationId: string): string | undefined {
    return this.conversationOwners.get(conversationId)?.userId
  }

  getUserConversationId(userId: string): string | undefined {
    return this.userToConversation.get(userId)
  }

  touchConversationOwner(conversationId: string): void {
    const owner = this.conversationOwners.get(conversationId)
    if (owner) {
      owner.lastActivityAt = Date.now()
    }
  }

  removeConversationOwner(conversationId: string): void {
    const owner = this.conversationOwners.get(conversationId)
    if (owner) {
      this.userToConversation.delete(owner.userId)
      this.conversationOwners.delete(conversationId)
    }
  }

  // ==========================================================================
  // TYPING INDICATORS
  // ==========================================================================

  setTypingIndicator(conversationId: string, userId: string): void {
    this.typingIndicators.set(`${conversationId}:${userId}`, {
      userId,
      conversationId,
      updatedAt: Date.now()
    })
  }

  clearTypingIndicator(conversationId: string, userId: string): void {
    this.typingIndicators.delete(`${conversationId}:${userId}`)
  }

  getTypingUsers(conversationId: string): string[] {
    const users: string[] = []
    const now = Date.now()
    const cfg = getCleanupConfig()
    const threshold = cfg.typingThresholdMs

    for (const [key, indicator] of this.typingIndicators.entries()) {
      if (indicator.conversationId === conversationId) {
        if (now - indicator.updatedAt < threshold) {
          users.push(indicator.userId)
        } else {
          this.typingIndicators.delete(key)
        }
      }
    }

    return users
  }

  // ==========================================================================
  // PRESENCE
  // ==========================================================================

  setUserPresence(userId: string, status: UserPresence['status']): void {
    this.userPresence.set(userId, {
      status,
      lastSeen: Date.now()
    })
  }

  getUserPresence(userId: string): UserPresence | undefined {
    return this.userPresence.get(userId)
  }

  // ==========================================================================
  // CLEANUP
  // ==========================================================================

  private runCleanup(): void {
    const now = Date.now()
    let cleaned = 0
    const cfg = getCleanupConfig()

    // Clean stale typing indicators
    const typingThreshold = now - cfg.typingThresholdMs
    for (const [key, indicator] of this.typingIndicators.entries()) {
      if (indicator.updatedAt < typingThreshold) {
        this.typingIndicators.delete(key)
        cleaned++
      }
    }

    // Clean stale presence
    const presenceThreshold = now - (cfg.presenceThresholdMinutes * 60 * 1000)
    for (const [userId, presence] of this.userPresence.entries()) {
      if (presence.lastSeen < presenceThreshold) {
        this.userPresence.delete(userId)
        cleaned++
      }
    }

    // Clean stale uploads
    const uploadThreshold = now - (cfg.uploadThresholdHours * 60 * 60 * 1000)
    for (const [key, upload] of this.activeUploads.entries()) {
      if (upload.startedAt < uploadThreshold) {
        this.activeUploads.delete(key)
        cleaned++
      }
    }

    if (cleaned > 0) {
      logger.debug({ cleaned }, 'Cleanup completed')
    }
  }

  private checkMemoryUsage(): void {
    // Calculate approximate memory usage
    let total = 0
    total += this.memoryStats.userCache
    total += this.memoryStats.sessionCache
    total += this.estimateMapSize(this.connectedUsers)
    total += this.estimateMapSize(this.conversationOwners)
    total += this.estimateMapSize(this.userPresence)
    total += this.estimateMapSize(this.typingIndicators)
    total += this.estimateMapSize(this.activeUploads)
    total += this.estimateMapSize(this.pendingEmails)
    
    this.currentMemoryUsage = total

    // Log stats
    logger.info({
      totalMB: Math.round(total / 1024 / 1024),
      limitMB: MEMORY_LIMIT_MB,
      utilization: Math.round((total / MEMORY_LIMIT_BYTES) * 100),
      caches: {
        userCache: { size: this.userCache.size, mb: Math.round(this.memoryStats.userCache / 1024 / 1024) },
        sessionCache: { size: this.sessionValidationCache.size, mb: Math.round(this.memoryStats.sessionCache / 1024 / 1024) },
        connectedUsers: this.connectedUsers.size,
        conversationOwners: this.conversationOwners.size
      }
    }, 'Memory usage report')

    // Warn if approaching limit
    if (total > MEMORY_LIMIT_BYTES * 0.85) {
      logger.warn({ 
        usageMB: Math.round(total / 1024 / 1024),
        limitMB: MEMORY_LIMIT_MB 
      }, 'Memory usage approaching limit!')
      
      // Force aggressive eviction
      this.forceEviction()
    }
  }

  private estimateMapSize(map: Iterable<[unknown, unknown]>): number {
    let size = 0
    for (const [key, value] of map) {
      size += estimateObjectSize(key) + estimateObjectSize(value)
    }
    return size
  }

  private forceEviction(): void {
    logger.warn('Forcing aggressive cache eviction')
    
    // Evict 20% of each cache
    const userEvictCount = Math.floor(this.userCache.size * 0.2)
    const sessionEvictCount = Math.floor(this.sessionValidationCache.size * 0.2)
    
    let evicted = 0
    
    // Evict oldest users (LRU does this automatically, but we force it)
    for (const key of this.userCache.keys()) {
      if (evicted >= userEvictCount) break
      this.userCache.delete(key)
      evicted++
    }
    
    // Evict session validations
    evicted = 0
    for (const key of this.sessionValidationCache.keys()) {
      if (evicted >= sessionEvictCount) break
      this.sessionValidationCache.delete(key)
      evicted++
    }
    
    // Clear non-critical maps
    this.userNames.clear()
    this.emailPreferences.clear()
    
    logger.warn({ userEvictCount, sessionEvictCount }, 'Aggressive eviction completed')
  }

  // ==========================================================================
  // UTILITIES
  // ==========================================================================

  private clearAll(): void {
    this.userCache.clear()
    this.sessionValidationCache.clear()
    this.connectedUsers.clear()
    this.userPresence.clear()
    this.typingIndicators.clear()
    this.emailPreferences.clear()
    this.pendingEmails.clear()
    this.userNames.clear()
    this.activeUploads.clear()
    this.conversationOwners.clear()
    this.userToConversation.clear()
    this.userSessionKeys.clear()
    
    this.memoryStats = {
      userCache: 0,
      sessionCache: 0,
      connectedUsers: 0,
      conversationOwners: 0,
      other: 0
    }
  }

  getStats(): object {
    return {
      memory: {
        limitMB: MEMORY_LIMIT_MB,
        usageMB: Math.round(this.currentMemoryUsage / 1024 / 1024),
        utilization: Math.round((this.currentMemoryUsage / MEMORY_LIMIT_BYTES) * 100)
      },
      caches: {
        userCache: {
          size: this.userCache.size,
          max: this.userCache.max
        },
        sessionCache: {
          size: this.sessionValidationCache.size,
          max: this.sessionValidationCache.max
        }
      },
      maps: {
        connectedUsers: this.connectedUsers.size,
        conversationOwners: this.conversationOwners.size,
        typingIndicators: this.typingIndicators.size,
        activeUploads: this.activeUploads.size
      }
    }
  }
}

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

export const serverState = new StateManager()

// ============================================================================
// EXPORT HELPERS (Same API as before)
// ============================================================================

export const addUserToCache = (userId: string, user: CachedUser) => serverState.addUserToCache(userId, user)
export const getUserFromCache = (userId: string) => serverState.getUserFromCache(userId)
export const updateUserCache = (userId: string, updates: Partial<CachedUser>, emit = true) => serverState.updateUserCache(userId, updates, emit)
export const removeUserFromCache = (userId: string, emit = true) => serverState.removeUserFromCache(userId, emit)
export const invalidateUsersByStatus = (status: string, emit = true) => serverState.invalidateUsersByStatus(status, emit)

export const getSessionValidationCache = (userId: string, sessionId: string) => serverState.getSessionValidationCache(userId, sessionId)
export const setSessionValidationCache = (userId: string, sessionId: string, valid: boolean, ttlMs?: number) => serverState.setSessionValidationCache(userId, sessionId, valid, ttlMs)
export const invalidateSessionCache = (userId: string, sessionId: string, emit = true) => serverState.invalidateSessionCache(userId, sessionId, emit)
export const invalidateAllUserSessions = (userId: string, emit = true) => serverState.invalidateAllUserSessions(userId, emit)

export const setConversationOwner = (conversationId: string, userId: string) => serverState.setConversationOwner(conversationId, userId)
export const getUserConversationId = (userId: string) => serverState.getUserConversationId(userId)
export const touchConversationOwner = (conversationId: string) => serverState.touchConversationOwner(conversationId)
export const getConversationOwner = (conversationId: string) => serverState.getConversationOwner(conversationId)

export const addConnectedUser = (userId: string, socketId: string) => serverState.addConnectedUser(userId, socketId)
export const removeConnectedUser = (userId: string, socketId: string) => serverState.removeConnectedUser(userId, socketId)
export const isUserConnected = (userId: string) => serverState.isUserConnected(userId)
export const getUserSocketCount = (userId: string) => serverState.getUserSocketCount(userId)

export const setUserPresence = (userId: string, status: UserPresence['status']) => serverState.setUserPresence(userId, status)
export const getUserPresence = (userId: string) => serverState.getUserPresence(userId)

export const setTypingIndicator = (conversationId: string, userId: string) => serverState.setTypingIndicator(conversationId, userId)
export const clearTypingIndicator = (conversationId: string, userId: string) => serverState.clearTypingIndicator(conversationId, userId)
export const getTypingUsers = (conversationId: string) => serverState.getTypingUsers(conversationId)

export const getCacheStats = () => serverState.getStats()

export default serverState
