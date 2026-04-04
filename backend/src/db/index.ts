import { drizzle, LibSQLDatabase } from 'drizzle-orm/libsql'
import { sql } from 'drizzle-orm'
import { createClient, type Client } from '@libsql/client'
import { env } from '../lib/env.js'
import { logger } from '../lib/logger.js'
import { getConfig } from '../lib/config.js'
import { CircuitBreaker } from '../lib/circuitBreaker.js'
import { retryWithBackoff } from '../lib/utils.js'
import { emitToAdmins } from '../socket/index.js'
import { forceLogoutSession } from '../socket/index.js'
import * as schema from './schema.js'
import { sessions, refreshTokens, passwordResetTokens } from './schema.js'

// 15s instead of 8s to tolerate primary DB scale-to-zero cold boots 
// and cross-ocean packet loss on stateless edge environments
const DEFAULT_DB_TIMEOUT_MS = 15000

let rawClient: Client | null = null
let wrappedClient: Client | null = null
let db: LibSQLDatabase<typeof schema> | null = null

/**
 * Detect libsql hrana stream expiry or transient transport errors.
 * libsql streams expire after ~15s of inactivity (tursodatabase/libsql#985).
 * 503 = Turso edge gateway transient, also retryable.
 */
function isStreamExpired(error: unknown): boolean {
  if (error instanceof Error) {
    const msg = error.message
    return (
      msg.includes('STREAM_EXPIRED') ||
      msg.includes('stream has expired') ||
      msg.includes('HRANA_WEBSOCKET_ERROR') ||
      msg.includes('WebSocket was closed')
    )
  }
  return false
}

function isTransientServerError(error: unknown): boolean {
  if (error instanceof Error) {
    const msg = error.message
    return msg.includes('SERVER_ERROR') || msg.includes('503')
  }
  return false
}

async function rebuildClient(): Promise<Client> {
  rawClient = null
  wrappedClient = null
  db = null
  logger.warn('Rebuilding libsql client after stream expiry')
  await createDbClient()
  db = drizzle(wrappedClient!, { schema, logger: env.isDev })
  return rawClient!
}

function getTimeoutMs(): number {
  try {
    return getConfig().server?.requestTimeoutMs ?? DEFAULT_DB_TIMEOUT_MS
  } catch {
    return DEFAULT_DB_TIMEOUT_MS
  }
}

function withDbTimeout<T>(promise: Promise<T>, timeoutMs: number = getTimeoutMs()): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Database operation timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    promise
      .then((result) => {
        clearTimeout(timeoutId)
        resolve(result)
      })
      .catch((error) => {
        clearTimeout(timeoutId)
        reject(error)
      })
  })
}

const dbCircuitBreaker = new CircuitBreaker({
  name: 'Database',
  // DB has its own circuit breaker config — independent from storage/ImageKit.
  // Storage CB is tuned for CDN latency; DB CB is tuned for query latency.
  // Using separate values prevents a storage config change from silently
  // altering DB resilience behavior.
  failureThreshold: getConfig().security?.password?.argon2Iterations ? 5 : 5,
  recoveryTimeoutMs: 30_000,
  onStateChange: (state, failures) => {
    logger.warn({ name: 'Database', state, failures }, 'Circuit breaker state changed')
    if (state === 'OPEN') {
      try {
        emitToAdmins('database:circuit_opened', {
          state,
          failures,
          timestamp: Date.now()
        })
      } catch (error) {
        logger.debug({
          error: error instanceof Error ? error.message : 'Unknown error'
        }, 'Unable to emit database circuit event')
      }
    }
  }
})

function wrapClientWithResilience(client: Client): Client {
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'execute') {
        return async (...args: unknown[]) => {
          const fn = Reflect.get(target, prop, receiver) as (...args: unknown[]) => Promise<unknown>
          try {
            return withDbCircuitBreaker(() => withDbTimeout(fn.apply(target, args)))
          } catch (error) {
            if (isStreamExpired(error) || isTransientServerError(error)) {
              await rebuildClient()
              const newClient = getClient()
              const newFn = Reflect.get(newClient, prop, receiver) as (...args: unknown[]) => Promise<unknown>
              return withDbCircuitBreaker(() => withDbTimeout(newFn.apply(newClient, args)))
            }
            throw error
          }
        }
      }

      if (prop === 'batch') {
        return async (...args: unknown[]) => {
          const fn = Reflect.get(target, prop, receiver) as (...args: unknown[]) => Promise<unknown>
          try {
            return withDbCircuitBreaker(() => withDbTimeout(fn.apply(target, args)))
          } catch (error) {
            if (isStreamExpired(error) || isTransientServerError(error)) {
              await rebuildClient()
              const newClient = getClient()
              const newFn = Reflect.get(newClient, prop, receiver) as (...args: unknown[]) => Promise<unknown>
              return withDbCircuitBreaker(() => withDbTimeout(newFn.apply(newClient, args)))
            }
            throw error
          }
        }
      }

      // Wrap transaction() so it also goes through the circuit breaker and timeout.
      // Without this, db.transaction() bypasses all resilience logic — if Turso drops
      // the connection mid-pipeline the circuit breaker never sees the failure.
      if (prop === 'transaction') {
        return async (...args: unknown[]) => {
          const fn = Reflect.get(target, prop, receiver) as (...args: unknown[]) => Promise<unknown>
          try {
            return withDbCircuitBreaker(() => withDbTimeout(fn.apply(target, args), getTimeoutMs() * 2))
          } catch (error) {
            if (isStreamExpired(error) || isTransientServerError(error)) {
              await rebuildClient()
              const newClient = getClient()
              const newFn = Reflect.get(newClient, prop, receiver) as (...args: unknown[]) => Promise<unknown>
              return withDbCircuitBreaker(() => withDbTimeout(newFn.apply(newClient, args), getTimeoutMs() * 2))
            }
            throw error
          }
        }
      }

      const value = Reflect.get(target, prop, receiver)
      if (typeof value === 'function') {
        return value.bind(target)
      }
      return value
    }
  })
}

async function createDbClient(): Promise<Client> {
  if (rawClient) return rawClient

  const url = env.databaseUrl
  const authToken = env.authToken

  logger.info({ url: url.substring(0, 25) + '...', hasAuth: !!authToken }, 'Creating database client')

  if (!authToken) {
    throw new Error('TURSO_AUTH_TOKEN is required for remote database')
  }

  const config = getConfig()
  
  rawClient = createClient({
    url,
    authToken,
    // libsql manages connection pooling internally; no poolSize config exposed
  })

  wrappedClient = wrapClientWithResilience(rawClient)
  
  logger.info('Database client initialized with resilience wrapper')
  
  return rawClient
}

function getClient(): Client {
  if (!rawClient) {
    throw new Error('Database client not initialized. Call initDb() first.')
  }
  return wrappedClient || rawClient
}

export async function initDb(): Promise<LibSQLDatabase<typeof schema>> {
  if (db) return db

  await createDbClient()

  // IMPORTANT: use wrappedClient (not rawClient) so every Drizzle operation
  // goes through the circuit breaker + timeout proxy. rawClient bypasses both.
  db = drizzle(wrappedClient!, {
    schema,
    logger: env.isDev
  })

  logger.info('Drizzle ORM initialized with resilience-wrapped database client')
  
  // PRE-WARM: Excite the LibSQL connection immediately so the first user request 
  // on a newly scaled container doesn't eat the TLS handshake + auth 1RTT penalty.
  try {
    await withDbTimeout(wrappedClient!.execute('SELECT 1'), 5000)
    logger.info('Database Edge connection pre-warmed successfully')
  } catch (error) {
    logger.warn({ error: error instanceof Error ? error.message : String(error) }, 'Database pre-warm failed or timed out, but continuing init')
  }

  return db
}

export function getDb(): LibSQLDatabase<typeof schema> {
  if (!db) {
    throw new Error('Database not initialized. Call initDb() first at startup.')
  }
  return db
}

export function getDbClient(): Client {
  return getClient()
}

export const dbReady: Promise<void> = Promise.resolve()

const database = new Proxy({} as LibSQLDatabase<typeof schema>, {
  get(_target, prop, receiver) {
    if (!db) throw new Error('Database accessed before initialization. Call initDb() first.')
    const value = Reflect.get(db, prop, receiver)
    return typeof value === 'function' ? value.bind(db) : value
  }
})
export { database as db }

export { schema }

export async function checkDbHealth(): Promise<{
  status: 'healthy' | 'degraded' | 'unhealthy'
  latency?: number
  error?: string
}> {
  try {
    const start = Date.now()
    await retryWithBackoff(async () => {
      const client = getClient()
      await client.execute('SELECT 1')
    }, 2, 250)

    const latency = Date.now() - start

    if (latency > 1000) {
      return { status: 'degraded', latency }
    }

    return { status: 'healthy', latency }
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error'
    }
  }
}

export async function cleanupExpiredSessions(): Promise<{ cleaned: number; expiredByUser: Map<string, string[]> }> {
  const nowSec = Math.floor(Date.now() / 1000)
  const expiredByUser = new Map<string, string[]>()

  try {
    let totalCleaned = 0
    const client = getClient()
    const batchSize = getConfig().db?.listLimit ?? 500

    while (true) {
      const expiredResult = await withDbTimeout(
        client.execute(
          'SELECT id, user_id FROM sessions WHERE revoked_at IS NULL AND expires_at < ? LIMIT ?',
          [nowSec, batchSize]
        ),
        10000
      )
      
      const expiredSessions = expiredResult.rows as unknown as { id: string; user_id: string }[]
      if (expiredSessions.length === 0) break

      const sessionIds = expiredSessions.map(s => s.id)

      // Group by user for socket notifications
      for (const s of expiredSessions) {
        const existing = expiredByUser.get(s.user_id) ?? []
        existing.push(s.id)
        expiredByUser.set(s.user_id, existing)
      }

      try {
        await withDbCircuitBreaker(() => withDbTimeout(
          client.execute('BEGIN TRANSACTION'),
          5000
        ))

        try {
          await withDbCircuitBreaker(() => withDbTimeout(
            client.execute(
              `UPDATE refresh_tokens SET revoked_at = ? WHERE revoked_at IS NULL AND session_id IN (${sessionIds.map(() => '?').join(',')})`,
              [nowSec, ...sessionIds]
            ),
            10000
          ))

          await withDbCircuitBreaker(() => withDbTimeout(
            client.execute(
              `UPDATE sessions SET revoked_at = ? WHERE id IN (${sessionIds.map(() => '?').join(',')})`,
              [nowSec, ...sessionIds]
            ),
            10000
          ))

          await withDbCircuitBreaker(() => withDbTimeout(client.execute('COMMIT'), 5000))
        } catch (error) {
          await client.execute('ROLLBACK').catch(() => {})
          throw error
        }
      } catch (error) {
        logger.error({ error, sessionCount: sessionIds.length }, 'Failed to cleanup session batch')
      }

      // Force-logout connected sockets for each revoked session in this batch
      for (const s of expiredSessions) {
        try { forceLogoutSession(s.id, 'Session expired') } catch { /* socket not ready */ }
      }

      totalCleaned += sessionIds.length
      if (expiredSessions.length < batchSize) break
    }

    await withDbTimeout(
      client.execute(
        'DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL OR expires_at < ?',
        [nowSec]
      ),
      10000
    )

    if (totalCleaned > 0) {
      logger.info({ cleaned: totalCleaned, usersAffected: expiredByUser.size }, 'Expired sessions cleaned')
    }

    return { cleaned: totalCleaned, expiredByUser }
  } catch (error) {
    logger.error({ error }, 'Session cleanup failed')
    return { cleaned: 0, expiredByUser }
  }
}

export async function closeDb(): Promise<void> {
  if (rawClient) {
    try {
      await rawClient.close()
    } catch (error) {
      logger.error({ error }, 'Error closing database client')
    }
    rawClient = null
    wrappedClient = null
    db = null
    logger.info('Database connection closed')
  }
}

export { sessions, refreshTokens }

export function getDbCircuitBreakerState(): { state: string; failures: number } {
  return dbCircuitBreaker.getState()
}

export async function withDbCircuitBreaker<T>(operation: () => Promise<T>): Promise<T> {
  return dbCircuitBreaker.execute(operation)
}
