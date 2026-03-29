import type { FastifyInstance } from 'fastify'
import { checkDbHealth } from '../db/index.js'
import { requireAdmin } from '../middleware/auth.js'
import { serverState } from '../state.js'
import { getRateLimitStats, createRateLimiters } from '../middleware/rateLimit.js'
import { getCircuitBreakerState, checkStorageHealth } from '../services/storage.js'
import { getConnectedUsersCount } from '../socket/index.js'
import { getCacheConfig } from '../lib/config.js'

let cachedHealthResult: unknown = null
let cachedHealthAt = 0

export async function healthRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  fastify.get('/health', { preHandler: rateLimiters.api }, async (request, reply) => {
    const now = Date.now()
    const cacheConfig = getCacheConfig()

    // Only serve cached result when it was healthy — never serve a stale healthy
    // response to a PaaS load balancer while the DB is actually down.
    if (cachedHealthResult && now - cachedHealthAt < cacheConfig.healthTTLMs) {
      return reply.send(cachedHealthResult)
    }

    const startedAt = now
    try {
      const dbHealth = await checkDbHealth()

      const response = {
        status: dbHealth.status === 'healthy' ? 'ok' :
          dbHealth.status === 'degraded' ? 'degraded' : 'error',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: { status: dbHealth.status },
        responseTime: Date.now() - startedAt
      }

      const statusCode = dbHealth.status === 'healthy' ? 200 :
        dbHealth.status === 'degraded' ? 200 : 503

      // Cache ONLY when healthy — degraded/unhealthy must always re-check
      if (dbHealth.status === 'healthy') {
        cachedHealthResult = response
        cachedHealthAt = Date.now()
      } else {
        cachedHealthResult = null
        cachedHealthAt = 0
      }

      return reply.code(statusCode).send(response)
    } catch (error) {
      cachedHealthResult = null
      cachedHealthAt = 0
      return reply.code(503).send({
        status: 'error',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: { status: 'unhealthy' },
        responseTime: Date.now() - startedAt
      })
    }
  })

  fastify.get('/health/detailed', { preHandler: requireAdmin }, async (request, reply) => {
    const startedAt = Date.now()
    const memory = process.memoryUsage()

    try {
      const [dbHealth, storageHealth, stateStats, rateLimitStats, circuitBreakerState] = await Promise.all([
        checkDbHealth(),
        checkStorageHealth(),
        serverState.getStats(),
        getRateLimitStats(),
        getCircuitBreakerState()
      ])

      const response = {
        status: dbHealth.status === 'healthy' && storageHealth.status === 'healthy' ? 'ok' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
          rss: Math.round(memory.rss / 1024 / 1024),
          heapUsed: Math.round(memory.heapUsed / 1024 / 1024),
          heapTotal: Math.round(memory.heapTotal / 1024 / 1024),
          external: Math.round(memory.external / 1024 / 1024)
        },
        database: {
          status: dbHealth.status,
          latency: dbHealth.latency
        },
        storage: {
          status: storageHealth.status,
          latency: storageHealth.latency,
          circuitBreaker: circuitBreakerState,
          connected: circuitBreakerState.state === 'CLOSED'
        },
        state: stateStats,
        rateLimit: rateLimitStats,
        sockets: {
          connected: getConnectedUsersCount()
        },
        responseTime: Date.now() - startedAt
      }

      return reply.send(response)
    } catch (error) {
      return reply.code(503).send({
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
        responseTime: Date.now() - startedAt
      })
    }
  })
}
