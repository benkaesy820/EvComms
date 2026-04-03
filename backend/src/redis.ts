import { Redis } from 'ioredis'
import { logger } from './lib/logger.js'

let redisInstance: Redis | null = null

export function getRedis(): Redis | null {
  if (redisInstance && redisInstance.status === 'ready') return redisInstance
  // If instance exists but not ready (reconnecting), return it — ioredis will queue commands
  if (redisInstance && redisInstance.status === 'connecting') return redisInstance

  const redisUrl = process.env.UPSTASH_REDIS_URL
  if (!redisUrl) {
    logger.info('UPSTASH_REDIS_URL not provided. Proceeding without Redis (single-server mode).')
    return null
  }

  try {
    const isUpstash = redisUrl.includes('upstash.io')
    
    redisInstance = new Redis(redisUrl, {
      tls: isUpstash ? { rejectUnauthorized: true } : undefined,
      retryStrategy: (times) => {
        // Exponential backoff capped at 30s. Never return null — always
        // keep trying so Redis recovery is automatic after transient outages.
        const delay = Math.min(1000 * Math.pow(1.5, Math.min(times, 12)), 30_000)
        if (times % 12 === 0) {
          logger.warn({ times, delay }, 'Redis still unreachable — will keep retrying')
        }
        return delay
      },
      maxRetriesPerRequest: null,
    })

    redisInstance.on('error', (err) => {
      logger.error({ err: err.message }, 'Redis connection error')
    })

    redisInstance.on('connect', () => {
      logger.info('Connected to Redis successfully')
    })

    redisInstance.on('ready', () => {
      logger.info('Redis ready')
    })

    redisInstance.on('close', () => {
      logger.warn('Redis connection closed — will reconnect')
    })

    redisInstance.on('reconnecting', () => {
      logger.info('Redis reconnecting...')
    })

    return redisInstance
  } catch (err) {
    logger.error({ err }, 'Failed to initialize Redis client')
    return null
  }
}

export async function closeRedis(): Promise<void> {
  if (redisInstance) {
    await redisInstance.quit()
    redisInstance = null
  }
}
