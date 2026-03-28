import { Redis } from 'ioredis'
import { logger } from './lib/logger.js'

let redisInstance: Redis | null = null

export function getRedis(): Redis | null {
  if (redisInstance) return redisInstance

  const redisUrl = process.env.UPSTASH_REDIS_URL
  if (!redisUrl) {
    logger.info('UPSTASH_REDIS_URL not provided. Proceeding without Redis (socket fragmentation and email duplication risks remain on multi-container setups).')
    return null
  }

  try {
    // Upstash requires TLS for secure connections
    const isUpstash = redisUrl.includes('upstash.io')
    
    redisInstance = new Redis(redisUrl, {
      tls: isUpstash ? { rejectUnauthorized: false } : undefined,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000)
        return delay
      },
      maxRetriesPerRequest: 3,
    })

    redisInstance.on('error', (err) => {
      logger.error({ err: err.message }, 'Redis connection error')
    })

    redisInstance.on('connect', () => {
      logger.info('Connected to Redis (Upstash) successfully')
    })

    return redisInstance
  } catch (err) {
    logger.error({ err }, 'Failed to initialize Redis client')
    return null
  }
}
