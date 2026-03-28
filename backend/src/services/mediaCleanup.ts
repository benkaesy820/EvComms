import { inArray } from 'drizzle-orm'
import { db, getDbClient } from '../db/index.js'
import { media } from '../db/schema.js'
import { deleteFromR2 } from './storage.js'
import { getConfig } from '../lib/config.js'
import { emitToAdmins } from '../socket/index.js'
import { retryWithBackoff } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { env } from '../lib/env.js'

// Media cleanup service following CLEANUP:batch and ERR:retry(exp) principles
export class MediaCleanupService {
  private cleanupInterval: NodeJS.Timeout | null = null

  start(): void {
    if (this.cleanupInterval) {
      this.stop()
    }

    const config = getConfig()
    const intervalMs = config.storage.cleanup?.mediaCleanupIntervalMs ?? 300_000

    // Delay the first run to avoid racing with the initial DB sync pull.
    // The interval-based follow-up runs are unaffected by this delay.
    setTimeout(() => {
      this.runCleanup().catch((error) => {
        const message = error instanceof Error ? error.message : (typeof error === 'object' ? JSON.stringify(error) : String(error))
        logger.error({ error: message }, 'Initial media cleanup run failed')
        emitToAdmins('cleanup:error', {
          service: 'media',
          error: message,
          timestamp: Date.now()
        })
      })
    }, 5_000)

    this.cleanupInterval = setInterval(async () => {
      try {
        await this.runCleanup()
      } catch (error) {
        const message = error instanceof Error ? error.message : (typeof error === 'object' ? JSON.stringify(error) : String(error))
        logger.warn({ error: message }, 'Scheduled media cleanup run failed')
        emitToAdmins('cleanup:error', {
          service: 'media',
          error: message,
          timestamp: Date.now()
        })
      }
    }, intervalMs)
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
  }

  private async runCleanup(): Promise<void> {
    const config = getConfig()

    // In development, skip R2 operations if credentials aren't configured.
    // This prevents noisy startup errors when running locally without R2.
    if (env.isDev && (!env.r2AccountId || !env.r2AccessKeyId || !env.r2SecretAccessKey || !env.r2BucketName)) {
      logger.debug('Media cleanup skipped — R2 not configured in development')
      return
    }

    const staleThreshold = new Date(Date.now() - config.limits.upload.confirmTimeout * 1000)
    const staleThresholdSec = Math.floor(staleThreshold.getTime() / 1000)
    logger.info({ staleThresholdSec }, 'Running media cleanup')
    
    // Use raw libsql client to bypass drizzle's query builder issue
    const client = getDbClient()
    const staleMediaResult = await client.execute(
      'select id, r2_key from media where status = ? and uploaded_at < ?',
      ['PENDING', staleThresholdSec]
    )
    const staleMedia = staleMediaResult.rows as unknown as { id: string; r2_key: string }[]
    
    if (staleMedia.length > 0) {
      const { cleanedCount, failedCount } = await this.cleanStaleMedia(staleMedia)
      emitToAdmins('cleanup:media_completed', { cleanedCount, failedCount, totalProcessed: staleMedia.length, timestamp: Date.now() })
    }

    // Purge FAILED records older than 7 days that are not attached to any message
    await this.purgeFailedMedia()
  }

  private async purgeFailedMedia(): Promise<void> {
    const config = getConfig()
    const failedRetainDays = config.storage.cleanup?.failedRetainDays ?? 7
    const FAILED_RETAIN_MS = failedRetainDays * 24 * 60 * 60 * 1000
    const cutoffSec = Math.floor((Date.now() - FAILED_RETAIN_MS) / 1000)
    
    // Use raw libsql client to bypass drizzle's query builder issue
    const client = getDbClient()
    const failedMediaResult = await client.execute(
      'select id, r2_key from media where status = ? and uploaded_at < ?',
      ['FAILED', cutoffSec]
    )
    const failedMedia = failedMediaResult.rows as unknown as { id: string; r2_key: string }[]
    
    if (failedMedia.length === 0) return

    const deletedIds: string[] = []
    for (const item of failedMedia) {
      try {
        const config = getConfig()
        await retryWithBackoff(() => deleteFromR2(item.r2_key), config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
        deletedIds.push(item.id)
      } catch (error) {
        logger.warn({ mediaId: item.id, error }, 'Failed to delete FAILED media from R2')
      }
    }
    if (deletedIds.length > 0) {
      await db.delete(media).where(inArray(media.id, deletedIds))
      logger.info({ count: deletedIds.length }, 'Purged stale FAILED media records')
    }
  }

  async triggerManualCleanup(): Promise<{ cleanedCount: number; failedCount: number }> {
    const config = getConfig()
    const staleThreshold = new Date(Date.now() - config.limits.upload.confirmTimeout * 1000)
    const staleThresholdSec = Math.floor(staleThreshold.getTime() / 1000)
    
    // Use raw libsql client to bypass drizzle's query builder issue
    const client = getDbClient()
    const staleMediaResult = await client.execute(
      'select id, r2_key from media where status = ? and uploaded_at < ?',
      ['PENDING', staleThresholdSec]
    )
    const staleMedia = staleMediaResult.rows as unknown as { id: string; r2_key: string }[]
    
    return this.cleanStaleMedia(staleMedia)
  }

  private async cleanStaleMedia(staleMedia: { id: string; r2_key: string }[]): Promise<{ cleanedCount: number; failedCount: number }> {
    if (staleMedia.length === 0) return { cleanedCount: 0, failedCount: 0 }

    const cleanedIds: string[] = []
    let failedCount = 0

    for (const item of staleMedia) {
      try {
        const config = getConfig()
        await retryWithBackoff(() => deleteFromR2(item.r2_key), config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
        cleanedIds.push(item.id)
      } catch (error) {
        failedCount++
        emitToAdmins('cleanup:media_failed', {
          mediaId: item.id,
          r2Key: item.r2_key,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now()
        })
      }
    }

    if (cleanedIds.length > 0) {
      // Delete records outright — files are already removed from R2
      await db.delete(media).where(inArray(media.id, cleanedIds))
    }

    return { cleanedCount: cleanedIds.length, failedCount }
  }
}

// Singleton instance
export const mediaCleanupService = new MediaCleanupService()
