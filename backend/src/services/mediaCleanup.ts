import { and, eq, lt, inArray, isNull } from 'drizzle-orm'
import { db } from '../db/index.js'
import { media } from '../db/schema.js'
import { deleteFromR2 } from './storage.js'
import { getConfig } from '../lib/config.js'
import { emitToAdmins } from '../socket/index.js'
import { retryWithBackoff } from '../lib/utils.js'
import { logger } from '../lib/logger.js'

// Media cleanup service following CLEANUP:batch and ERR:retry(exp) principles
export class MediaCleanupService {
  private cleanupInterval: NodeJS.Timeout | null = null

  start(): void {
    if (this.cleanupInterval) {
      this.stop()
    }

    const config = getConfig()
    const intervalMs = config.presence.sessionDbCleanupIntervalMs

    // Delay the first run to avoid racing with the initial DB sync pull.
    // The interval-based follow-up runs are unaffected by this delay.
    setTimeout(() => {
      this.runCleanup().catch((error) => {
        logger.error({ error }, 'Initial media cleanup run failed')
        emitToAdmins('cleanup:error', {
          service: 'media',
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now()
        })
      })
    }, 5_000)

    this.cleanupInterval = setInterval(async () => {
      try {
        await this.runCleanup()
      } catch (error) {
        emitToAdmins('cleanup:error', {
          service: 'media',
          error: error instanceof Error ? error.message : 'Unknown error',
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
    const staleThreshold = new Date(Date.now() - config.limits.upload.confirmTimeout * 1000)
    const staleMedia = await db.query.media.findMany({
      where: and(eq(media.status, 'PENDING'), lt(media.uploadedAt, staleThreshold)),
      columns: { id: true, r2Key: true }
    })
    if (staleMedia.length > 0) {
      const { cleanedCount, failedCount } = await this.cleanStaleMedia(staleMedia)
      emitToAdmins('cleanup:media_completed', { cleanedCount, failedCount, totalProcessed: staleMedia.length, timestamp: Date.now() })
    }

    // Purge FAILED records older than 7 days that are not attached to any message
    await this.purgeFailedMedia()
  }

  private async purgeFailedMedia(): Promise<void> {
    const FAILED_RETAIN_MS = 7 * 24 * 60 * 60 * 1000
    const CONCURRENCY = 5
    const cutoff = new Date(Date.now() - FAILED_RETAIN_MS)
    const failedMedia = await db.query.media.findMany({
      where: and(eq(media.status, 'FAILED'), lt(media.uploadedAt, cutoff), isNull(media.messageId)),
      columns: { id: true, r2Key: true }
    })
    if (failedMedia.length === 0) return

    const deletedIds: string[] = []

    for (let i = 0; i < failedMedia.length; i += CONCURRENCY) {
      const batch = failedMedia.slice(i, i + CONCURRENCY)
      const results = await Promise.allSettled(
        batch.map(async (item) => {
          const config = getConfig()
          await retryWithBackoff(() => deleteFromR2(item.r2Key), config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
          return item.id
        })
      )
      for (let j = 0; j < results.length; j++) {
        const r = results[j]!
        if (r.status === 'fulfilled') {
          deletedIds.push(r.value)
        } else {
          logger.warn({ mediaId: batch[j]!.id, reason: r.reason }, 'Failed to delete FAILED media from R2')
        }
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
    const staleMedia = await db.query.media.findMany({
      where: and(eq(media.status, 'PENDING'), lt(media.uploadedAt, staleThreshold)),
      columns: { id: true, r2Key: true }
    })
    return this.cleanStaleMedia(staleMedia)
  }

  private async cleanStaleMedia(staleMedia: { id: string; r2Key: string }[]): Promise<{ cleanedCount: number; failedCount: number }> {
    if (staleMedia.length === 0) return { cleanedCount: 0, failedCount: 0 }

    const CONCURRENCY = 5
    const cleanedIds: string[] = []
    let failedCount = 0

    // Process in parallel batches — avoids N × R2 latency waterfall
    for (let i = 0; i < staleMedia.length; i += CONCURRENCY) {
      const batch = staleMedia.slice(i, i + CONCURRENCY)
      const results = await Promise.allSettled(
        batch.map(async (item) => {
          const config = getConfig()
          await retryWithBackoff(() => deleteFromR2(item.r2Key), config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
          return item.id
        })
      )

      for (let j = 0; j < results.length; j++) {
        const result = results[j]!
        if (result.status === 'fulfilled') {
          cleanedIds.push(result.value)
        } else {
          failedCount++
          const item = batch[j]!
          emitToAdmins('cleanup:media_failed', {
            mediaId: item.id,
            r2Key: item.r2Key,
            error: result.reason instanceof Error ? result.reason.message : 'Unknown error',
            timestamp: Date.now()
          })
        }
      }
    }

    if (cleanedIds.length > 0) {
      // Bulk delete — all confirmed R2 deletes in one query
      await db.delete(media).where(inArray(media.id, cleanedIds))
    }

    return { cleanedCount: cleanedIds.length, failedCount }
  }
}

// Singleton instance
export const mediaCleanupService = new MediaCleanupService()
