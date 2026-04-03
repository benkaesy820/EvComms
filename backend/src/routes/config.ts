import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { ulid } from 'ulid'
import { getConfig, getBrand, updateBrand, brandSchema, atomicWriteConfig, storefrontSchema, type AppConfig } from '../lib/config.js'
import { db } from '../db/index.js'
import { auditLogs } from '../db/schema.js'
import { requireSuperAdmin, sendError } from '../middleware/auth.js'
import { createRateLimiters } from '../middleware/rateLimit.js'
import { anonymizeIpAddress } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import { getIO } from '../socket/index.js'
import { env } from '../lib/env.js'
import { enforceMaxDevicesGlobally } from '../auth/index.js'

const subsidiarySchema = z.object({
  id: z.string().min(1).max(26),
  name: z.string().min(1).max(100),
  description: z.string().max(300).optional(),
  url: z.string().url().optional().or(z.literal('')),
  industry: z.string().max(60).optional(),
  founded: z.string().max(10).optional(),
})

const featuresSchema = z.object({
  userRegistration: z.boolean(),
  mediaUpload: z.boolean(),
  messageDelete: z.boolean().optional(),
  messageDeleteTimeLimitSeconds: z.number().int().positive().optional(),
})

const limitsSchema = z.object({
  message: z.object({
    textMaxLength: z.number().int().positive().max(10000),
    teamTextMaxLength: z.number().int().positive().max(10000).optional(),
    perMinute: z.number().int().positive().optional(),
    perHour: z.number().int().positive().optional(),
  }).optional(),
  media: z.object({
    maxSizeImage: z.number().positive(),
    maxSizeDocument: z.number().positive(),
    perDay: z.number().int().positive().optional(),
  }).optional(),
  upload: z.object({
    presignedUrlTTL: z.number().int().min(60).max(3600).optional(),
  }).optional(),
})

const securitySchema = z.object({
  rateLimit: z.object({
    login: z.object({
      maxAttempts: z.number().int().positive(),
      windowMinutes: z.number().int().positive(),
      lockoutMinutes: z.number().int().positive(),
    }).optional(),
    api: z.object({
      requestsPerMinute: z.number().int().positive(),
    }).optional(),
  }).optional(),
  session: z.object({
    maxDevices: z.number().int().positive(),
    accessTokenDays: z.number().int().positive(),
  }).optional(),
  allowedMimeTypes: z.object({
    image: z.array(z.string()),
    document: z.array(z.string()),
  }).optional(),
})

const storageSchema = z.object({
  timeoutMs: z.number().int().positive().optional(),
  circuitBreaker: z.object({
    failureThreshold: z.number().int().positive().optional(),
    recoveryTimeoutMs: z.number().int().positive().optional(),
  }).optional(),
  retry: z.object({
    maxAttempts: z.number().int().positive().optional(),
    baseDelayMs: z.number().int().positive().optional(),
  }).optional(),
  imagekitPublicKey: z.string().optional(),
  imagekitUrlEndpoint: z.string().url().optional()
})

export async function configRoutes(fastify: FastifyInstance) {
  const rateLimiters = createRateLimiters()

  // Config GET is read-only and consumed by 28+ frontend components on mount.
  // Rate limiting here causes 429 cascades on initial load / server restart.
  fastify.get('/', async (_request, reply) => {
    const config = getConfig()
    const brand = getBrand()
    return reply.send({
      success: true,
      brand,
      features: config.features,
      limits: {
        message: { 
          textMaxLength: config.limits.message.textMaxLength,
          teamTextMaxLength: config.limits.message.teamTextMaxLength,
          perMinute: config.limits.message.perMinute,
          perHour: config.limits.message.perHour,
        },
        media: {
          maxSizeImage: config.limits.media.maxSizeImage,
          maxSizeDocument: config.limits.media.maxSizeDocument,
          perDay: config.limits.media.perDay,
        },
        upload: {
          presignedUrlTTL: config.limits.upload.presignedUrlTTL,
        },
      },
      allowedMimeTypes: config.allowedMimeTypes,
      subsidiaries: config.subsidiaries ?? [],
      storage: {
        timeoutMs: config.storage.timeoutMs,
        circuitBreaker: config.storage.circuitBreaker,
        retry: config.storage.retry,
        imagekitPublicKey: config.storage.imagekitPublicKey,
        imagekitUrlEndpoint: config.storage.imagekitUrlEndpoint
      },
      rateLimit: {
        login: {
          maxAttempts: config.rateLimit.login.maxAttempts,
          windowMinutes: config.rateLimit.login.windowMinutes,
          lockoutMinutes: config.rateLimit.login.lockoutMinutes,
        },
        api: {
          requestsPerMinute: config.rateLimit.api.requestsPerMinute,
        },
      },
      session: {
        maxDevices: config.session.maxDevices,
        accessTokenDays: config.session.accessTokenDays,
      },
      assignment: {
        maxConversationsPerAdmin: config.assignment?.maxConversationsPerAdmin ?? 25,
        superAdminThreshold: config.assignment?.superAdminThreshold ?? 0.8,
        preferOnlineAdmins: config.assignment?.preferOnlineAdmins ?? true,
      },
      // Non-secret ImageKit public key — safe to expose, required by frontend SDK
      imagekitPublicKey: config.storage.imagekitPublicKey ?? env.imagekitPublicKey ?? null,
      // Storefront content (FAQ, landing copy, contact, social, legal)
      storefront: config.storefront ?? null,
    })
  })

  fastify.patch('/brand', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = brandSchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid brand data', result.error.issues)
    }

    try {
      await updateBrand(result.data)

      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(),
          userId: request.user.id,
          ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.brand_update',
          entityType: 'config',
          entityId: 'brand',
          details: JSON.stringify({ siteName: result.data.siteName })
        })
      }

      logger.info({ userId: request.user?.id }, 'Brand updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, brand: result.data })
    } catch (error) {
      logger.error({ error }, 'Brand update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update brand')
    }
  })

  fastify.patch('/features', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = featuresSchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid features data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const existing = (cfg.features as Record<string, unknown>) ?? {}
        cfg.features = { ...existing, ...result.data }
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.features_update', entityType: 'config', entityId: 'features',
          details: JSON.stringify(result.data)
        })
      }
      logger.info({ userId: request.user?.id }, 'Features updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, features: result.data })
    } catch (error) {
      logger.error({ error }, 'Features update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update features')
    }
  })

  fastify.patch('/limits', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = limitsSchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid limits data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const limits = cfg.limits as Record<string, unknown>
        if (result.data.message) {
          const existing = (limits.message as Record<string, unknown>) ?? {}
          const merged = { ...existing, ...result.data.message }
          // Ensure rate fields are both present or both absent to prevent half-config (#15)
          if ((merged.perMinute === undefined) !== (merged.perHour === undefined)) {
            throw new Error('Both perMinute and perHour must be set together')
          }
          limits.message = merged
        }
        if (result.data.media) Object.assign((limits.media as Record<string, unknown>), result.data.media)
        if (result.data.upload?.presignedUrlTTL !== undefined) {
          const uploadCfg = (limits.upload as Record<string, unknown>) ?? {}
          uploadCfg.presignedUrlTTL = result.data.upload.presignedUrlTTL
          limits.upload = uploadCfg
        }
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.limits_update', entityType: 'config', entityId: 'limits',
          details: JSON.stringify(result.data)
        })
      }
      logger.info({ userId: request.user?.id }, 'Limits updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, limits: result.data })
    } catch (error) {
      logger.error({ error }, 'Limits update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update limits')
    }
  })

  fastify.patch('/subsidiaries', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = z.array(subsidiarySchema).safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid subsidiaries data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => { cfg.subsidiaries = result.data })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.subsidiaries_update', entityType: 'config', entityId: 'subsidiaries',
          details: JSON.stringify({ count: result.data.length })
        })
      }
      logger.info({ userId: request.user?.id }, 'Subsidiaries updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, subsidiaries: result.data })
    } catch (error) {
      logger.error({ error }, 'Subsidiaries update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update subsidiaries')
    }
  })

  fastify.patch('/security', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = securitySchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid security data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const data = result.data
        const config = cfg as Record<string, unknown>
        if (data.rateLimit?.login) {
          const rateLimit = config.rateLimit as Record<string, unknown>
          Object.assign(rateLimit.login as object, data.rateLimit.login)
        }
        if (data.rateLimit?.api) {
          const rateLimit = config.rateLimit as Record<string, unknown>
          Object.assign(rateLimit.api as object, data.rateLimit.api)
        }
        if (data.session) Object.assign(config.session as object, data.session)
        if (data.allowedMimeTypes) config.allowedMimeTypes = data.allowedMimeTypes
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.security_update', entityType: 'config', entityId: 'security',
          details: JSON.stringify(result.data)
        })
      }
      logger.info({ userId: request.user?.id }, 'Security config updated')
      // Enforce new maxDevices across all users immediately
      if (result.data.session?.maxDevices !== undefined) {
        const enforced = await enforceMaxDevicesGlobally()
        logger.info(enforced, 'maxDevices enforcement after config change')
      }
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true })
    } catch (error) {
      logger.error({ error }, 'Security update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update security config')
    }
  })

  fastify.patch('/storage', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = storageSchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid storage data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const storage = cfg.storage as Record<string, unknown>
        if (result.data.timeoutMs) storage.timeoutMs = result.data.timeoutMs
        if (result.data.circuitBreaker) {
          const cb = (storage.circuitBreaker as Record<string, unknown>) ?? {}
          Object.assign(cb, result.data.circuitBreaker)
          storage.circuitBreaker = cb
        }
        if (result.data.retry) {
          const rt = (storage.retry as Record<string, unknown>) ?? {}
          Object.assign(rt, result.data.retry)
          storage.retry = rt
        }
        if (result.data.imagekitPublicKey !== undefined) {
          storage.imagekitPublicKey = result.data.imagekitPublicKey === '' ? undefined : result.data.imagekitPublicKey
        }
        if (result.data.imagekitUrlEndpoint !== undefined) {
          storage.imagekitUrlEndpoint = result.data.imagekitUrlEndpoint === '' ? undefined : result.data.imagekitUrlEndpoint
        }
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.storage_update', entityType: 'config', entityId: 'storage',
          details: JSON.stringify(result.data)
        })
      }
      logger.info({ userId: request.user?.id }, 'Storage updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, storage: result.data })
    } catch (error) {
      logger.error({ error }, 'Storage update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update storage')
    }
  })

  // PATCH /config/storefront — update FAQ, landing copy, contact, social, legal
  fastify.patch('/storefront', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = storefrontSchema.safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid storefront data', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const existing = (cfg.storefront as Record<string, unknown>) ?? {}
        cfg.storefront = { ...existing, ...result.data }
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.storefront_update', entityType: 'config', entityId: 'storefront',
          details: JSON.stringify({ sections: Object.keys(result.data) })
        })
      }
      logger.info({ userId: request.user?.id }, 'Storefront updated')
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, storefront: result.data })
    } catch (error) {
      logger.error({ error }, 'Storefront update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update storefront')
    }
  })

  // PATCH /config/assignment — update assignment engine settings (real-time, no restart needed)
  fastify.patch('/assignment', { preHandler: [requireSuperAdmin] }, async (request, reply) => {
    const result = z.object({
      maxConversationsPerAdmin: z.number().int().min(1).max(500).optional(),
      superAdminThreshold: z.number().min(0).max(1).optional(),
      preferOnlineAdmins: z.boolean().optional(),
    }).safeParse(request.body)
    if (!result.success) {
      return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid assignment config', result.error.issues)
    }
    try {
      await atomicWriteConfig((cfg) => {
        const existing = (cfg.assignment as Record<string, unknown>) ?? {}
        cfg.assignment = { ...existing, ...result.data }
      })
      if (request.user) {
        await db.insert(auditLogs).values({
          id: ulid(), userId: request.user.id, ipAddress: anonymizeIpAddress(request.ip, 'truncate'),
          action: 'config.assignment_update', entityType: 'config', entityId: 'assignment',
          details: JSON.stringify(result.data),
        })
      }
      logger.info({ userId: request.user?.id, patch: result.data }, 'Assignment config updated')
      // Broadcast so all connected admin clients re-fetch config immediately
      try { getIO().emit('cache:invalidate', { keys: ['appConfig'] }) } catch (e) { logger.error(e, 'Failed to broadcast config update') }
      return reply.send({ success: true, assignment: result.data })
    } catch (error) {
      logger.error({ error }, 'Assignment config update failed')
      return sendError(reply, 500, 'INTERNAL_ERROR', 'Failed to update assignment config')
    }
  })
}
