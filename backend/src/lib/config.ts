import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { z } from 'zod'
import { logger } from './logger.js'
import { clusterBus } from './events.js'

const brandSchema = z.object({
    siteName: z.string().min(1),
    tagline: z.string(),
    company: z.string(),
    supportEmail: z.string().email(),
    logoUrl: z.string().optional(),
    primaryColor: z.string().optional(),
    statResponseTime: z.string().optional(),
    statUptime: z.string().optional(),
    statAvailability: z.string().optional()
})

const subsidiarySchema = z.object({
    id: z.string(),
    name: z.string(),
    description: z.string().optional(),
    url: z.string().url().optional(),
    industry: z.string().optional(),
    founded: z.string().optional()
})


const faqItemSchema = z.object({
    id: z.string(),
    question: z.string(),
    answer: z.string(),
})

const storefrontSchema = z.object({
    landing: z.object({
        heroHeadline: z.string().optional(),
        heroSubheadline: z.string().optional(),
        ctaPrimary: z.string().optional(),
        ctaSecondary: z.string().optional(),
        showHowItWorks: z.boolean().optional(),
        showFeatures: z.boolean().optional(),
        showStats: z.boolean().optional(),
    }).optional(),
    contact: z.object({
        responseTime: z.string().optional(),
        officeHours: z.string().optional(),
        address: z.string().optional(),
        phone: z.string().optional(),
        showLiveChat: z.boolean().optional(),
    }).optional(),
    faq: z.array(faqItemSchema).optional(),
    social: z.object({
        twitter: z.string().optional(),
        linkedin: z.string().optional(),
        instagram: z.string().optional(),
        facebook: z.string().optional(),
        youtube: z.string().optional(),
    }).optional(),
    legal: z.object({
        termsLastUpdated: z.string().optional(),
        privacyLastUpdated: z.string().optional(),
        companyLegalName: z.string().optional(),
        registrationNumber: z.string().optional(),
        vatNumber: z.string().optional(),
    }).optional(),
})

export type StorefrontConfig = z.infer<typeof storefrontSchema>
export type FaqItem = z.infer<typeof faqItemSchema>
export { storefrontSchema, faqItemSchema }

export type BrandConfig = z.infer<typeof brandSchema>
export type SubsidiaryConfig = z.infer<typeof subsidiarySchema>

export { brandSchema, subsidiarySchema }

const configSchema = z.object({
    brand: brandSchema.optional(),
    storefront: storefrontSchema.optional(),
    limits: z.object({
        message: z.object({
            textMaxLength: z.number().positive(),
            teamTextMaxLength: z.number().positive().default(5000),
            perMinute: z.number().positive(),
            perHour: z.number().positive()
        }),
        media: z.object({
            maxSizeImage: z.number().positive(),
            maxSizeDocument: z.number().positive(),
            perDay: z.number().positive()
        }),
        upload: z.object({
            presignedUrlTTL: z.number().positive(),
            confirmTimeout: z.number().positive(),
            maxAgeMs: z.number().positive().default(1800000)
        }),
        announcement: z.object({
            maxTitleLength: z.number().positive().default(200),
            maxContentLength: z.number().positive().default(10000),
            maxPollOptions: z.number().positive().default(10),
            maxEmojiLength: z.number().positive().default(10),
            commentMaxLength: z.number().positive().default(1000)
        }).optional(),
        userReport: z.object({
            maxDescriptionLength: z.number().positive().default(5000),
            maxSubjectLength: z.number().positive().default(200),
            maxPerHour: z.number().positive().default(10)
        }).optional(),
        dm: z.object({
            maxContentLength: z.number().positive().default(100000)
        }).optional(),
        conversation: z.object({
            contentMaxLength: z.number().positive().default(100000)
        }).optional()
    }),
    rateLimit: z.object({
        login: z.object({
            maxAttempts: z.number().positive(),
            windowMinutes: z.number().positive(),
            lockoutMinutes: z.number().positive()
        }),
        passwordReset: z.object({
            maxAttempts: z.number().positive(),
            windowMinutes: z.number().positive()
        }),
        passwordChange: z.object({
            maxAttempts: z.number().positive(),
            windowMinutes: z.number().positive()
        }),
        registration: z.object({
            maxAttempts: z.number().positive(),
            windowHours: z.number().positive()
        }),
        api: z.object({
            requestsPerMinute: z.number().positive()
        }),
        stream: z.object({
            maxRequests: z.number().positive(),
            windowMs: z.number().positive(),
            maxEntries: z.number().positive(),
            maxSizeBytes: z.number().positive()
        }).optional(),
        announcement: z.object({
            votePerMinute: z.number().positive().default(10),
            publicRequestsPerMinute: z.number().positive().default(60)
        }).optional(),
        adminPasswordReset: z.object({
            maxAttempts: z.number().positive().default(5),
            windowHours: z.number().positive().default(1)
        }).optional(),
        store: z.object({
            maxEntries: z.number().positive().default(20000),
            maxSizeBytes: z.number().positive().default(1048576),
            loginLockoutMaxEntries: z.number().positive().default(40000),
            loginLockoutMaxSizeBytes: z.number().positive().default(2097152)
        }).optional()
    }),
    session: z.object({
        maxDevices: z.number().positive(),
        passwordResetTokenMinutes: z.number().positive(),
        refreshTokenDays: z.number().positive(),
        accessTokenDays: z.number().positive(),
        validationCacheTTLSeconds: z.number().positive().default(10)
    }),
    email: z.object({
        notification: z.object({
            debounceSeconds: z.number().positive(),
            maxDelaySeconds: z.number().positive(),
            minOfflineSeconds: z.number().positive(),
            maxRetries: z.number().positive(),
            retryBackoffMs: z.number().positive()
        }),
        queue: z.object({
            maxSize: z.number().positive().default(1000),
            drainTimeoutMs: z.number().positive().default(5000),
            sendTimeoutMs: z.number().positive().default(8000),
            defaultMaxQueueSize: z.number().positive().default(1000)
        }).optional(),
        templates: z.object({
            resetTokenExpiryMinutes: z.number().positive().default(30)
        }).optional()
    }),
    storage: z.object({
        timeoutMs: z.number().positive(),
        circuitBreaker: z.object({
            failureThreshold: z.number().positive(),
            recoveryTimeoutMs: z.number().positive()
        }),
        retry: z.object({
            maxAttempts: z.number().positive(),
            baseDelayMs: z.number().positive()
        }),
        imagekitPublicKey: z.string().optional(),
        imagekitUrlEndpoint: z.string().url().optional(),
        imagekitMaxExpireSeconds: z.number().positive().default(1800),
        cleanup: z.object({
            failedRetainDays: z.number().positive().default(7),
            mediaCleanupIntervalMs: z.number().positive().default(300_000) // 5 minutes default
        }).optional()
    }),
    socket: z.object({
        authWindowMs: z.number().positive(),
        authMaxAttempts: z.number().positive(),
        pingTimeoutMs: z.number().positive(),
        pingIntervalMs: z.number().positive(),
        maxTimeoutMs: z.number().positive(),
        maxConnectionsPerIp: z.number().positive().optional(),
        connectionWindowMs: z.number().positive().optional(),
        rateLimiter: z.object({
            maxEntries: z.number().positive().default(10000)
        }).optional(),
        payload: z.object({
            maxSizeBytes: z.number().positive().default(5242880)
        }).optional()
    }),
    presence: z.object({
        typingIndicatorTTL: z.number().positive(),
        awayThresholdMs: z.number().positive(),
        offlineThresholdMs: z.number().positive(),
        cleanupIntervalMs: z.number().positive(),
        sessionDbCleanupIntervalMs: z.number().positive(),
        socketRateCleanupIntervalMs: z.number().positive(),
        typingCleanupThresholdMs: z.number().positive().default(10000),
        presenceCleanupThresholdMinutes: z.number().positive().default(5),
        uploadCleanupThresholdHours: z.number().positive().default(1)
    }),
    allowedMimeTypes: z.object({
        image: z.array(z.string()),
        document: z.array(z.string())
    }),
    features: z.object({
        userRegistration: z.boolean(),
        mediaUpload: z.boolean(),
        messageDelete: z.boolean().optional(),
        messageDeleteTimeLimitSeconds: z.number().positive().default(300)
    }),
    server: z.object({
        maxBodySize: z.number().positive(),
        requestTimeoutMs: z.number().positive(),
        shutdownTimeoutMs: z.number().positive(),
        statsLogIntervalMs: z.number().positive().optional(),
        hstsMaxAgeSeconds: z.number().positive().default(31536000),
        jsonBodyLimit: z.number().positive().default(1048576),
        maxParamLength: z.number().positive().default(100)
    }).optional(),
    cache: z.object({
        maxUserCacheSize: z.number().positive(),
        maxTypingIndicators: z.number().positive(),
        maxActiveUploads: z.number().positive(),
        maxSocketRateLimiters: z.number().positive(),
        maxEmailQueueSize: z.number().positive(),
        maxRateLimitEntries: z.number().positive().optional(),
        rateLimitCleanupIntervalMs: z.number().positive().optional(),
        health: z.object({
            ttlMs: z.number().positive().default(5000)
        }).optional(),
        stats: z.object({
            ttlMs: z.number().positive().default(30000)
        }).optional(),
        memory: z.object({
            totalBudgetMB: z.number().positive().default(200),
            userCacheMax: z.number().positive().default(400000),
            userCacheMaxSizeMB: z.number().positive().default(80),
            sessionCacheMax: z.number().positive().default(400000),
            sessionCacheMaxSizeMB: z.number().positive().default(40),
            connectedUsersMax: z.number().positive().default(50000),
            connectedUsersMaxSizeMB: z.number().positive().default(20),
            userPresenceMax: z.number().positive().default(100000),
            userPresenceMaxSizeMB: z.number().positive().default(10),
            typingIndicatorsMax: z.number().positive().default(50000),
            typingIndicatorsMaxSizeMB: z.number().positive().default(5),
            emailPreferencesMax: z.number().positive().default(50000),
            emailPreferencesMaxSizeMB: z.number().positive().default(5),
            pendingEmailsMax: z.number().positive().default(50000),
            pendingEmailsMaxSizeMB: z.number().positive().default(10),
            userNamesMax: z.number().positive().default(50000),
            userNamesMaxSizeMB: z.number().positive().default(5),
            activeUploadsMax: z.number().positive().default(50000),
            activeUploadsMaxSizeMB: z.number().positive().default(10),
            conversationOwnersMax: z.number().positive().default(100000),
            conversationOwnersMaxSizeMB: z.number().positive().default(20),
            userToConversationMax: z.number().positive().default(100000),
            userToConversationMaxSizeMB: z.number().positive().default(10),
            userSessionKeysMax: z.number().positive().default(50000),
            userSessionKeysMaxSizeMB: z.number().positive().default(10)
        }).optional()
    }).optional(),
    db: z.object({
        defaultTimeoutMs: z.number().positive().default(8000),
        cleanupTransactionTimeoutMs: z.number().positive().default(30000),
        maxLimit: z.number().positive().default(100),
        defaultLimit: z.number().positive().default(50),
        listLimit: z.number().positive().default(500)
    }).optional(),
    security: z.object({
        csrf: z.object({
            tokenLength: z.number().positive().default(32)
        }).optional(),
        password: z.object({
            argon2MemoryKib: z.number().positive().default(65536),
            argon2Iterations: z.number().positive().default(3),
            argon2Parallelism: z.number().positive().default(4)
        }).optional()
    }).optional(),
    pagination: z.object({
        announcementsDefault: z.number().positive().default(20),
        announcementsMax: z.number().positive().default(50),
        conversationsDefault: z.number().positive().default(50),
        conversationsMax: z.number().positive().default(100),
        messagesDefault: z.number().positive().default(50),
        messagesMax: z.number().positive().default(100),
        usersDefault: z.number().positive().default(50),
        usersMax: z.number().positive().default(100),
        adminsDefault: z.number().positive().default(50),
        adminsMax: z.number().positive().default(100),
        internalMessagesDefault: z.number().positive().default(50),
        internalMessagesMax: z.number().positive().default(100),
        dmMessagesDefault: z.number().positive().default(50),
        dmMessagesMax: z.number().positive().default(100),
        auditLogsDefault: z.number().positive().default(50),
        auditLogsMax: z.number().positive().default(100),
        userReportsDefault: z.number().positive().default(20),
        userReportsMax: z.number().positive().default(50)
    }).optional(),
    subsidiaries: z.array(subsidiarySchema).optional().default([]),
    assignment: z.object({
        maxConversationsPerAdmin: z.number().positive().default(25),
        idleThresholdHours: z.number().positive().default(4),
        preferOnlineAdmins: z.boolean().default(true),
        // SUPER_ADMIN only used when ALL eligible ADMINs are at this fraction of max load.
        // 0.8 = SUPER_ADMINs absorb overflow once regular admins hit 80% capacity.
        superAdminThreshold: z.number().min(0).max(1).default(0.8),
    }).optional(),
})

// TypeScript interface matching the schema
export interface AppConfig {
    brand?: BrandConfig
    limits: {
        message: {
            textMaxLength: number
            teamTextMaxLength: number
            perMinute: number
            perHour: number
        }
        media: {
            maxSizeImage: number
            maxSizeDocument: number
            perDay: number
        }
        upload: {
            presignedUrlTTL: number
            confirmTimeout: number
            maxAgeMs?: number
        }
        announcement?: {
            maxTitleLength: number
            maxContentLength: number
            maxPollOptions: number
            maxEmojiLength: number
            commentMaxLength: number
        }
        userReport?: {
            maxDescriptionLength: number
            maxSubjectLength: number
            maxPerHour: number
        }
        dm?: {
            maxContentLength: number
        }
        conversation?: {
            contentMaxLength: number
        }
    }
    rateLimit: {
        login: {
            maxAttempts: number
            windowMinutes: number
            lockoutMinutes: number
        }
        passwordReset: {
            maxAttempts: number
            windowMinutes: number
        }
        passwordChange: {
            maxAttempts: number
            windowMinutes: number
        }
        registration: {
            maxAttempts: number
            windowHours: number
        }
        api: {
            requestsPerMinute: number
        }
        stream?: {
            maxRequests: number
            windowMs: number
            maxEntries: number
            maxSizeBytes: number
        }
        announcement?: {
            votePerMinute: number
            publicRequestsPerMinute: number
        }
        adminPasswordReset?: {
            maxAttempts: number
            windowHours: number
        }
        store?: {
            maxEntries: number
            maxSizeBytes: number
            loginLockoutMaxEntries: number
            loginLockoutMaxSizeBytes: number
        }
    }
    session: {
        maxDevices: number
        passwordResetTokenMinutes: number
        refreshTokenDays: number
        accessTokenDays: number
        validationCacheTTLSeconds: number
    }
    email: {
        notification: {
            debounceSeconds: number
            maxDelaySeconds: number
            minOfflineSeconds: number
            maxRetries: number
            retryBackoffMs: number
        }
        queue?: {
            maxSize: number
            drainTimeoutMs: number
            sendTimeoutMs: number
            defaultMaxQueueSize: number
        }
        templates?: {
            resetTokenExpiryMinutes: number
        }
    }
    storage: {
        timeoutMs: number
        circuitBreaker: {
            failureThreshold: number
            recoveryTimeoutMs: number
        }
        retry: {
            maxAttempts: number
            baseDelayMs: number
        }
        imagekitPublicKey?: string
        imagekitUrlEndpoint?: string
        imagekitMaxExpireSeconds?: number
        cleanup?: {
            failedRetainDays: number
            mediaCleanupIntervalMs: number
        }
    }
    socket: {
        authWindowMs: number
        authMaxAttempts: number
        pingTimeoutMs: number
        pingIntervalMs: number
        maxTimeoutMs: number
        maxConnectionsPerIp?: number
        connectionWindowMs?: number
        rateLimiter?: {
            maxEntries: number
        }
        payload?: {
            maxSizeBytes: number
        }
    }
    presence: {
        typingIndicatorTTL: number
        awayThresholdMs: number
        offlineThresholdMs: number
        cleanupIntervalMs: number
        sessionDbCleanupIntervalMs: number
        socketRateCleanupIntervalMs: number
        typingCleanupThresholdMs?: number
        presenceCleanupThresholdMinutes?: number
        uploadCleanupThresholdHours?: number
    }
    allowedMimeTypes: {
        image: string[]
        document: string[]
    }
    features: {
        userRegistration: boolean
        mediaUpload: boolean
        messageDelete?: boolean
        messageDeleteTimeLimitSeconds?: number
    }
    server?: {
        maxBodySize: number
        requestTimeoutMs: number
        shutdownTimeoutMs: number
        statsLogIntervalMs?: number
        hstsMaxAgeSeconds?: number
        jsonBodyLimit?: number
        maxParamLength?: number
    }
    cache?: {
        maxUserCacheSize: number
        maxTypingIndicators: number
        maxActiveUploads: number
        maxSocketRateLimiters: number
        maxEmailQueueSize: number
        maxRateLimitEntries?: number
        rateLimitCleanupIntervalMs?: number
        health?: {
            ttlMs: number
        }
        stats?: {
            ttlMs: number
        }
        memory?: {
            totalBudgetMB: number
            userCacheMax: number
            userCacheMaxSizeMB: number
            sessionCacheMax: number
            sessionCacheMaxSizeMB: number
            connectedUsersMax: number
            connectedUsersMaxSizeMB: number
            userPresenceMax: number
            userPresenceMaxSizeMB: number
            typingIndicatorsMax: number
            typingIndicatorsMaxSizeMB: number
            emailPreferencesMax: number
            emailPreferencesMaxSizeMB: number
            pendingEmailsMax: number
            pendingEmailsMaxSizeMB: number
            userNamesMax: number
            userNamesMaxSizeMB: number
            activeUploadsMax: number
            activeUploadsMaxSizeMB: number
            conversationOwnersMax: number
            conversationOwnersMaxSizeMB: number
            userToConversationMax: number
            userToConversationMaxSizeMB: number
            userSessionKeysMax: number
            userSessionKeysMaxSizeMB: number
        }
    }
    db?: {
        defaultTimeoutMs: number
        cleanupTransactionTimeoutMs: number
        maxLimit?: number
        defaultLimit?: number
        listLimit?: number
    }
    security?: {
        csrf?: {
            tokenLength: number
        }
        password?: {
            argon2MemoryKib: number
            argon2Iterations: number
            argon2Parallelism: number
        }
    }
    pagination?: {
        announcementsDefault?: number
        announcementsMax?: number
        conversationsDefault?: number
        conversationsMax?: number
        messagesDefault?: number
        messagesMax?: number
        usersDefault?: number
        usersMax?: number
        adminsDefault?: number
        adminsMax?: number
        internalMessagesDefault?: number
        internalMessagesMax?: number
        dmMessagesDefault?: number
        dmMessagesMax?: number
        auditLogsDefault?: number
        auditLogsMax?: number
        userReportsDefault?: number
        userReportsMax?: number
    }
    subsidiaries?: SubsidiaryConfig[]
    assignment?: {
        maxConversationsPerAdmin: number
        idleThresholdHours: number
        preferOnlineAdmins: boolean
        superAdminThreshold: number
    }
    storefront?: StorefrontConfig
}

let config: AppConfig | null = null
let configWriteLock: Promise<void> = Promise.resolve()

export function getConfigPath(): string {
    const __dirname = path.dirname(fileURLToPath(import.meta.url))
    return path.join(__dirname, '..', '..', 'config.json')
}

export async function atomicWriteConfig(patch: (cfg: Record<string, unknown>) => void): Promise<void> {
    configWriteLock = configWriteLock
        .catch((err) => {
            logger.warn({ error: err instanceof Error ? err.message : String(err) }, 'Previous config write failed')
        })
        .then(async () => {
            const configPath = getConfigPath()
            const tempPath = `${configPath}.tmp`
            let fullConfig: Record<string, unknown>

            try {
                fullConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>
            } catch (err) {
                throw new Error(`Failed to read config: ${err instanceof Error ? err.message : String(err)}`)
            }

            patch(fullConfig)

            try {
                await fs.promises.writeFile(tempPath, JSON.stringify(fullConfig, null, 4))
                await fs.promises.rename(tempPath, configPath)
            } catch (err) {
                try {
                    await fs.promises.unlink(tempPath)
                } catch {
                    // Ignore cleanup errors
                }
                throw new Error(`Failed to write config: ${err instanceof Error ? err.message : String(err)}`)
            }

            // Apply immediately to running memory
            const result = configSchema.safeParse(fullConfig)
            if (result.success) {
                const oldConfig = config
                config = result.data as AppConfig

                // Detect changed sections by comparing old vs new
                const sections: (keyof AppConfig)[] = [
                    'session', 'rateLimit', 'presence', 'storage', 'socket',
                    'limits', 'features', 'email', 'assignment', 'cache',
                ]
                const changed = new Set<string>()
                for (const section of sections) {
                    const oldVal = oldConfig ? JSON.stringify(oldConfig[section]) : undefined
                    const newVal = JSON.stringify(config[section])
                    if (oldVal !== newVal) changed.add(section)
                }

                // Broadcast to all subsystems
                if (changed.size > 0) {
                    const changePayload = { sections: Array.from(changed), timestamp: Date.now() }
                    logger.info({ sections: changePayload.sections }, 'Config changed — broadcasting to subsystems')
                    clusterBus.emit('config:changed', changePayload)
                }
            } else {
                throw new Error(`Invalid config after patch: ${result.error.message}`)
            }
        })
    return configWriteLock
}

export function loadConfig(): AppConfig {
    if (config) return config

    const configPath = getConfigPath()
    const configFile = fs.readFileSync(configPath, 'utf-8')
    const parsed = JSON.parse(configFile)

    const result = configSchema.safeParse(parsed)
    if (!result.success) {
        const issues = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')
        throw new Error(`Invalid config.json: ${issues}`)
    }

    config = result.data as AppConfig
    return config
}

/**
 * Force-reload config from disk and broadcast changes locally.
 * Used by remote instances when they receive a config:changed event
 * from serverSideEmit, or for external config file changes.
 */
export function reloadConfig(): AppConfig {
    const configPath = getConfigPath()
    const configFile = fs.readFileSync(configPath, 'utf-8')
    const parsed = JSON.parse(configFile)

    const result = configSchema.safeParse(parsed)
    if (!result.success) {
        const issues = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')
        throw new Error(`Invalid config.json: ${issues}`)
    }

    const oldConfig = config
    config = result.data as AppConfig

    // Detect changed sections
    const sections: (keyof AppConfig)[] = [
        'session', 'rateLimit', 'presence', 'storage', 'socket',
        'limits', 'features', 'email', 'assignment', 'cache',
    ]
    const changed = new Set<string>()
    for (const section of sections) {
        const oldVal = oldConfig ? JSON.stringify(oldConfig[section]) : undefined
        const newVal = JSON.stringify(config[section])
        if (oldVal !== newVal) changed.add(section)
    }

    if (changed.size > 0) {
        const changePayload = { sections: Array.from(changed), timestamp: Date.now() }
        logger.info({ sections: changePayload.sections }, 'Config reloaded from disk — broadcasting locally')
        clusterBus.emit('config:changed', changePayload)
    }

    return config
}

export function getConfig(): AppConfig {
    if (!config) {
        return loadConfig()
    }
    return config
}

export function getBrand(): BrandConfig {
    const cfg = getConfig()
    return cfg.brand || {
        siteName: 'Customer Hub',
        tagline: 'Your direct line to our team',
        company: '',
        supportEmail: '',
        logoUrl: undefined,
        statResponseTime: undefined,
        statUptime: undefined,
        statAvailability: undefined
    }
}

export async function updateBrand(newBrand: BrandConfig): Promise<void> {
    await atomicWriteConfig((cfg) => { cfg.brand = newBrand })
}

export function normalizeMimeType(mimeType: string): string {
    return (mimeType.split(';')[0] ?? mimeType).trim()
}

export function isAllowedMimeType(
    mimeType: string,
    category: 'image' | 'document'
): boolean {
    return getConfig().allowedMimeTypes[category].includes(normalizeMimeType(mimeType))
}

export function getMaxFileSize(
    category: 'image' | 'document'
): number {
    const cfg = getConfig()
    const key = `maxSize${category.charAt(0).toUpperCase() + category.slice(1)}` as
        | 'maxSizeImage'
        | 'maxSizeDocument'
    return cfg.limits.media[key]
}

export function getMediaCategory(
    mimeType: string
): 'image' | 'document' | null {
    const cfg = getConfig()
    const normalized = normalizeMimeType(mimeType)
    if (cfg.allowedMimeTypes.image.includes(normalized)) return 'image'
    if (cfg.allowedMimeTypes.document.includes(normalized)) return 'document'
    return null
}

// Helper functions for new config sections
export function getCacheConfig() {
    const cfg = getConfig()
    return {
        healthTTLMs: cfg.cache?.health?.ttlMs ?? 5000,
        statsTTLMs: cfg.cache?.stats?.ttlMs ?? 30000,
        maxSocketRateLimiters: cfg.cache?.maxSocketRateLimiters ?? 10000,
        maxEmailQueueSize: cfg.cache?.maxEmailQueueSize ?? 1000,
        memory: cfg.cache?.memory
    }
}

export function getSessionConfig() {
    const cfg = getConfig()
    return {
        validationTTLMs: cfg.session.validationCacheTTLSeconds * 1000,
        passwordResetTokenMs: cfg.session.passwordResetTokenMinutes * 60 * 1000,
        refreshTokenMs: cfg.session.refreshTokenDays * 24 * 60 * 60 * 1000,
        accessTokenMs: cfg.session.accessTokenDays * 24 * 60 * 60 * 1000,
        maxDevices: cfg.session.maxDevices
    }
}

export function getRateLimitWindows() {
    const cfg = getConfig()
    return {
        minuteMs: 60 * 1000,
        hourMs: 60 * 60 * 1000,
        loginWindowMs: cfg.rateLimit.login.windowMinutes * 60 * 1000,
        lockoutMs: cfg.rateLimit.login.lockoutMinutes * 60 * 1000
    }
}

export function getSocketConfig() {
    const cfg = getConfig()
    return {
        maxPayloadSize: cfg.socket.payload?.maxSizeBytes ?? 5242880,
        maxRateLimitEntries: cfg.socket.rateLimiter?.maxEntries ?? 10000
    }
}

export function getSecurityConfig() {
    const cfg = getConfig()
    return {
        csrfTokenLength: cfg.security?.csrf?.tokenLength ?? 32,
        argon2MemoryKib: cfg.security?.password?.argon2MemoryKib ?? 65536,
        argon2Iterations: cfg.security?.password?.argon2Iterations ?? 3,
        argon2Parallelism: cfg.security?.password?.argon2Parallelism ?? 4
    }
}

export function getMemoryConfig() {
    const cfg = getConfig()
    const memory = cfg.cache?.memory
    return {
        totalBudgetMB: memory?.totalBudgetMB ?? 200,
        userCache: {
            max: memory?.userCacheMax ?? 400000,
            maxSizeBytes: (memory?.userCacheMaxSizeMB ?? 80) * 1024 * 1024
        },
        sessionCache: {
            max: memory?.sessionCacheMax ?? 400000,
            maxSizeBytes: (memory?.sessionCacheMaxSizeMB ?? 40) * 1024 * 1024,
            entrySizeBytes: 100
        },
        connectedUsers: {
            max: memory?.connectedUsersMax ?? 50000,
            maxSizeBytes: (memory?.connectedUsersMaxSizeMB ?? 20) * 1024 * 1024
        },
        userPresence: {
            max: memory?.userPresenceMax ?? 100000,
            maxSizeBytes: (memory?.userPresenceMaxSizeMB ?? 10) * 1024 * 1024,
            entrySizeBytes: 100
        },
        typingIndicators: {
            max: memory?.typingIndicatorsMax ?? 50000,
            maxSizeBytes: (memory?.typingIndicatorsMaxSizeMB ?? 5) * 1024 * 1024,
            entrySizeBytes: 100
        },
        emailPreferences: {
            max: memory?.emailPreferencesMax ?? 50000,
            maxSizeBytes: (memory?.emailPreferencesMaxSizeMB ?? 5) * 1024 * 1024,
            entrySizeBytes: 50
        },
        pendingEmails: {
            max: memory?.pendingEmailsMax ?? 50000,
            maxSizeBytes: (memory?.pendingEmailsMaxSizeMB ?? 10) * 1024 * 1024
        },
        userNames: {
            max: memory?.userNamesMax ?? 50000,
            maxSizeBytes: (memory?.userNamesMaxSizeMB ?? 5) * 1024 * 1024
        },
        activeUploads: {
            max: memory?.activeUploadsMax ?? 50000,
            maxSizeBytes: (memory?.activeUploadsMaxSizeMB ?? 10) * 1024 * 1024
        },
        conversationOwners: {
            max: memory?.conversationOwnersMax ?? 100000,
            maxSizeBytes: (memory?.conversationOwnersMaxSizeMB ?? 20) * 1024 * 1024,
            entrySizeBytes: 200
        },
        userToConversation: {
            max: memory?.userToConversationMax ?? 100000,
            maxSizeBytes: (memory?.userToConversationMaxSizeMB ?? 10) * 1024 * 1024,
            entrySizeBytes: 100
        },
        userSessionKeys: {
            max: memory?.userSessionKeysMax ?? 50000,
            maxSizeBytes: (memory?.userSessionKeysMaxSizeMB ?? 10) * 1024 * 1024
        }
    }
}

export function getCleanupConfig() {
    const cfg = getConfig()
    return {
        intervalMs: 10000,
        memoryCheckIntervalMs: 30000,
        typingThresholdMs: cfg.presence.typingCleanupThresholdMs ?? 10000,
        presenceThresholdMinutes: cfg.presence.presenceCleanupThresholdMinutes ?? 5,
        uploadThresholdHours: cfg.presence.uploadCleanupThresholdHours ?? 1
    }
}

export function getPaginationConfig() {
    const cfg = getConfig()
    return {
        announcements: {
            default: cfg.pagination?.announcementsDefault ?? 20,
            max: cfg.pagination?.announcementsMax ?? 50
        },
        conversations: {
            default: cfg.pagination?.conversationsDefault ?? 50,
            max: cfg.pagination?.conversationsMax ?? 100
        },
        messages: {
            default: cfg.pagination?.messagesDefault ?? 50,
            max: cfg.pagination?.messagesMax ?? 100
        },
        users: {
            default: cfg.pagination?.usersDefault ?? 50,
            max: cfg.pagination?.usersMax ?? 100
        },
        admins: {
            default: cfg.pagination?.adminsDefault ?? 50,
            max: cfg.pagination?.adminsMax ?? 100
        },
        internalMessages: {
            default: cfg.pagination?.internalMessagesDefault ?? 50,
            max: cfg.pagination?.internalMessagesMax ?? 100
        },
        dmMessages: {
            default: cfg.pagination?.dmMessagesDefault ?? 50,
            max: cfg.pagination?.dmMessagesMax ?? 100
        },
        auditLogs: {
            default: cfg.pagination?.auditLogsDefault ?? 50,
            max: cfg.pagination?.auditLogsMax ?? 100
        },
        userReports: {
            default: cfg.pagination?.userReportsDefault ?? 20,
            max: cfg.pagination?.userReportsMax ?? 50
        }
    }
}
