import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3'
import { NodeHttpHandler } from '@smithy/node-http-handler'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { ulid } from 'ulid'
import { env } from '../lib/env.js'
import { getConfig } from '../lib/config.js'
import { CircuitBreaker } from '../lib/circuitBreaker.js'
import { emitToAdmins } from '../socket/index.js'
import { retryWithBackoff } from '../lib/utils.js'
import { logger } from '../lib/logger.js'
import ImageKit from 'imagekit'

let s3Client: S3Client | null = null
let storageCircuitBreaker: CircuitBreaker | null = null
let storageCircuitBreakerConfigKey = ''
let imageKitInstance: ImageKit | null = null

let imageKitConfigKey = ''

function getImageKit(): ImageKit {
  const config = getConfig()
  const publicKey = config.storage.imagekitPublicKey || env.imagekitPublicKey
  const urlEndpoint = config.storage.imagekitUrlEndpoint || env.imagekitUrlEndpoint
  const privateKey = env.imagekitPrivateKey

  if (!publicKey || !privateKey || !urlEndpoint) {
    throw new Error('ImageKit credentials not configured')
  }

  const currentKey = `${publicKey}:${urlEndpoint}`
  if (!imageKitInstance || imageKitConfigKey !== currentKey) {
    imageKitInstance = new ImageKit({
      publicKey,
      privateKey,
      urlEndpoint
    })
    imageKitConfigKey = currentKey
  }
  return imageKitInstance
}

function getStorageCircuitBreaker(): CircuitBreaker {
  const circuitConfig = getConfig().storage.circuitBreaker
  const configKey = `${circuitConfig.failureThreshold}:${circuitConfig.recoveryTimeoutMs}`

  if (!storageCircuitBreaker || storageCircuitBreakerConfigKey !== configKey) {
    storageCircuitBreaker = new CircuitBreaker({
      name: 'Storage',
      failureThreshold: circuitConfig.failureThreshold,
      recoveryTimeoutMs: circuitConfig.recoveryTimeoutMs,
      onStateChange: (state, failures) => {
        if (state === 'HALF_OPEN') {
          emitToAdmins('storage:circuit_recovery', { state, timestamp: Date.now() })
        } else if (state === 'OPEN') {
          emitToAdmins('storage:circuit_opened', { state, failures, timestamp: Date.now() })
        } else if (state === 'CLOSED') {
          emitToAdmins('storage:circuit_closed', { state, timestamp: Date.now() })
        }
      }
    })
    storageCircuitBreakerConfigKey = configKey
  }

  return storageCircuitBreaker
}

function getS3Client(): S3Client {
  if (!s3Client) {
    if (!env.r2AccountId || !env.r2AccessKeyId || !env.r2SecretAccessKey || !env.r2BucketName) {
      throw new Error('R2 credentials not configured')
    }

    const timeoutMs = getConfig().storage.timeoutMs

    s3Client = new S3Client({
      region: 'auto',
      endpoint: `https://${env.r2AccountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: env.r2AccessKeyId,
        secretAccessKey: env.r2SecretAccessKey
      },
      requestHandler: new NodeHttpHandler({
        requestTimeout: timeoutMs,
        connectionTimeout: timeoutMs
      })
    })
  }
  return s3Client
}

interface UploadUrlParams {
  type: 'IMAGE' | 'DOCUMENT'
  mimeType: string
  size: number
  filename: string
}

interface UploadUrlResult {
  uploadUrl: string
  mediaId: string
  r2Key: string
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number = getConfig().storage.timeoutMs): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Operation timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    promise
      .then(result => {
        clearTimeout(timeoutId)
        resolve(result)
      })
      .catch(error => {
        clearTimeout(timeoutId)
        reject(error)
      })
  })
}

interface UploadAuthParams {
  token?: string
  expire?: number
  signature?: string
  urlEndpoint?: string
  uploadUrl?: string // For R2
  mediaId: string
  r2Key: string // keeping property name for DB backward compat
  provider: 'R2' | 'IMAGEKIT'
}

interface ImageKitFile {
  fileId?: string
  name?: string
}

export async function generateUploadUrl(params: UploadUrlParams): Promise<UploadAuthParams> {
  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    return retryWithBackoff(async () => {
      const mediaId = ulid()
      const extension = params.filename.split('.').pop() || 'bin'
      const r2Key = `${params.type.toLowerCase()}/${mediaId}.${extension}`

      if (params.type === 'IMAGE') {
        const ik = getImageKit()
        // ImageKit hard limit: expire must be < 1 hour (3600s) into the future.
        // Use config value, capped at ImageKit's limit.
        const MAX_IK_EXPIRE_SECS = config.storage.imagekitMaxExpireSeconds ?? 1800
        const ikExpireSecs = Math.min(
          config.limits.upload.presignedUrlTTL ?? MAX_IK_EXPIRE_SECS,
          MAX_IK_EXPIRE_SECS
        )
        const expireUnix = Math.floor(Date.now() / 1000) + ikExpireSecs
        const auth = ik.getAuthenticationParameters(undefined, expireUnix)

        return {
          ...auth,
          urlEndpoint: config.storage.imagekitUrlEndpoint || env.imagekitUrlEndpoint || '',
          mediaId,
          r2Key,
          provider: 'IMAGEKIT'
        }
      } else {
        const client = getS3Client()
        const command = new PutObjectCommand({
          Bucket: env.r2BucketName!,
          Key: r2Key,
          ContentType: params.mimeType,
          ContentLength: params.size
        })

        const uploadUrl = await withTimeout(
          getSignedUrl(client, command, {
            expiresIn: config.limits.upload.presignedUrlTTL
          }),
          config.storage.timeoutMs
        )
        return { uploadUrl, mediaId, r2Key, provider: 'R2' }
      }
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

/**
 * ARCHITECTURE FIX: Delete file from ImageKit by fileId
 * Used by webhook handler for invalid file cleanup
 */
export async function deleteFromImageKit(fileId: string): Promise<void> {
  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    return retryWithBackoff(async () => {
      const ik = getImageKit()
      await ik.deleteFile(fileId)
      logger.debug({ fileId }, 'Deleted file from ImageKit')
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

/**
 * ARCHITECTURE FIX: Delete file from ImageKit by R2 key (path)
 * Looks up file by name, then deletes by fileId
 */
export async function deleteFromImageKitByKey(r2Key: string): Promise<void> {
  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    return retryWithBackoff(async () => {
      const ik = getImageKit()
      const filename = r2Key.split('/')[1]
      if (!filename) return
      
      // Sanitize filename for search query
      const sanitizedName = filename.replace(/"/g, '\\"').replace(/\\/g, '\\\\')
      const files = await ik.listFiles({
        searchQuery: `name="${sanitizedName}"`
      })

      if (files && files.length > 0) {
        const theFile = files[0] as ImageKitFile | undefined
        if (theFile?.fileId) {
          await ik.deleteFile(theFile.fileId)
          logger.debug({ r2Key, fileId: theFile.fileId }, 'Deleted file from ImageKit by key')
        }
      }
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

interface UploadParams {
  key: string
  data: Buffer
  mimeType: string
  metadata?: Record<string, string>
}

export async function uploadToR2(params: UploadParams): Promise<string> {
  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    const timeoutMs = config.storage.timeoutMs
    return retryWithBackoff(async () => {
      const { key, data, mimeType } = params
      const isMediaKit = key.startsWith('image/')

      if (isMediaKit) {
        const ik = getImageKit()
        const folder = key.split('/')[0] // 'video' or 'image'
        const filename = key.split('/')[1]

        if (!filename) throw new Error('Invalid filename in key')

        const result = await ik.upload({
          file: data,
          fileName: filename,
          folder: `/${folder}`,
          useUniqueFileName: false
        })

        return result.url
      } else {
        const client = getS3Client()
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

        const command = new PutObjectCommand({
          Bucket: env.r2BucketName!,
          Key: key,
          Body: data,
          ContentType: mimeType,
          ContentLength: data.length,
          Metadata: params.metadata
        })

        try {
          await client.send(command, { abortSignal: controller.signal })
        } finally {
          clearTimeout(timeoutId)
        }

        // Return CDN URL for R2
        return `${env.r2PublicUrl?.replace(/\/$/, '')}/${key}`
      }
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

export async function deleteFromR2(r2Key: string): Promise<void> {
  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    const timeoutMs = config.storage.timeoutMs
    return retryWithBackoff(async () => {
      const isMediaKit = r2Key.startsWith('image/')

      if (isMediaKit) {
        await deleteFromImageKitByKey(r2Key)
      } else {
        const client = getS3Client()
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

        const command = new DeleteObjectCommand({
          Bucket: env.r2BucketName!,
          Key: r2Key
        })

        try {
          await client.send(command, { abortSignal: controller.signal })
        } finally {
          clearTimeout(timeoutId)
        }
      }
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

// CRITICAL FIX: Documents now require presigned URLs - no public access
export function getCdnUrl(r2Key: string, mediaType?: string): string {
  // Documents CANNOT use public URLs - must use getSignedR2Url for access
  if (r2Key.startsWith('document/')) {
    throw new Error('Documents require presigned URLs - use getSignedR2Url() instead')
  }

  const config = getConfig()
  const endpoint = config.storage.imagekitUrlEndpoint || env.imagekitUrlEndpoint
  const pubKey = config.storage.imagekitPublicKey || env.imagekitPublicKey

  if (!endpoint) {
    throw new Error('IMAGEKIT_URL_ENDPOINT is not configured')
  }

  // If full credentials are provided, use the official SDK to generate the proper URL structure 
  // (handles path normalization, transformations, and signatures if required by the dashboard)
  if (pubKey && env.imagekitPrivateKey) {
    const ik = getImageKit()
    // Path must start with / — ImageKit SDK concatenates endpoint + path directly
    const ikPath = r2Key.startsWith('/') ? r2Key : `/${r2Key}`
    if (!mediaType || mediaType === 'IMAGE') {
      return ik.url({
        path: ikPath,
        transformation: [{ format: 'auto', quality: '80' }]
      })
    }
    return ik.url({ path: ikPath })
  }

  // Fallback string concatenation if only the endpoint is provided
  const baseUrl = endpoint.replace(/\/+$/, '')

  if (!mediaType || mediaType === 'IMAGE') {
    // path-based transform is consistently supported by ImageKit
    return `${baseUrl}/tr:f-auto,q-80/${r2Key.replace(/^\/+/, '')}`
  }

  return `${baseUrl}/${r2Key.replace(/^\/+/, '')}`
}

export async function getSignedR2Url(r2Key: string, expiresIn: number = 60): Promise<string> {
  const isMediaKit = r2Key.startsWith('image/')
  if (isMediaKit) {
    return Promise.resolve(getCdnUrl(r2Key))
  }

  return getStorageCircuitBreaker().execute(async () => {
    const config = getConfig()
    return retryWithBackoff(async () => {
      const client = getS3Client()

      const command = new GetObjectCommand({
        Bucket: env.r2BucketName!,
        Key: r2Key
      })

      return withTimeout(
        getSignedUrl(client, command, { expiresIn }),
        config.storage.timeoutMs
      )
    }, config.storage.retry.maxAttempts, config.storage.retry.baseDelayMs)
  })
}

export function getCircuitBreakerState(): { state: string; failures: number } {
  return getStorageCircuitBreaker().getState()
}

export async function checkStorageHealth(): Promise<{
  status: 'healthy' | 'degraded' | 'unhealthy'
  latency?: number
  error?: string
}> {
  const config = getConfig()
  const pubKey = config.storage.imagekitPublicKey || env.imagekitPublicKey
  const endpoint = config.storage.imagekitUrlEndpoint || env.imagekitUrlEndpoint
  if (!pubKey || !env.imagekitPrivateKey || !endpoint) {
    return { status: 'unhealthy', error: 'ImageKit not configured' }
  }

  try {
    const start = Date.now()
    const ik = getImageKit()

    // Test API connectivity by doing a simple fast query
    await ik.listFiles({ limit: 1 })

    const latency = Date.now() - start

    if (latency > 2000) {
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
