import dotenv from 'dotenv'
import { z } from 'zod'

dotenv.config({ path: '.env' })
dotenv.config({ path: '.env.local', override: true })

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().min(1).default('0.0.0.0'),

  TURSO_DATABASE_URL: z.string().min(1),
  TURSO_AUTH_TOKEN: z.string().min(1),

  JWT_SECRET: z.string().min(24),
  JWT_EXPIRY_MINUTES: z.coerce.number().int().positive().default(15),
  JWT_ISSUER: z.string().min(1).optional(),
  JWT_AUDIENCE: z.string().min(1).optional(),

  R2_ACCOUNT_ID: z.string().optional(),
  R2_ACCESS_KEY_ID: z.string().optional(),
  R2_SECRET_ACCESS_KEY: z.string().optional(),
  R2_BUCKET_NAME: z.string().optional(),
  R2_PUBLIC_URL: z.string().optional(),

  IMAGEKIT_PUBLIC_KEY: z.string().optional(),
  IMAGEKIT_PRIVATE_KEY: z.string().optional(),
  IMAGEKIT_URL_ENDPOINT: z.string().optional(),

  // Production email: Brevo
  BREVO_API_KEY: z.string().optional(),
  BREVO_SENDER_EMAIL: z.string().email().optional(),
  BREVO_SENDER_NAME: z.string().optional(),

  // Development email: Mailpit (local SMTP catch-all, no auth)
  MAILPIT_HOST: z.string().default('localhost'),
  MAILPIT_PORT: z.coerce.number().int().positive().default(1025),

  CORS_ORIGIN: z.string().default('http://localhost:5173'),

  APP_NAME: z.string().min(1).max(50).default('Business Chat'),
  APP_URL: z.string().url().default('http://localhost:5173')
}).superRefine((data, ctx) => {
  if (data.NODE_ENV === 'production') {
    if (data.JWT_SECRET.length < 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.too_small,
        type: 'string',
        minimum: 32,
        inclusive: true,
        message: 'Must be at least 32 characters in production',
        path: ['JWT_SECRET']
      })
    }

    if (!data.JWT_ISSUER) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'JWT_ISSUER is required in production',
        path: ['JWT_ISSUER']
      })
    }

    if (!data.JWT_AUDIENCE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'JWT_AUDIENCE is required in production',
        path: ['JWT_AUDIENCE']
      })
    }

    if (!data.R2_ACCOUNT_ID || !data.R2_ACCESS_KEY_ID || !data.R2_SECRET_ACCESS_KEY || !data.R2_BUCKET_NAME) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'R2 configuration is required in production',
        path: ['R2_ACCOUNT_ID']
      })
    }

    if (!data.BREVO_API_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'BREVO_API_KEY is required in production',
        path: ['BREVO_API_KEY']
      })
    }

    if (!data.BREVO_SENDER_EMAIL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'BREVO_SENDER_EMAIL is required in production',
        path: ['BREVO_SENDER_EMAIL']
      })
    }

    if (!data.TURSO_AUTH_TOKEN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'TURSO_AUTH_TOKEN is required in production',
        path: ['TURSO_AUTH_TOKEN']
      })
    }
  }
})

const parsed = envSchema.safeParse(process.env)

if (!parsed.success) {
  const message = parsed.error.issues
    .map((issue: z.ZodIssue) => `${issue.path.join('.')}: ${issue.message}`)
    .join('\n')
  throw new Error(`Invalid environment configuration:\n${message}`)
}

export const env = {
  nodeEnv: parsed.data.NODE_ENV,
  isDev: parsed.data.NODE_ENV === 'development',
  isProd: parsed.data.NODE_ENV === 'production',
  isTest: parsed.data.NODE_ENV === 'test',
  port: parsed.data.PORT,
  host: parsed.data.HOST,

  databaseUrl: parsed.data.TURSO_DATABASE_URL,
  authToken: parsed.data.TURSO_AUTH_TOKEN,

  jwtSecret: parsed.data.JWT_SECRET,
  jwtExpiryMinutes: parsed.data.JWT_EXPIRY_MINUTES,
  jwtIssuer: parsed.data.JWT_ISSUER ?? parsed.data.APP_URL,
  jwtAudience: parsed.data.JWT_AUDIENCE ?? parsed.data.APP_NAME,

  r2AccountId: parsed.data.R2_ACCOUNT_ID,
  r2AccessKeyId: parsed.data.R2_ACCESS_KEY_ID,
  r2SecretAccessKey: parsed.data.R2_SECRET_ACCESS_KEY,
  r2BucketName: parsed.data.R2_BUCKET_NAME,
  r2PublicUrl: parsed.data.R2_PUBLIC_URL,

  imagekitPublicKey: parsed.data.IMAGEKIT_PUBLIC_KEY,
  imagekitPrivateKey: parsed.data.IMAGEKIT_PRIVATE_KEY,
  imagekitUrlEndpoint: parsed.data.IMAGEKIT_URL_ENDPOINT,

  // Production: Brevo
  brevoApiKey: parsed.data.BREVO_API_KEY,
  brevoSenderEmail: parsed.data.BREVO_SENDER_EMAIL,
  brevoSenderName: parsed.data.BREVO_SENDER_NAME,

  // Development: Mailpit
  mailpitHost: parsed.data.MAILPIT_HOST,
  mailpitPort: parsed.data.MAILPIT_PORT,

  corsOrigin: parsed.data.CORS_ORIGIN,

  appName: parsed.data.APP_NAME,
  appUrl: parsed.data.APP_URL
} as const
