import pino from 'pino'
import { env } from './env.js'

export const logger = pino({
    level: env.isDev ? 'debug' : 'info',
    redact: ['err.config.headers["x-refresh-token"]', 'req.headers["x-refresh-token"]', 'request.headers["x-refresh-token"]', 'headers["x-refresh-token"]'],
    ...(env.isDev ? { transport: { target: 'pino-pretty', options: { colorize: true } } } : {})
})
