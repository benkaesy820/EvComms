import 'dotenv/config'
import { defineConfig } from 'drizzle-kit'

const databaseUrl = process.env.TURSO_DATABASE_URL ?? 'file:./local.db'
const authToken = process.env.TURSO_AUTH_TOKEN

// For local SQLite, don't use authToken
const isLocal = databaseUrl.startsWith('file:')

// For embedded replica mode: push schema to Turso cloud via db:push:remote.
// The embedded replica client syncs schema changes on next syncInterval or client.sync().
// db:push:local is only needed for standalone local SQLite dev without cloud sync.

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'turso',
  dbCredentials: {
    url: databaseUrl,
    ...(isLocal ? {} : { authToken: authToken ?? '' })
  },
  tablesFilter: ['!turso_*']
})
