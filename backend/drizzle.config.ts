import 'dotenv/config'
import { defineConfig } from 'drizzle-kit'

const databaseUrl = process.env.TURSO_DATABASE_URL ?? 'file:./local.db'
const authToken = process.env.TURSO_AUTH_TOKEN

// Omit authToken only for plain local SQLite file mode (no cloud sync).
// Embedded replica mode (file: URL + TURSO_SYNC_URL) still needs the token for migrations.
const isLocal = databaseUrl.startsWith('file:') && !process.env.TURSO_SYNC_URL

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
