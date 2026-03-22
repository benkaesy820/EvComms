/**
 * db:status — Quick health check: shows migration status + DB connection test
 *
 * Usage:
 *   npm run db:status
 */

import 'dotenv/config'
import { createClient } from '@libsql/client'
import { readdir } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const MIGRATIONS_DIR = join(__dirname, '..', 'drizzle')

const url = process.env.TURSO_DATABASE_URL
const authToken = process.env.TURSO_AUTH_TOKEN

if (!url || !authToken) {
  console.error('\n❌  TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set in your .env\n')
  process.exit(1)
}

const client = createClient({ url, authToken })

console.log('\n🔍  Checking database status...\n')

// Connection test
try {
  await client.execute('SELECT 1')
  console.log(`  ✅  Connected to: ${url.replace(/\?.*/, '')}`)
} catch (err: any) {
  console.error(`  ❌  Connection failed: ${err.message}\n`)
  process.exit(1)
}

// Table count
const tablesResult = await client.execute(
  `SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'libsql_%' AND name NOT LIKE '_migrations'`
)
const tableCount = (tablesResult.rows[0] as any).count
console.log(`  📊  Tables in DB: ${tableCount}`)

// Migration tracking table
let applied = new Set<string>()
try {
  await client.execute(`CREATE TABLE IF NOT EXISTS _migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`)
  const appliedResult = await client.execute(
    `SELECT filename, applied_at FROM _migrations ORDER BY id`
  )
  applied = new Set(appliedResult.rows.map((r: any) => r.filename as string))
  console.log(`  📝  Tracked migrations: ${applied.size}`)
} catch {
  console.log(`  ⚠️   Migration tracking table not found`)
}

// Local migration files
const allFiles = (await readdir(MIGRATIONS_DIR))
  .filter(f => f.endsWith('.sql') && !f.endsWith('_down.sql'))
  .sort()

const pending = allFiles.filter(f => !applied.has(f))

console.log(`  📁  Local migration files: ${allFiles.length}`)

if (pending.length === 0) {
  console.log(`\n  ✅  All migrations applied — DB is up to date.\n`)
} else {
  console.log(`\n  ⏳  Pending migrations (${pending.length}):\n`)
  for (const f of pending) console.log(`       ${f}`)
  console.log(`\n  👉  Run: npm run db:migrate\n`)
}

await client.close()
