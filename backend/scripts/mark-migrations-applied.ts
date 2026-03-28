/**
 * After db:push, mark all existing migrations as applied in _migrations table.
 * This prevents db:migrate from trying to re-run them.
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
  console.error('❌ TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set')
  process.exit(1)
}

const client = createClient({ url, authToken })

// Ensure _migrations table exists
await client.execute(`
  CREATE TABLE IF NOT EXISTS _migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
  )
`)

// Get all migration files
const allFiles = (await readdir(MIGRATIONS_DIR))
  .filter(f => f.endsWith('.sql') && !f.endsWith('_down.sql'))
  .sort()

// Get already applied migrations
const appliedResult = await client.execute(`SELECT filename FROM _migrations`)
const applied = new Set(appliedResult.rows.map((r: any) => r.filename as string))

const toMark = allFiles.filter(f => !applied.has(f))

if (toMark.length === 0) {
  console.log('✅ All migrations already marked as applied')
  await client.close()
  process.exit(0)
}

console.log(`📝 Marking ${toMark.length} migration(s) as applied...`)

for (const filename of toMark) {
  await client.execute({
    sql: `INSERT INTO _migrations (filename) VALUES (?)`,
    args: [filename],
  })
  console.log(`  ✓ ${filename}`)
}

console.log('\n✅ Done! You can now run db:migrate safely.\n')
await client.close()
