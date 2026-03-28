/**
 * db:migrate — Run pending SQL migration files against the Turso database
 *
 * Tracks applied migrations in a `_migrations` table (created if missing).
 * Only runs each file once, in filename order. Safe to re-run at any time.
 *
 * Usage:
 *   npm run db:migrate            — apply all pending migrations
 *   npm run db:migrate -- --dry   — print pending migrations without running them
 *   npm run db:migrate -- --list  — print all migrations and their applied status
 */

import 'dotenv/config'
import { createClient } from '@libsql/client'
import { readdir, readFile } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

// ─── Config ──────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url))
const MIGRATIONS_DIR = join(__dirname, '..', 'drizzle')

const url = process.env.TURSO_DATABASE_URL
const authToken = process.env.TURSO_AUTH_TOKEN

if (!url || !authToken) {
  console.error('\n❌  TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set in your .env\n')
  process.exit(1)
}

const args = process.argv.slice(2)
const DRY_RUN = args.includes('--dry')
const LIST_ONLY = args.includes('--list')

// ─── Connect ──────────────────────────────────────────────────────────────────

const client = createClient({ url, authToken })

// ─── Ensure tracking table exists ────────────────────────────────────────────

await client.execute(`
  CREATE TABLE IF NOT EXISTS _migrations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    filename  TEXT    NOT NULL UNIQUE,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
  )
`)

// ─── Fetch already-applied migrations ────────────────────────────────────────

const appliedResult = await client.execute(`SELECT filename FROM _migrations ORDER BY id`)
const applied = new Set(appliedResult.rows.map((r: any) => r.filename as string))

// ─── Discover migration files ────────────────────────────────────────────────

const allFiles = (await readdir(MIGRATIONS_DIR))
  .filter(f => f.endsWith('.sql') && !f.endsWith('_down.sql'))
  .sort()  // lexicographic = chronological given 0000_, 0001_, ... naming

const pending = allFiles.filter(f => !applied.has(f))

// ─── --list mode ─────────────────────────────────────────────────────────────

if (LIST_ONLY) {
  console.log('\n📋  Migration status:\n')
  for (const f of allFiles) {
    const status = applied.has(f) ? '✅ applied' : '⏳ pending'
    console.log(`  ${status}  ${f}`)
  }
  if (pending.length === 0) {
    console.log('\n  All migrations are up to date.\n')
  } else {
    console.log(`\n  ${pending.length} pending migration(s) — run npm run db:migrate to apply.\n`)
  }
  await client.close()
  process.exit(0)
}

// ─── Nothing to do ───────────────────────────────────────────────────────────

if (pending.length === 0) {
  console.log('\n✅  Database is up to date — no pending migrations.\n')
  await client.close()
  process.exit(0)
}

// ─── Dry run ─────────────────────────────────────────────────────────────────

if (DRY_RUN) {
  console.log('\n🔍  Dry run — would apply:\n')
  for (const f of pending) console.log(`  ⏳  ${f}`)
  console.log(`\n  Total: ${pending.length} migration(s). Remove --dry to apply.\n`)
  await client.close()
  process.exit(0)
}

// ─── Apply pending migrations ─────────────────────────────────────────────────

console.log(`\n🚀  Applying ${pending.length} pending migration(s)...\n`)

let succeeded = 0
let failed = 0

for (const filename of pending) {
  const filepath = join(MIGRATIONS_DIR, filename)
  const sql = await readFile(filepath, 'utf8')

  // Parse SQL into individual executable statements:
  //  1. Split on drizzle-kit breakpoint markers (non-capturing, so the marker
  //     itself is never kept as a token).
  //  2. Strip SQL line-comments from each chunk BEFORE splitting on ";".
  //     Stripping after the fact would filter out entire chunks that start
  //     with a comment header (e.g. the file-level banner before CREATE TABLE).
  //  3. Split each comment-free chunk on ";" to get individual statements.
  //  4. Trim and discard blanks.
  const statements = sql
    .split(/--> statement-breakpoint/)
    .map(chunk => chunk.replace(/^[ \t]*--[^\n]*$/gm, ''))  // strip comment-only lines
    .flatMap(chunk => chunk.split(';'))
    .map(s => s.trim())
    .filter(s => s.length > 0)

  process.stdout.write(`  ⏳  ${filename} ... `)

  try {
    for (const statement of statements) {
      try {
        await client.execute(statement)
      } catch (stmtErr: any) {
        // Gracefully handle "duplicate column" errors for migrations whose
        // columns are already present in 0000_init.sql on a fresh database.
        // This happens for 0001 (subsidiary_ids) and 0002 (media_id) which
        // are already included in the init schema but kept as migrations for
        // upgrading existing databases.
        const msg: string = stmtErr?.message ?? ''
        const isDuplicateColumn =
          msg.includes('duplicate column name') ||
          msg.includes('already exists') ||
          (msg.includes('SQLITE') && msg.toLowerCase().includes('duplicate'))
        
        if (isDuplicateColumn) {
          // Column already exists — fresh DB install, skip gracefully
          continue
        }

        // For any other error, re-throw so the outer catch handles it
        throw stmtErr
      }
    }

    // Mark as applied
    await client.execute({
      sql: `INSERT INTO _migrations (filename) VALUES (?)`,
      args: [filename],
    })

    console.log('✅')
    succeeded++
  } catch (err: any) {
    console.log('❌')
    console.error(`\n     Error: ${err.message}\n`)
    failed++

    // Stop on first failure — don't apply out-of-order migrations
    console.error(`  ⛔  Stopping. Fix the error above and re-run.\n`)
    break
  }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log()
if (failed === 0) {
  console.log(`✅  Done — ${succeeded} migration(s) applied successfully.\n`)
} else {
  console.log(`⚠️   ${succeeded} applied, ${failed} failed. Fix and re-run db:migrate.\n`)
}

await client.close()
process.exit(failed > 0 ? 1 : 0)