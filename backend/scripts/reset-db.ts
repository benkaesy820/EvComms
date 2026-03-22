import 'dotenv/config'
import { createClient } from '@libsql/client'

const url = process.env.TURSO_DATABASE_URL
const authToken = process.env.TURSO_AUTH_TOKEN

if (!url || !authToken) {
  console.error('❌  TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set in your .env')
  process.exit(1)
}

const client = createClient({ url, authToken })

console.log('⚠️   Wiping database...\n')

// Drop in explicit dependency order (children before parents) so FK constraints never fire.
// Turso remote does not honour PRAGMA foreign_keys = OFF per-connection.
const DROP_ORDER = [
  // leaf tables first (no children)
  'announcement_comments',
  'announcement_reactions',
  'announcement_votes',
  'audit_logs',
  'direct_message_reactions',
  'dm_recipient_status',
  'internal_message_reactions',
  'internal_message_reads',
  'message_reactions',
  'user_status_history',
  'password_reset_tokens',
  'refresh_tokens',
  'sessions',
  // media messages (reference media + messages/internal_messages/direct_messages)
  'direct_messages',
  'internal_messages',
  'messages',
  // other entities that reference media or users
  'registration_reports',
  'user_reports',
  'media',
  // conversations references users
  'conversations',
  // announcements stand alone (created_by → users)
  'announcements',
  // users last
  'users',
  // drizzle migrations table
  '__drizzle_migrations',
]

// Also catch any tables not in our explicit list
const result = await client.execute(
  `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'libsql_%'`
)
const allTables = new Set(result.rows.map((r: any) => r.name as string))

// Build final list: explicit order first, then anything remaining
const toDropInOrder = [
  ...DROP_ORDER.filter(t => allTables.has(t)),
  ...[...allTables].filter(t => !DROP_ORDER.includes(t)),
]

for (const table of toDropInOrder) {
  try {
    await client.execute(`DROP TABLE IF EXISTS "${table}"`)
    console.log(`  ✓ dropped ${table}`)
  } catch (err: any) {
    console.warn(`  ⚠ could not drop ${table}: ${err.message}`)
  }
}

console.log('\n✅  All tables dropped.')
console.log('👉  Now run: npm run db:push   (or drizzle-kit push) to recreate the schema.\n')

await client.close()
process.exit(0)
