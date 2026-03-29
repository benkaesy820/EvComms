// One-shot script to apply the push_subscriptions migration directly via libsql
import 'dotenv/config'
import { createClient } from '@libsql/client'

const url = process.env.TURSO_DATABASE_URL
const authToken = process.env.TURSO_AUTH_TOKEN

if (!url || !authToken) {
  console.error('Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN')
  process.exit(1)
}

const client = createClient({ url, authToken })

const statements = [
  `CREATE TABLE IF NOT EXISTS \`push_subscriptions\` (
    \`id\` text PRIMARY KEY NOT NULL,
    \`user_id\` text NOT NULL,
    \`endpoint\` text NOT NULL,
    \`p256dh\` text NOT NULL,
    \`auth\` text NOT NULL,
    \`user_agent\` text,
    \`created_at\` integer DEFAULT (unixepoch()) NOT NULL,
    \`updated_at\` integer DEFAULT (unixepoch()) NOT NULL,
    FOREIGN KEY (\`user_id\`) REFERENCES \`users\`(\`id\`) ON UPDATE no action ON DELETE cascade
  )`,
  `CREATE INDEX IF NOT EXISTS \`idx_push_subs_user\` ON \`push_subscriptions\` (\`user_id\`)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS \`uq_push_endpoint\` ON \`push_subscriptions\` (\`endpoint\`)`,
]

for (const sql of statements) {
  try {
    await client.execute(sql)
    console.log('✓', sql.slice(0, 60).replace(/\s+/g, ' ').trim())
  } catch (err) {
    console.error('✗', err.message)
  }
}

await client.close()
console.log('Done.')
