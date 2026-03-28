import { db, initDb } from './src/db'
import { sql } from 'drizzle-orm'
import { getConfig } from './src/config'

async function run() {
  try {
    const config = getConfig()
    await initDb(config)
    
    console.log('Running test query')
    await db.run(sql`
        INSERT INTO internal_message_reads (id, user_id, last_read_at, unread_count, updated_at)
        SELECT
          lower(hex(randomblob(10))),
          u.id,
          unixepoch(),
          COALESCE((SELECT unread_count FROM internal_message_reads WHERE user_id = u.id), 0) + 1,
          unixepoch()
        FROM users u
        WHERE u.role IN ('ADMIN', 'SUPER_ADMIN')
          AND u.status = 'APPROVED'
        ON CONFLICT(user_id) DO UPDATE SET
          unread_count = internal_message_reads.unread_count + 1,
          updated_at = unixepoch()
      `)
    
    const reads = await db.all(sql`SELECT * FROM internal_message_reads`)
    console.log('Reads:', reads)
  } catch (err) {
    console.error('ERROR:', err)
  }
}
run()
