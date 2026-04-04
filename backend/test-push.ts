import { ensureInitialized, sendPushToUser } from './src/lib/webPush.js'
import { db, initDb } from './src/db/index.js'
import { users } from './src/db/schema.js'
import { eq } from 'drizzle-orm'
import { logger } from './src/lib/logger.js'

async function run() {
  await initDb()
  const email = 'dawnred820@gmail.com'
  
  const user = await db.query.users.findFirst({
    where: eq(users.email, email)
  })

  if (!user) {
    console.log('User not found:', email)
    process.exit(1)
  }

  console.log(`Sending test push to ${user.name} (${user.id})...`)

  try {
    await sendPushToUser(user.id, {
      title: '🔔 Terminal Test',
      body: 'This push was sent directly from a terminal script!',
      tag: 'terminal-test',
      data: { url: '/' }
    })
    console.log('Push sent successfully. Check your OS notifications.')
  } catch (err) {
    console.error('Push failed:', err)
  }
  process.exit(0)
}

run()
