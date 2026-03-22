import 'dotenv/config'
import { createClient } from '@libsql/client'
import { drizzle } from 'drizzle-orm/libsql'
import { hash } from '@node-rs/argon2'
import { ulid } from 'ulid'
import { eq } from 'drizzle-orm'
import * as schema from '../src/db/schema.js'

const url = process.env.TURSO_DATABASE_URL
const authToken = process.env.TURSO_AUTH_TOKEN

if (!url || !authToken) {
  console.error('❌  TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set in your .env')
  process.exit(1)
}

// ─── Seed config — change these before running ───────────────────────────────
const SUPER_ADMIN = {
  email: 'dawnred820@gmail.com',
  password: 'Triphina1323@',
  name: 'Super Admin',
}
// ─────────────────────────────────────────────────────────────────────────────

const client = createClient({ url, authToken })
const db = drizzle(client, { schema })

console.log('🌱  Seeding admin user...\n')

const passwordHash = await hash(SUPER_ADMIN.password, {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
})

// Check if admin already exists — update if so, insert if not
const existing = await db.query.users.findFirst({
  where: eq(schema.users.email, SUPER_ADMIN.email),
  columns: { id: true },
})

if (existing) {
  await db.update(schema.users)
    .set({ passwordHash, name: SUPER_ADMIN.name, role: 'SUPER_ADMIN', status: 'APPROVED', mediaPermission: true, emailNotifyOnMessage: true })
    .where(eq(schema.users.email, SUPER_ADMIN.email))
  console.log(`  ✓ Updated existing SUPER_ADMIN`)
} else {
  await db.insert(schema.users).values({
    id: ulid(),
    email: SUPER_ADMIN.email,
    passwordHash,
    name: SUPER_ADMIN.name,
    role: 'SUPER_ADMIN',
    status: 'APPROVED',
    mediaPermission: true,
    emailNotifyOnMessage: true,
  })
  console.log(`  ✓ Created SUPER_ADMIN`)
}

console.log(`    email:    ${SUPER_ADMIN.email}`)
console.log(`    password: ${SUPER_ADMIN.password}`)
console.log('\n✅  Seed complete.\n')

await client.close()
process.exit(0)
