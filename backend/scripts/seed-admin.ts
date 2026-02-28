/**
 * seed-admin.ts — Database management script for EvComms
 *
 * Usage:
 *   npx tsx scripts/seed-admin.ts --seed          # Create Super Admin only
 *   npx tsx scripts/seed-admin.ts --wipe          # Wipe all data (keep tables)
 *   npx tsx scripts/seed-admin.ts --wipe --seed   # Wipe then seed fresh admin
 *
 * npm shortcuts:
 *   npm run db:wipe    # wipe only
 *   npm run db:seed    # seed only
 *   npm run db:fresh   # wipe + seed
 *
 * Env overrides:
 *   SEED_ADMIN_EMAIL    (default: admin@evcomms.com)
 *   SEED_ADMIN_PASSWORD (default: Admin1234!)
 *   SEED_ADMIN_NAME     (default: Super Admin)
 */
import 'dotenv/config'
import { hash } from '@node-rs/argon2'
import { createClient } from '@libsql/client'
import { drizzle } from 'drizzle-orm/libsql'
import { eq } from 'drizzle-orm'
import { ulid } from 'ulid'
import * as schema from '../src/db/schema.js'

// ── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2)
const doWipe = args.includes('--wipe')
const doSeed = args.includes('--seed')

if (!doWipe && !doSeed) {
    console.error('❌  No mode specified.')
    console.error('')
    console.error('   Usage: npx tsx scripts/seed-admin.ts [--wipe] [--seed]')
    console.error('')
    console.error('   --wipe        Truncate all table data (keeps schema)')
    console.error('   --seed        Create Super Admin user')
    console.error('   --wipe --seed Wipe first, then seed fresh admin')
    process.exit(1)
}

// ── Config ───────────────────────────────────────────────────────────────────
const ADMIN_EMAIL = process.env.SEED_ADMIN_EMAIL ?? 'admin@evcomms.com'
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD ?? 'Admin1234!'
const ADMIN_NAME = process.env.SEED_ADMIN_NAME ?? 'Super Admin'

const DATABASE_URL = process.env.TURSO_DATABASE_URL
const AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN

if (!DATABASE_URL) {
    console.error('❌  TURSO_DATABASE_URL is not set')
    process.exit(1)
}

// ── DB ───────────────────────────────────────────────────────────────────────
const client = createClient({
    url: DATABASE_URL,
    ...(AUTH_TOKEN ? { authToken: AUTH_TOKEN } : {})
})
const db = drizzle(client, { schema })

// ── Wipe ─────────────────────────────────────────────────────────────────────
// Tables listed in FK-safe order: child rows deleted before parent rows.
// Using raw SQL DELETE FROM to avoid Drizzle generic-array type issues.
const WIPE_ORDER = [
    'announcement_comments',
    'announcement_reactions',
    'announcement_votes',
    'message_reactions',
    'direct_message_reactions',
    'internal_message_reactions',
    'direct_messages',
    'internal_messages',
    'messages',
    'announcements',
    'media',
    'conversations',
    'password_reset_tokens',
    'refresh_tokens',
    'sessions',
    'audit_logs',
    'user_status_history',
    'users',
] as const

async function wipe() {
    console.log('\n🗑️   Wiping all table data...')
    console.log(`    DB: ${DATABASE_URL!.substring(0, 50)}...\n`)

    await client.execute('PRAGMA foreign_keys = OFF')

    for (const table of WIPE_ORDER) {
        await client.execute(`DELETE FROM \`${table}\``)
        console.log(`   ✓ ${table}`)
    }

    await client.execute('PRAGMA foreign_keys = ON')

    console.log('\n✅  All tables wiped. Schema preserved.\n')
}

// ── Seed ─────────────────────────────────────────────────────────────────────
async function seed() {
    console.log('\n🌱   Seeding Super Admin...')
    console.log(`    Email   : ${ADMIN_EMAIL}`)
    console.log(`    Name    : ${ADMIN_NAME}`)
    console.log(`    DB      : ${DATABASE_URL!.substring(0, 50)}...\n`)

    const existing = await db
        .select({ id: schema.users.id, role: schema.users.role })
        .from(schema.users)
        .where(eq(schema.users.email, ADMIN_EMAIL))
        .limit(1)

    if (existing.length > 0) {
        console.log(`⚠️   User already exists (role: ${existing[0]?.role}). Skipping.`)
        console.log('    Run with --wipe --seed to start completely fresh.\n')
        return
    }

    const passwordHash = await hash(ADMIN_PASSWORD)

    await db.insert(schema.users).values({
        id: ulid(),
        email: ADMIN_EMAIL,
        passwordHash,
        name: ADMIN_NAME,
        role: 'SUPER_ADMIN',
        status: 'APPROVED',
        mediaPermission: true,
        emailNotifyOnMessage: true,
    })

    console.log('✅  Super Admin created!')
    console.log('\n   Login with:')
    console.log(`   Email   : ${ADMIN_EMAIL}`)
    console.log(`   Password: ${ADMIN_PASSWORD}`)
    console.log('\n   ⚠️  Change your password after first login!\n')
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    try {
        if (doWipe) await wipe()
        if (doSeed) await seed()
    } catch (err) {
        console.error('❌  Script failed:', err)
        process.exit(1)
    } finally {
        client.close()
    }
}

main()
