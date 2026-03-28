/**
 * Subsidiary-Aware Workload Assignment Engine
 *
 * Priority tiers for pickBestAdmin():
 *   1. Online ADMIN who handles this subsidiary, lowest load first
 *   2. Online SUPER_ADMIN — ONLY when ALL online ADMINs are at/above superAdminThreshold
 *   3. Online ADMIN regardless of subsidiary (lowest load) — final online fallback
 *   4. Offline ADMIN who handles this subsidiary, lowest load first
 *   5. Offline ADMIN regardless of subsidiary (lowest load)
 *   6. null — no eligible admin found
 *
 * Efficiency:
 *   - Online path: single DB query for workloads, all else in memory
 *   - Offline path: one extra DB query only when no online admin found
 *   - Offline subsidiaryIds fetched from DB (not cache — offline = not in cache)
 *
 * Circular-dependency fix:
 *   - socket emits are called via dynamic import inside reassignForSubsidiary,
 *     so this module has NO static dependency on socket/index.ts
 */

import { db } from '../db/index.js'
import { conversations, users } from '../db/schema.js'
import { eq, and, inArray, isNull, sql, or } from 'drizzle-orm'
import { serverState, getUserFromCache } from '../state.js'
import { getConfig } from './config.js'
import { logger } from './logger.js'

export interface AdminWorkload {
  adminId: string
  name: string
  activeCount: number
  isOnline: boolean
  role: 'ADMIN' | 'SUPER_ADMIN'
  /** Parsed subsidiary IDs this admin handles. Empty = generalist (handles all). */
  subsidiaryIds: string[]
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function parseSubsidiaryIds(raw: string | null | undefined): string[] {
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
  } catch {
    return []
  }
}

function adminHandlesSubsidiary(admin: AdminWorkload, subsidiaryId: string | null | undefined): boolean {
  if (!subsidiaryId) return true           // no subsidiary → any admin qualifies
  if (admin.subsidiaryIds.length === 0) return true  // generalist → handles all
  return admin.subsidiaryIds.includes(subsidiaryId)
}

// ---------------------------------------------------------------------------
// Public: workload data for a set of admin IDs
// ---------------------------------------------------------------------------

/**
 * Returns workload data. For online admins, subsidiaryIds is read from the
 * in-memory cache (fast). For offline admins, caller should supply a
 * subsidiaryMap so we don't rely on stale/missing cache entries.
 */
export async function getAdminWorkloads(
  adminIds: string[],
  globalOnlineSet?: Set<string>,
  nameMap?: Map<string, string>,
  subsidiaryMap?: Map<string, string | null>,
): Promise<AdminWorkload[]> {
  if (adminIds.length === 0) return []

  const rows = await db
    .select({
      assignedAdminId: conversations.assignedAdminId,
      count: sql<number>`count(*)`.as('count'),
    })
    .from(conversations)
    .where(and(
      inArray(conversations.assignedAdminId, adminIds),
      isNull(conversations.archivedAt),
      isNull(conversations.deletedAt),
    ))
    .groupBy(conversations.assignedAdminId)

  const countMap = new Map<string, number>()
  for (const row of rows) {
    if (row.assignedAdminId) countMap.set(row.assignedAdminId, Number(row.count))
  }

  return adminIds.map((id) => {
    const cached = getUserFromCache(id) as { role?: string; status?: string; name?: string; subsidiaryIds?: string | null } | null
    // Prefer cache for subsidiaryIds (online admins); fall back to subsidiaryMap (offline admins)
    const rawSubIds = cached?.subsidiaryIds ?? subsidiaryMap?.get(id) ?? null
    const isOnlineCheck = globalOnlineSet ? globalOnlineSet.has(id) : serverState.isUserConnected(id)
    return {
      adminId: id,
      name: nameMap?.get(id) ?? cached?.name ?? id,
      activeCount: countMap.get(id) ?? 0,
      isOnline: isOnlineCheck,
      role: (cached?.role ?? 'ADMIN') as 'ADMIN' | 'SUPER_ADMIN',
      subsidiaryIds: parseSubsidiaryIds(rawSubIds),
    }
  })
}

// ---------------------------------------------------------------------------
// Public: pick best admin
// ---------------------------------------------------------------------------

export async function pickBestAdmin(subsidiaryId?: string | null): Promise<string | null> {
  const cfg = getConfig()
  const maxLoad   = cfg.assignment?.maxConversationsPerAdmin ?? 25
  const saRatio   = cfg.assignment?.superAdminThreshold ?? 0.8
  const saLoadCap = Math.ceil(maxLoad * saRatio)  // e.g. 25 * 0.8 = 20

  // ── Step 1: collect online admin IDs from globally aware Redis ──────────────────────────
  const { getOnlineAdminIdsGlobally } = await import('../socket/index.js')
  const allOnlineIdsRaw = await getOnlineAdminIdsGlobally()
  
  const onlineAdminIds: string[] = []
  const onlineSuperAdminIds: string[] = []
  const allOnlineIds: string[] = []

  for (const userId of allOnlineIdsRaw) {
    const cached = getUserFromCache(userId) as { role?: string; status?: string } | null
    // Fallback default role/status in case Redis knows they are connected but local cache hasn't synced
    const role = cached?.role ?? 'ADMIN'
    const status = cached?.status ?? 'APPROVED'
    
    if (status !== 'APPROVED') continue
    if (role === 'ADMIN') onlineAdminIds.push(userId)
    else if (role === 'SUPER_ADMIN') onlineSuperAdminIds.push(userId)
    
    allOnlineIds.push(userId)
  }

  const globalOnlineSet = new Set(allOnlineIds)

  if (allOnlineIds.length > 0) {
    // Single DB query covers all online admins
    const workloads = await getAdminWorkloads(allOnlineIds, globalOnlineSet)
    const onlineAdmins = workloads.filter(w => w.role === 'ADMIN')

    // Tier 1: subsidiary-matched online ADMINs under hard cap
    const matched = onlineAdmins
      .filter(w => w.activeCount < maxLoad && adminHandlesSubsidiary(w, subsidiaryId))
      .sort((a, b) => a.activeCount - b.activeCount)

    if (matched.length > 0) {
      logger.debug({ pick: matched[0]!.adminId, load: matched[0]!.activeCount, subsidiaryId }, 'Assignment: subsidiary-matched online ADMIN')
      return matched[0]!.adminId
    }

    // Are ALL online ADMINs at/above the soft threshold?
    const allAtThreshold = onlineAdmins.length === 0
      || onlineAdmins.every(w => w.activeCount >= saLoadCap)

    // Tier 2: SUPER_ADMINs — only when all ADMINs are at/above threshold
    if (allAtThreshold && onlineSuperAdminIds.length > 0) {
      const superWorkloads = workloads.filter(w => w.role === 'SUPER_ADMIN')
      const eligibleSA = superWorkloads
        .filter(w => w.activeCount < maxLoad && adminHandlesSubsidiary(w, subsidiaryId))
        .sort((a, b) => a.activeCount - b.activeCount)

      if (eligibleSA.length > 0) {
        logger.debug({ pick: eligibleSA[0]!.adminId, load: eligibleSA[0]!.activeCount }, 'Assignment: SUPER_ADMIN overflow fallback')
        return eligibleSA[0]!.adminId
      }
    }

    // Tier 3: any online ADMIN under hard cap regardless of subsidiary
    // (runs whether allAtThreshold is true or false — covers the case where
    //  allAtThreshold=true but no SA was available or matched)
    const anyOnline = onlineAdmins
      .filter(w => w.activeCount < maxLoad)
      .sort((a, b) => a.activeCount - b.activeCount)

    if (anyOnline.length > 0) {
      logger.debug({ pick: anyOnline[0]!.adminId, load: anyOnline[0]!.activeCount, subsidiaryId }, 'Assignment: generalist online ADMIN fallback')
      return anyOnline[0]!.adminId
    }

    logger.warn({ onlineAdmins: allOnlineIds.length, maxLoad, saLoadCap }, 'Assignment: all online admins at hard cap')
  }

  // ── Step 2: no eligible online admin — fetch offline approved ADMINs ──────
  const allOnlineSet = new Set(allOnlineIds)

  const offlineRows = await db
    .select({ id: users.id, subsidiaryIds: users.subsidiaryIds })
    .from(users)
    .where(and(eq(users.role, 'ADMIN'), eq(users.status, 'APPROVED')))
    .limit(50)

  const offlineFiltered = offlineRows.filter(r => !allOnlineSet.has(r.id))
  if (offlineFiltered.length === 0) {
    logger.warn({ subsidiaryId }, 'Assignment: no eligible admin — conversation unassigned')
    return null
  }

  const offlineIds = offlineFiltered.map(r => r.id)
  // Pass subsidiaryMap so getAdminWorkloads can use DB data for offline admins
  // (they're not in the in-memory cache since they never connected this session)
  const offlineSubMap = new Map(offlineFiltered.map(r => [r.id, r.subsidiaryIds]))
  const workloads = await getAdminWorkloads(offlineIds, globalOnlineSet, undefined, offlineSubMap)

  // Tier 4: subsidiary-matched offline ADMIN
  const matchedOffline = workloads
    .filter(w => w.activeCount < maxLoad && adminHandlesSubsidiary(w, subsidiaryId))
    .sort((a, b) => a.activeCount - b.activeCount)

  if (matchedOffline.length > 0) {
    logger.debug({ pick: matchedOffline[0]!.adminId }, 'Assignment: subsidiary-matched offline ADMIN')
    return matchedOffline[0]!.adminId
  }

  // Tier 5: any offline ADMIN under cap
  const anyOffline = workloads
    .filter(w => w.activeCount < maxLoad)
    .sort((a, b) => a.activeCount - b.activeCount)

  if (anyOffline.length > 0) {
    logger.debug({ pick: anyOffline[0]!.adminId }, 'Assignment: generalist offline ADMIN fallback')
    return anyOffline[0]!.adminId
  }

  logger.warn({ subsidiaryId }, 'Assignment: no eligible admin — conversation unassigned')
  return null
}

// ---------------------------------------------------------------------------
// Public: smart re-assignment when subsidiary changes
// ---------------------------------------------------------------------------

export async function reassignForSubsidiary(
  conversationId: string,
  newSubsidiaryId: string | null,
  currentAdminId: string | null,
  conversationUserId: string,
): Promise<string | null> {
  // No existing assignment — run a fresh pick
  if (!currentAdminId) {
    return pickBestAdmin(newSubsidiaryId)
  }

  // Check if current admin already handles this subsidiary
  const currentCached = getUserFromCache(currentAdminId) as { subsidiaryIds?: string | null } | null
  let currentSubIds: string[]

  if (currentCached) {
    currentSubIds = parseSubsidiaryIds(currentCached.subsidiaryIds)
  } else {
    // Admin not in cache (offline) — fetch from DB
    const row = await db.query.users.findFirst({
      where: eq(users.id, currentAdminId),
      columns: { subsidiaryIds: true },
    })
    currentSubIds = parseSubsidiaryIds(row?.subsidiaryIds)
  }

  const currentHandlesIt =
    currentSubIds.length === 0 ||
    !newSubsidiaryId ||
    currentSubIds.includes(newSubsidiaryId)

  if (currentHandlesIt) {
    logger.debug({ conversationId, currentAdminId, newSubsidiaryId }, 'Subsidiary changed — current admin already handles it')
    return currentAdminId
  }

  // Find a better admin
  const newAdminId = await pickBestAdmin(newSubsidiaryId)

  if (!newAdminId || newAdminId === currentAdminId) {
    logger.debug({ conversationId, currentAdminId, newSubsidiaryId }, 'No better match — keeping current admin')
    return currentAdminId
  }

  // Write new assignment
  await db.update(conversations)
    .set({ assignedAdminId: newAdminId })
    .where(eq(conversations.id, conversationId))

  logger.info({ conversationId, oldAdminId: currentAdminId, newAdminId, newSubsidiaryId }, 'Subsidiary reassignment complete')

  // Fetch user name and new admin name in parallel — they are independent
  const [convUser, cachedOrDbNewAdmin] = await Promise.all([
    db.query.users.findFirst({
      where: eq(users.id, conversationUserId),
      columns: { name: true },
    }),
    !getUserFromCache(newAdminId)
      ? db.query.users.findFirst({
          where: eq(users.id, newAdminId),
          columns: { name: true, role: true },
        })
      : Promise.resolve(null)
  ])
  const userName = convUser?.name ?? 'a user'

  // Resolve the new admin's name/role for the conversation:assigned broadcast.
  let newAdminName: string | undefined
  let newAdminRole: string | undefined
  const cachedNewAdmin = getUserFromCache(newAdminId) as { name?: string; role?: string } | null
  if (cachedNewAdmin) {
    newAdminName = cachedNewAdmin.name
    newAdminRole = cachedNewAdmin.role
  } else {
    newAdminName = (cachedOrDbNewAdmin as { name?: string; role?: string } | null)?.name
    newAdminRole = (cachedOrDbNewAdmin as { name?: string; role?: string } | null)?.role
  }

  // Dynamic import breaks the circular dependency:
  // assignmentEngine does NOT statically depend on socket/index
  try {
    const { emitToUser, emitToAdmins } = await import('../socket/index.js')
    emitToUser(currentAdminId, 'conversation:removed', { conversationId, userName, reason: 'subsidiary_reassignment' })
    emitToUser(newAdminId, 'conversation:assigned_to_you', { conversationId, userName, subsidiaryId: newSubsidiaryId })
    emitToAdmins('conversation:assigned', {
      conversationId,
      assignedAdminId: newAdminId,
      assignedAdminName: newAdminName,
      assignedAdminRole: newAdminRole,
      oldAdminId: currentAdminId,
      reason: 'subsidiary_reassignment',
    })
  } catch (err) {
    logger.warn({ err, conversationId }, 'Failed to emit reassignment socket events — non-fatal')
  }

  return newAdminId
}

// ---------------------------------------------------------------------------
// Public: workload summary for admin dashboard
// ---------------------------------------------------------------------------

export async function getAllAdminWorkloads(): Promise<AdminWorkload[]> {
  const [admins, { getOnlineAdminIdsGlobally }] = await Promise.all([
    db
      .select({ id: users.id, name: users.name, role: users.role })
      .from(users)
      .where(and(
        or(eq(users.role, 'ADMIN'), eq(users.role, 'SUPER_ADMIN')),
        eq(users.status, 'APPROVED'),
      )),
    import('../socket/index.js')
  ])

  const globalOnlineSet = new Set(await getOnlineAdminIdsGlobally())
  const ids = admins.map(a => a.id)
  const nameMap = new Map(admins.map(a => [a.id, a.name]))
  return getAdminWorkloads(ids, globalOnlineSet, nameMap)
}
