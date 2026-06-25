import { auditLogs, authRateLimits, passwordResetTokens, runMigrations, sessions, users } from "@evbus/db";
import {
  accountPreferencesResponseSchema,
  authResponseSchema,
  loginRequestSchema,
  publicUserSchema,
  registerRequestSchema,
  requestPasswordResetSchema,
  resetPasswordSchema,
  sessionsResponseSchema,
  updateAccountPreferencesRequestSchema
} from "@evbus/shared";
import { and, desc, eq, gt, inArray, isNull, lte, sql } from "drizzle-orm";
import { clearSessionCookie, createSessionCookie, getSessionToken } from "./cookies";
import { getConnection, getDb } from "./db";
import type { Env } from "./index";
import { hashPassword, randomToken, sha256Hex, verifyPassword } from "./crypto";
import { HttpError, json, readJson } from "./http";
import { enqueueNotification, processNotificationJobs } from "./notifications";

const sessionDays = 30;
const maxSessionsPerUser = 2;
const loginLockThreshold = 10;
const loginLockMinutes = 30;
const resetLockThreshold = 5;
const resetLockMinutes = 30;

const bootstrapAdminSchema = registerRequestSchema.extend({});

export async function handleAuth(
  request: Request,
  env: Env,
  pathname: string,
  ctx?: ExecutionContext
) {
  if (pathname === "/auth/register" && request.method === "POST") {
    return register(request, env);
  }

  if (pathname === "/auth/login" && request.method === "POST") {
    return login(request, env);
  }

  if (pathname === "/auth/logout" && request.method === "POST") {
    return logout(request, env);
  }

  if (pathname === "/auth/logout-all" && request.method === "POST") {
    return logoutAll(request, env);
  }

  if (pathname === "/auth/sessions" && request.method === "GET") {
    return listSessions(request, env);
  }

  if (pathname === "/account/preferences" && request.method === "GET") {
    return getPreferences(request, env);
  }

  if (pathname === "/account/preferences" && request.method === "PUT") {
    return updatePreferences(request, env);
  }

  if (pathname === "/auth/request-password-reset" && request.method === "POST") {
    return requestPasswordReset(request, env, ctx);
  }

  if (pathname === "/auth/reset-password" && request.method === "POST") {
    return resetPassword(request, env);
  }

  if (pathname === "/auth/me" && request.method === "GET") {
    const user = await requireUser(request, env);
    return json(authResponseSchema.parse({ user: toPublicUser(user) }));
  }

  if (pathname === "/dev/migrate" && request.method === "POST") {
    ensureDevelopment(env);
    try {
      await runMigrations(getConnection(env));
    } catch (error) {
      throw new HttpError(500, error instanceof Error ? error.message : "Migration failed.");
    }
    return json({ ok: true });
  }

  if (pathname === "/dev/bootstrap-admin" && request.method === "POST") {
    ensureDevelopment(env);
    return bootstrapAdmin(request, env);
  }

  return null;
}

export async function requireUser(request: Request, env: Env) {
  const token = getSessionToken(request);

  if (!token) {
    throw new HttpError(401, "Not authenticated.");
  }

  const db = getDb(env);
  const tokenHash = await sha256Hex(token);
  const now = new Date();

  const [row] = await db
    .select({
      id: users.id,
      role: users.role,
      name: users.name,
      email: users.email,
      phone: users.phone,
      registrationNote: users.registrationNote,
      status: users.status
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now)
      )
    )
    .limit(1);

  if (!row) {
    throw new HttpError(401, "Not authenticated.");
  }

  if (row.status !== "approved") {
    throw new HttpError(403, "Account is not approved.");
  }

  return row;
}

async function register(request: Request, env: Env) {
  const input = await readJson(request, registerRequestSchema);
  const db = getDb(env);
  const email = input.email.toLowerCase();
  const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);

  if (existing) {
    throw new HttpError(409, "An account with this email already exists.");
  }

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(input.password);

  await db.insert(users).values({
    id,
    role: "customer",
    name: input.name,
    email,
    phone: input.phone,
    registrationNote: input.registrationNote ?? null,
    passwordHash,
    status: "pending"
  });

  await audit(db, null, "customer.registered", "user", id, request, {
    email,
    hasRegistrationNote: Boolean(input.registrationNote)
  });
  return json(
    authResponseSchema.parse({
      user: toPublicUser({
        id,
        role: "customer",
        name: input.name,
        email,
        phone: input.phone,
        registrationNote: input.registrationNote ?? null,
        status: "pending"
      })
    }),
    201
  );
}

async function login(request: Request, env: Env) {
  const input = await readJson(request, loginRequestSchema);
  const db = getDb(env);
  const email = input.email.toLowerCase();
  const emailLimitHash = await sha256Hex(`login:email:${email}`);
  const ipLimitHash = await sha256Hex(`login:ip:${getIpPrefix(request) ?? "unknown"}`);

  await assertNotLocked(db, "login_email", emailLimitHash);
  await assertNotLocked(db, "login_ip", ipLimitHash);

  const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);

  if (!user || !(await verifyPassword(input.password, user.passwordHash))) {
    await recordFailedAttempt(db, "login_email", emailLimitHash, loginLockThreshold, loginLockMinutes);
    await recordFailedAttempt(db, "login_ip", ipLimitHash, loginLockThreshold, loginLockMinutes);
    throw new HttpError(401, "Invalid email or password.");
  }

  if (user.status !== "approved") {
    await recordFailedAttempt(db, "login_email", emailLimitHash, loginLockThreshold, loginLockMinutes);
    throw new HttpError(403, `Account is ${user.status}.`);
  }

  await clearRateLimit(db, "login_email", emailLimitHash);
  await clearRateLimit(db, "login_ip", ipLimitHash);

  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + sessionDays * 24 * 60 * 60 * 1000);

  await db.insert(sessions).values({
    id: crypto.randomUUID(),
    userId: user.id,
    tokenHash,
    userAgent: request.headers.get("User-Agent"),
    ipPrefix: getIpPrefix(request),
    expiresAt
  });

  await trimSessions(db, user.id);
  await audit(db, user.id, "auth.login", "user", user.id, request);

  const response = json(authResponseSchema.parse({ user: toPublicUser(user) }));
  response.headers.append("Set-Cookie", createSessionCookie(token, expiresAt, isSecureCookie(env)));
  return response;
}

async function logout(request: Request, env: Env) {
  const token = getSessionToken(request);
  const db = getDb(env);

  if (token) {
    await db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(eq(sessions.tokenHash, await sha256Hex(token)));
  }

  const response = json({ ok: true });
  response.headers.append("Set-Cookie", clearSessionCookie(isSecureCookie(env)));
  return response;
}

async function logoutAll(request: Request, env: Env) {
  const user = await requireUser(request, env);
  const db = getDb(env);
  const now = new Date();

  await db
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.userId, user.id), isNull(sessions.revokedAt)));

  await audit(db, user.id, "auth.logout_all", "user", user.id, request);

  const response = json({ ok: true });
  response.headers.append("Set-Cookie", clearSessionCookie(isSecureCookie(env)));
  return response;
}

async function listSessions(request: Request, env: Env) {
  const user = await requireUser(request, env);
  const token = getSessionToken(request);
  const tokenHash = token ? await sha256Hex(token) : null;
  const db = getDb(env);
  const rows = await db
    .select({
      id: sessions.id,
      tokenHash: sessions.tokenHash,
      userAgent: sessions.userAgent,
      ipPrefix: sessions.ipPrefix,
      createdAt: sessions.createdAt,
      expiresAt: sessions.expiresAt
    })
    .from(sessions)
    .where(and(eq(sessions.userId, user.id), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())))
    .orderBy(desc(sessions.createdAt))
    .limit(10);

  return json(
    sessionsResponseSchema.parse({
      sessions: rows.map((session) => ({
        id: session.id,
        current: tokenHash === session.tokenHash,
        userAgent: session.userAgent,
        ipPrefix: session.ipPrefix,
        createdAt: session.createdAt.toISOString(),
        expiresAt: session.expiresAt.toISOString()
      }))
    })
  );
}

async function getPreferences(request: Request, env: Env) {
  const user = await requireUser(request, env);
  const db = getDb(env);
  const [row] = await db
    .select({ emailNotificationsEnabled: users.emailNotificationsEnabled })
    .from(users)
    .where(eq(users.id, user.id))
    .limit(1);

  return json(
    accountPreferencesResponseSchema.parse({
      preferences: {
        emailNotificationsEnabled: row?.emailNotificationsEnabled !== 0
      }
    })
  );
}

async function updatePreferences(request: Request, env: Env) {
  const user = await requireUser(request, env);
  const input = await readJson(request, updateAccountPreferencesRequestSchema);
  const db = getDb(env);
  const updates: { emailNotificationsEnabled?: number; updatedAt: Date } = { updatedAt: new Date() };

  if (typeof input.emailNotificationsEnabled === "boolean") {
    updates.emailNotificationsEnabled = input.emailNotificationsEnabled ? 1 : 0;
  }

  await db.update(users).set(updates).where(eq(users.id, user.id));
  await audit(db, user.id, "account.preferences.updated", "user", user.id, request, input);

  return json(
    accountPreferencesResponseSchema.parse({
      preferences: {
        emailNotificationsEnabled: input.emailNotificationsEnabled ?? true
      }
    })
  );
}

async function requestPasswordReset(request: Request, env: Env, ctx?: ExecutionContext) {
  const input = await readJson(request, requestPasswordResetSchema);
  const db = getDb(env);
  const email = input.email.toLowerCase();
  const resetLimitHash = await sha256Hex(`password-reset:${email}:${getIpPrefix(request) ?? "unknown"}`);

  await assertNotLocked(db, "password_reset", resetLimitHash);
  await recordFailedAttempt(db, "password_reset", resetLimitHash, resetLockThreshold, resetLockMinutes);

  const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);

  if (user && user.status === "approved") {
    const token = randomToken(32);
    const tokenHash = await sha256Hex(token);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await db.insert(passwordResetTokens).values({
      id: crypto.randomUUID(),
      userId: user.id,
      tokenHash,
      expiresAt
    });

    await db
      .update(passwordResetTokens)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(passwordResetTokens.userId, user.id),
          isNull(passwordResetTokens.usedAt),
          lte(passwordResetTokens.expiresAt, expiresAt),
          sql`${passwordResetTokens.tokenHash} <> ${tokenHash}`
        )
      );

    await audit(db, user.id, "auth.password_reset.requested", "user", user.id, request);
    await enqueueNotification(env, {
      recipientId: user.id,
      type: "auth.password_reset",
      dedupeKey: `password-reset:${user.id}:${tokenHash}`,
      payload: {
        token,
        email: user.email
      }
    });
    const delivery = processNotificationJobs(env, { dryRun: false, limit: 3 }).catch((error) => {
      console.error(error);
    });
    if (ctx) {
      ctx.waitUntil(delivery);
    } else {
      await delivery;
    }
  }

  return json({ ok: true });
}

async function resetPassword(request: Request, env: Env) {
  const input = await readJson(request, resetPasswordSchema);
  const db = getDb(env);
  const tokenHash = await sha256Hex(input.token);
  const now = new Date();

  const [resetToken] = await db
    .select()
    .from(passwordResetTokens)
    .where(
      and(
        eq(passwordResetTokens.tokenHash, tokenHash),
        isNull(passwordResetTokens.usedAt),
        gt(passwordResetTokens.expiresAt, now)
      )
    )
    .limit(1);

  if (!resetToken) {
    throw new HttpError(400, "Password reset link is invalid or expired.");
  }

  await db
    .update(users)
    .set({
      passwordHash: await hashPassword(input.password),
      updatedAt: now
    })
    .where(eq(users.id, resetToken.userId));

  await db
    .update(passwordResetTokens)
    .set({ usedAt: now })
    .where(eq(passwordResetTokens.id, resetToken.id));

  await db
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.userId, resetToken.userId), isNull(sessions.revokedAt)));

  await audit(db, resetToken.userId, "auth.password_reset.completed", "user", resetToken.userId, request);

  return json({ ok: true });
}

async function bootstrapAdmin(request: Request, env: Env) {
  const input = await readJson(request, bootstrapAdminSchema);
  const db = getDb(env);
  const [existingAdmin] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.role, "super_admin"))
    .limit(1);

  if (existingAdmin) {
    throw new HttpError(409, "Super Admin already exists.");
  }

  const id = crypto.randomUUID();
  const email = input.email.toLowerCase();

  await db.insert(users).values({
    id,
    role: "super_admin",
    name: input.name,
    email,
    phone: input.phone,
    passwordHash: await hashPassword(input.password),
    status: "approved"
  });

  await audit(db, id, "dev.bootstrap_admin", "user", id, request, { email });
  return json(
    authResponseSchema.parse({
      user: toPublicUser({
        id,
        role: "super_admin",
        name: input.name,
        email,
        phone: input.phone,
        status: "approved"
      })
    }),
    201
  );
}

async function trimSessions(db: ReturnType<typeof getDb>, userId: string) {
  const activeSessions = await db
    .select({ id: sessions.id })
    .from(sessions)
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    .orderBy(sessions.createdAt);

  const sessionsToRevoke = activeSessions.slice(0, Math.max(0, activeSessions.length - maxSessionsPerUser));

  if (sessionsToRevoke.length) {
    await db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(inArray(sessions.id, sessionsToRevoke.map((session) => session.id)));
  }
}

async function assertNotLocked(db: ReturnType<typeof getDb>, scope: string, identifierHash: string) {
  const [row] = await db
    .select({ lockedUntil: authRateLimits.lockedUntil })
    .from(authRateLimits)
    .where(and(eq(authRateLimits.scope, scope), eq(authRateLimits.identifierHash, identifierHash)))
    .limit(1);

  if (row?.lockedUntil && row.lockedUntil > new Date()) {
    throw new HttpError(429, "Too many attempts. Please try again later.");
  }
}

async function recordFailedAttempt(
  db: ReturnType<typeof getDb>,
  scope: string,
  identifierHash: string,
  threshold: number,
  lockMinutes: number
) {
  const now = new Date();
  const [row] = await db
    .select({ id: authRateLimits.id, attempts: authRateLimits.attempts })
    .from(authRateLimits)
    .where(and(eq(authRateLimits.scope, scope), eq(authRateLimits.identifierHash, identifierHash)))
    .limit(1);

  if (!row) {
    await db.insert(authRateLimits).values({
      id: crypto.randomUUID(),
      scope,
      identifierHash,
      attempts: 1,
      updatedAt: now
    });
    return;
  }

  const attempts = row.attempts + 1;
  await db
    .update(authRateLimits)
    .set({
      attempts,
      lockedUntil: attempts >= threshold ? new Date(Date.now() + lockMinutes * 60_000) : null,
      updatedAt: now
    })
    .where(eq(authRateLimits.id, row.id));
}

async function clearRateLimit(db: ReturnType<typeof getDb>, scope: string, identifierHash: string) {
  await db
    .update(authRateLimits)
    .set({ attempts: 0, lockedUntil: null, updatedAt: new Date() })
    .where(and(eq(authRateLimits.scope, scope), eq(authRateLimits.identifierHash, identifierHash)));
}

async function audit(
  db: ReturnType<typeof getDb>,
  actorId: string | null,
  action: string,
  targetType: string,
  targetId: string | null,
  request: Request,
  metadata?: Record<string, unknown>
) {
  await db.insert(auditLogs).values({
    id: crypto.randomUUID(),
    actorId,
    action,
    targetType,
    targetId,
    metadata: metadata ?? null,
    ipPrefix: getIpPrefix(request)
  });
}

function toPublicUser(user: {
  id: string;
  role: string;
  name: string;
  email: string;
  phone: string | null;
  status: string;
  registrationNote?: string | null;
}) {
  return publicUserSchema.parse({
    id: user.id,
    role: user.role,
    name: user.name,
    email: user.email,
    phone: user.phone,
    registrationNote: user.registrationNote ?? null,
    status: user.status
  });
}

function ensureDevelopment(env: Env) {
  if (env.APP_ENV !== "development") {
    throw new HttpError(404, "Not found.");
  }
}

function isSecureCookie(env: Env) {
  return env.APP_ENV !== "development";
}

function getIpPrefix(request: Request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;

  if (ip.includes(".")) {
    return ip.split(".").slice(0, 3).join(".");
  }

  return ip.split(":").slice(0, 4).join(":");
}
