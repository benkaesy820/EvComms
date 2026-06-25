import { agentDepartments, auditLogs, conversations, departments, notificationJobs, sessions, users } from "@evbus/db";
import {
  authResponseSchema,
  adminHealthResponseSchema,
  auditLogsResponseSchema,
  createDepartmentRequestSchema,
  departmentsResponseSchema,
  createAgentRequestSchema,
  notificationJobsResponseSchema,
  pendingUsersResponseSchema,
  processNotificationJobsRequestSchema,
  processNotificationJobsResponseSchema,
  publicUserSchema,
  rejectUserRequestSchema,
  updateAgentDepartmentsRequestSchema,
  usersResponseSchema
} from "@evbus/shared";
import { and, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { getDb } from "./db";
import type { Env } from "./index";
import { HttpError, json, readJson } from "./http";
import { requireUser } from "./auth";
import { hashPassword } from "./crypto";
import { enqueueNotification, processNotificationJobs } from "./notifications";
import { chooseAgentForConversation } from "./conversations";

export async function handleAdmin(request: Request, env: Env, pathname: string) {
  if (pathname === "/admin/pending-users" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const pendingUsers = await db
      .select()
      .from(users)
      .where(and(eq(users.role, "customer"), eq(users.status, "pending")))
      .orderBy(users.createdAt)
      .limit(100);

    return json(pendingUsersResponseSchema.parse({ users: pendingUsers.map(toPublicUser) }));
  }

  if (pathname === "/admin/agents" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const agents = await db
      .select()
      .from(users)
      .where(eq(users.role, "agent"))
      .orderBy(users.createdAt)
      .limit(100);

    return json(usersResponseSchema.parse({ users: agents.map(toPublicUser) }));
  }

  if (pathname === "/admin/customers" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const customers = await db
      .select()
      .from(users)
      .where(eq(users.role, "customer"))
      .orderBy(desc(users.createdAt))
      .limit(100);

    return json(usersResponseSchema.parse({ users: customers.map(toPublicUser) }));
  }

  if (pathname === "/admin/notification-jobs" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const jobs = await db
      .select({
        id: notificationJobs.id,
        recipientId: notificationJobs.recipientId,
        recipientEmail: users.email,
        channel: notificationJobs.channel,
        type: notificationJobs.type,
        status: notificationJobs.status,
        dedupeKey: notificationJobs.dedupeKey,
        attempts: notificationJobs.attempts,
        nextAttemptAt: notificationJobs.nextAttemptAt,
        sentAt: notificationJobs.sentAt,
        provider: notificationJobs.provider,
        lastError: notificationJobs.lastError,
        createdAt: notificationJobs.createdAt,
        updatedAt: notificationJobs.updatedAt
      })
      .from(notificationJobs)
      .leftJoin(users, eq(notificationJobs.recipientId, users.id))
      .orderBy(desc(notificationJobs.createdAt))
      .limit(25);

    return json(
      notificationJobsResponseSchema.parse({
        jobs: jobs.map((job) => ({
          ...job,
          nextAttemptAt: job.nextAttemptAt.toISOString(),
          sentAt: job.sentAt?.toISOString() ?? null,
          createdAt: job.createdAt.toISOString(),
          updatedAt: job.updatedAt.toISOString()
        }))
      })
    );
  }

  if (pathname === "/admin/audit-logs" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const url = new URL(request.url);
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") ?? 50)));
    const filters = [];
    const action = url.searchParams.get("action");
    const actorId = url.searchParams.get("actorId");
    const targetId = url.searchParams.get("targetId");
    const targetType = url.searchParams.get("targetType");

    if (action) filters.push(eq(auditLogs.action, action));
    if (actorId) filters.push(eq(auditLogs.actorId, actorId));
    if (targetId) filters.push(eq(auditLogs.targetId, targetId));
    if (targetType) filters.push(eq(auditLogs.targetType, targetType));

    const db = getDb(env);
    let query = db
      .select({
        id: auditLogs.id,
        actorId: auditLogs.actorId,
        action: auditLogs.action,
        targetType: auditLogs.targetType,
        targetId: auditLogs.targetId,
        metadata: auditLogs.metadata,
        ipPrefix: auditLogs.ipPrefix,
        createdAt: auditLogs.createdAt
      })
      .from(auditLogs)
      .$dynamic();

    if (filters.length) query = query.where(and(...filters));

    const rows = await query.orderBy(desc(auditLogs.createdAt)).limit(limit);
    const actorIds = [...new Set(rows.map((row) => row.actorId).filter((id): id is string => Boolean(id)))];
    const actors = actorIds.length
      ? await db
          .select({ id: users.id, email: users.email })
          .from(users)
          .where(inArray(users.id, actorIds))
      : [];
    const actorEmails = new Map(actors.map((actor) => [actor.id, actor.email]));

    return json(
      auditLogsResponseSchema.parse({
        logs: rows.map((row) => ({
          ...row,
          actorEmail: row.actorId ? actorEmails.get(row.actorId) ?? null : null,
          createdAt: row.createdAt.toISOString()
        }))
      })
    );
  }

  if (pathname === "/admin/health" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const startedAt = Date.now();
    await db.select({ ok: sql<number>`1` }).from(users).limit(1);
    const latencyMs = Date.now() - startedAt;

    const [open] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(conversations)
      .where(eq(conversations.status, "open"));
    const [unassigned] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(conversations)
      .where(and(eq(conversations.status, "open"), isNull(conversations.assignedAgentId)));
    const [waiting] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(conversations)
      .where(sql`${conversations.status} = 'open'
        AND ${conversations.lastCustomerMessageAt} IS NOT NULL
        AND (${conversations.lastAgentMessageAt} IS NULL OR ${conversations.lastCustomerMessageAt} > ${conversations.lastAgentMessageAt})`);
    const notificationCounts = await db
      .select({
        status: notificationJobs.status,
        count: sql<number>`COUNT(*)`
      })
      .from(notificationJobs)
      .where(sql`${notificationJobs.status} IN ('queued', 'failed', 'sending')`)
      .groupBy(notificationJobs.status);
    const notificationCount = new Map(notificationCounts.map((row) => [row.status, Number(row.count)]));

    return json(
      adminHealthResponseSchema.parse({
        ok: true,
        time: new Date().toISOString(),
        database: {
          ok: true,
          latencyMs
        },
        conversations: {
          open: Number(open?.count ?? 0),
          unassigned: Number(unassigned?.count ?? 0),
          waiting: Number(waiting?.count ?? 0)
        },
        notifications: {
          queued: notificationCount.get("queued") ?? 0,
          failed: notificationCount.get("failed") ?? 0,
          sending: notificationCount.get("sending") ?? 0
        }
      })
    );
  }

  if (pathname === "/admin/notification-jobs/process" && request.method === "POST") {
    const actor = await requireSuperAdmin(request, env);
    const input = await readJson(request, processNotificationJobsRequestSchema);
    const db = getDb(env);
    const result = await processNotificationJobs(env, {
      dryRun: input.dryRun ?? false,
      limit: input.limit ?? 5
    });

    await audit(db, actor.id, "admin.notification_jobs.processed", "notification_job", null, request, {
      dryRun: input.dryRun,
      processed: result.processed,
      sent: result.sent,
      failed: result.failed,
      skipped: result.skipped
    });

    return json(processNotificationJobsResponseSchema.parse(result));
  }

  if (pathname === "/admin/agents" && request.method === "POST") {
    const actor = await requireSuperAdmin(request, env);
    const input = await readJson(request, createAgentRequestSchema);
    const db = getDb(env);
    const email = input.email.toLowerCase();
    const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);

    if (existing) {
      throw new HttpError(409, "An account with this email already exists.");
    }

    const id = crypto.randomUUID();
    await db.insert(users).values({
      id,
      role: "agent",
      name: input.name,
      email,
      phone: input.phone ?? null,
      passwordHash: await hashPassword(input.password),
      status: "approved"
    });

    await audit(db, actor.id, "admin.agent.created", "user", id, request, { email });
    return json(
      authResponseSchema.parse({
        user: toPublicUser({
          id,
          role: "agent",
          name: input.name,
          email,
          phone: input.phone ?? null,
          status: "approved"
        })
      }),
      201
    );
  }

  if (pathname === "/admin/departments" && request.method === "GET") {
    await requireSuperAdmin(request, env);
    const db = getDb(env);
    const rows = await db.select().from(departments).orderBy(departments.name).limit(100);

    return json(
      departmentsResponseSchema.parse({
        departments: rows.map(serializeDepartment)
      })
    );
  }

  if (pathname === "/admin/departments" && request.method === "POST") {
    const actor = await requireSuperAdmin(request, env);
    const input = await readJson(request, createDepartmentRequestSchema);
    const db = getDb(env);
    const id = crypto.randomUUID();

    try {
      await db.insert(departments).values({
        id,
        name: input.name,
        active: 1
      });
    } catch (error) {
      if (error instanceof Error && /Duplicate entry|1062/.test(error.message)) {
        throw new HttpError(409, "Department already exists.");
      }
      throw error;
    }

    await audit(db, actor.id, "admin.department.created", "department", id, request, {
      name: input.name
    });

    const [department] = await db.select().from(departments).where(eq(departments.id, id)).limit(1);
    if (!department) {
      throw new HttpError(500, "Department was not saved.");
    }
    return json(departmentsResponseSchema.parse({ departments: [serializeDepartment(department)] }), 201);
  }

  const agentDepartmentsMatch = pathname.match(/^\/admin\/agents\/([^/]+)\/departments$/);
  if (agentDepartmentsMatch && request.method === "PUT") {
    const actor = await requireSuperAdmin(request, env);
    const input = await readJson(request, updateAgentDepartmentsRequestSchema);
    const db = getDb(env);
    const agentId = agentDepartmentsMatch[1];
    if (!agentId) {
      throw new HttpError(404, "Agent not found.");
    }
    const [agent] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.id, agentId), eq(users.role, "agent"), eq(users.status, "approved")))
      .limit(1);

    if (!agent) {
      throw new HttpError(404, "Approved agent not found.");
    }

    const uniqueDepartmentIds = [...new Set(input.departmentIds)];
    if (uniqueDepartmentIds.length) {
      const activeDepartments = await db
        .select({ id: departments.id })
        .from(departments)
        .where(and(inArray(departments.id, uniqueDepartmentIds), eq(departments.active, 1)));

      if (activeDepartments.length !== uniqueDepartmentIds.length) {
        throw new HttpError(400, "One or more departments are invalid.");
      }
    }

    await db.delete(agentDepartments).where(eq(agentDepartments.agentId, agent.id));
    if (uniqueDepartmentIds.length) {
      await db.insert(agentDepartments).values(
        uniqueDepartmentIds.map((departmentId) => ({
          id: crypto.randomUUID(),
          agentId: agent.id,
          departmentId
        }))
      );
    }

    await audit(db, actor.id, "admin.agent_departments.updated", "user", agent.id, request, {
      departmentIds: uniqueDepartmentIds
    });

    return json({ ok: true });
  }

  const approveMatch = pathname.match(/^\/admin\/users\/([^/]+)\/approve$/);
  if (approveMatch && request.method === "POST") {
    return updateCustomerStatus(request, env, approveMatch[1], "approved");
  }

  const rejectMatch = pathname.match(/^\/admin\/users\/([^/]+)\/reject$/);
  if (rejectMatch && request.method === "POST") {
    const input = await readJson(request, rejectUserRequestSchema);
    return updateCustomerStatus(request, env, rejectMatch[1], "rejected", input.reason);
  }

  const suspendMatch = pathname.match(/^\/admin\/users\/([^/]+)\/suspend$/);
  if (suspendMatch && request.method === "POST") {
    return suspendUser(request, env, suspendMatch[1]);
  }

  return null;
}

async function suspendUser(request: Request, env: Env, userId: string | undefined) {
  if (!userId) {
    throw new HttpError(404, "User not found.");
  }

  const actor = await requireSuperAdmin(request, env);
  if (actor.id === userId) {
    throw new HttpError(409, "You cannot suspend your own account.");
  }

  const db = getDb(env);
  const [target] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!target) {
    throw new HttpError(404, "User not found.");
  }

  if (target.status === "suspended") {
    throw new HttpError(409, "User is already suspended.");
  }

  const now = new Date();
  await db.update(users).set({ status: "suspended", updatedAt: now }).where(eq(users.id, target.id));
  await db
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.userId, target.id), isNull(sessions.revokedAt)));

  await audit(db, actor.id, "admin.user.suspended", "user", target.id, request, {
    email: target.email,
    role: target.role
  });

  if (target.role === "agent") {
    await reassignSuspendedAgentConversations(request, env, actor.id, target.id);
  }

  return json(authResponseSchema.parse({ user: toPublicUser({ ...target, status: "suspended" }) }));
}

async function reassignSuspendedAgentConversations(
  request: Request,
  env: Env,
  actorId: string,
  agentId: string
) {
  const db = getDb(env);
  const assignedConversations = await db
    .select({
      id: conversations.id,
      customerId: conversations.customerId
    })
    .from(conversations)
    .where(and(eq(conversations.assignedAgentId, agentId), eq(conversations.status, "open")));

  for (const conversation of assignedConversations) {
    const nextAgentId = await chooseAgentForConversation(env, agentId);
    await db
      .update(conversations)
      .set({ assignedAgentId: nextAgentId, updatedAt: new Date() })
      .where(eq(conversations.id, conversation.id));

    await audit(db, actorId, "conversation.reassigned_after_agent_suspension", "conversation", conversation.id, request, {
      suspendedAgentId: agentId,
      assignedAgentId: nextAgentId
    });

    await enqueueNotification(env, {
      recipientId: nextAgentId,
      type: "conversation.reassigned",
      dedupeKey: `agent-suspended-reassign:${conversation.id}:${nextAgentId ?? "unassigned"}:${Date.now()}`,
      payload: {
        conversationId: conversation.id,
        customerId: conversation.customerId,
        assignedBy: actorId
      }
    });
  }
}

async function updateCustomerStatus(
  request: Request,
  env: Env,
  userId: string | undefined,
  status: "approved" | "rejected",
  reason?: string
) {
  if (!userId) {
    throw new HttpError(404, "User not found.");
  }

  const actor = await requireSuperAdmin(request, env);
  const db = getDb(env);
  const [target] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, userId), eq(users.role, "customer")))
    .limit(1);

  if (!target) {
    throw new HttpError(404, "Customer not found.");
  }

  if (target.status !== "pending") {
    throw new HttpError(409, `Customer is already ${target.status}.`);
  }

  await db.update(users).set({ status, updatedAt: new Date() }).where(eq(users.id, target.id));

  await audit(db, actor.id, `admin.customer.${status}`, "user", target.id, request, {
    email: target.email,
    reason: reason ?? null
  });

  await enqueueNotification(env, {
    recipientId: target.id,
    type: status === "approved" ? "customer.approved" : "customer.rejected",
    dedupeKey: `customer-status:${target.id}:${status}`,
    payload: {
      customerId: target.id,
      customerName: target.name,
      email: target.email,
      reason: reason ?? null
    }
  });

  return json(authResponseSchema.parse({ user: toPublicUser({ ...target, status }) }));
}

async function requireSuperAdmin(request: Request, env: Env) {
  const user = await requireUser(request, env);

  if (user.role !== "super_admin") {
    throw new HttpError(403, "Super Admin access required.");
  }

  return user;
}

async function audit(
  db: ReturnType<typeof getDb>,
  actorId: string,
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

function serializeDepartment(department: {
  id: string;
  name: string;
  active: number;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: department.id,
    name: department.name,
    active: department.active !== 0,
    createdAt: department.createdAt.toISOString(),
    updatedAt: department.updatedAt.toISOString()
  };
}

function getIpPrefix(request: Request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;

  if (ip.includes(".")) {
    return ip.split(".").slice(0, 3).join(".");
  }

  return ip.split(":").slice(0, 4).join(":");
}
