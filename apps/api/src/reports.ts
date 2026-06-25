import { auditLogs, conversations, departments, reports, users } from "@evbus/db";
import {
  createReportRequestSchema,
  reportResponseSchema,
  reportsResponseSchema,
  reportsQuerySchema,
  updateReportStatusRequestSchema
} from "@evbus/shared";
import { and, desc, eq, lt } from "drizzle-orm";
import { requireUser } from "./auth";
import { getOrCreateCustomerConversation } from "./conversations";
import { getDb } from "./db";
import { HttpError, json, readJson } from "./http";
import type { Env } from "./index";

export async function handleReports(request: Request, env: Env, pathname: string) {
  if (pathname === "/reports" && request.method === "GET") {
    const actor = await requireUser(request, env);
    if (actor.role !== "customer") {
      throw new HttpError(403, "Customer access required.");
    }

    const db = getDb(env);
    const filters = [eq(reports.customerId, actor.id)];
    const queryParams = reportsQuerySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
    if (queryParams.status) filters.push(eq(reports.status, queryParams.status));
    if (queryParams.departmentId) filters.push(eq(reports.departmentId, queryParams.departmentId));
    if (queryParams.cursor) filters.push(lt(reports.createdAt, new Date(queryParams.cursor)));
    const rows = await db
      .select({
        id: reports.id,
        customerId: reports.customerId,
        conversationId: reports.conversationId,
        departmentId: reports.departmentId,
        customerName: users.name,
        title: reports.title,
        body: reports.body,
        status: reports.status,
        source: reports.source,
        resolvedBy: reports.resolvedBy,
        resolvedAt: reports.resolvedAt,
        createdAt: reports.createdAt,
        updatedAt: reports.updatedAt
      })
      .from(reports)
      .innerJoin(users, eq(reports.customerId, users.id))
      .where(and(...filters))
      .orderBy(desc(reports.createdAt))
      .limit(queryParams.limit);

    return json(reportsResponseSchema.parse({ reports: rows.map(serializeReport) }));
  }

  if (pathname === "/reports" && request.method === "POST") {
    const actor = await requireUser(request, env);
    if (actor.role !== "customer") {
      throw new HttpError(403, "Customer access required.");
    }

    const input = await readJson(request, createReportRequestSchema);
    const db = getDb(env);
    if (input.departmentId) {
      const [department] = await db
        .select({ id: departments.id })
        .from(departments)
        .where(and(eq(departments.id, input.departmentId), eq(departments.active, 1)))
        .limit(1);
      if (!department) {
        throw new HttpError(400, "Department is invalid.");
      }
    }

    const conversation = await getOrCreateCustomerConversation(env, actor.id);
    if (input.departmentId && !conversation.departmentId) {
      await db
        .update(conversations)
        .set({ departmentId: input.departmentId, updatedAt: new Date() })
        .where(eq(conversations.id, conversation.id));
    }
    const id = crypto.randomUUID();
    await db.insert(reports).values({
      id,
      customerId: actor.id,
      conversationId: conversation.id,
      departmentId: input.departmentId ?? null,
      title: input.title,
      body: input.body,
      status: "pending",
      source: "customer"
    });

    await audit(db, actor.id, "report.created", "report", id, request, {
      conversationId: conversation.id,
      departmentId: input.departmentId ?? null
    });

    const report = await getReportById(env, id);
    return json(reportResponseSchema.parse({ report: serializeReport(report) }), 201);
  }

  if (pathname === "/admin/reports" && request.method === "GET") {
    const actor = await requireUser(request, env);
    if (actor.role !== "super_admin" && actor.role !== "agent") {
      throw new HttpError(403, "Agent access required.");
    }

    const db = getDb(env);
    const filters = [];
    const queryParams = reportsQuerySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
    if (queryParams.status) filters.push(eq(reports.status, queryParams.status));
    if (queryParams.departmentId) filters.push(eq(reports.departmentId, queryParams.departmentId));
    if (queryParams.cursor) filters.push(lt(reports.createdAt, new Date(queryParams.cursor)));
    let query = db
      .select({
        id: reports.id,
        customerId: reports.customerId,
        conversationId: reports.conversationId,
        departmentId: reports.departmentId,
        customerName: users.name,
        title: reports.title,
        body: reports.body,
        status: reports.status,
        source: reports.source,
        resolvedBy: reports.resolvedBy,
        resolvedAt: reports.resolvedAt,
        createdAt: reports.createdAt,
        updatedAt: reports.updatedAt
      })
      .from(reports)
      .innerJoin(users, eq(reports.customerId, users.id))
      .leftJoin(conversations, eq(reports.conversationId, conversations.id))
      .$dynamic();

    if (actor.role === "agent") {
      filters.push(eq(conversations.assignedAgentId, actor.id));
    }

    if (filters.length) query = query.where(and(...filters));
    const rows = await query.orderBy(desc(reports.createdAt)).limit(queryParams.limit);
    return json(reportsResponseSchema.parse({ reports: rows.map(serializeReport) }));
  }

  const statusMatch = pathname.match(/^\/admin\/reports\/([^/]+)\/status$/);
  if (statusMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    if (actor.role !== "super_admin" && actor.role !== "agent") {
      throw new HttpError(403, "Agent access required.");
    }

    const input = await readJson(request, updateReportStatusRequestSchema);
    const db = getDb(env);
    const reportId = statusMatch[1];
    if (!reportId) {
      throw new HttpError(404, "Report not found.");
    }
    const report = await getReportWithConversation(env, reportId);
    if (actor.role === "agent" && report.assignedAgentId !== actor.id) {
      throw new HttpError(403, "Report is not assigned to you.");
    }

    const now = new Date();
    await db
      .update(reports)
      .set({
        status: input.status,
        resolvedBy: input.status === "resolved" ? actor.id : null,
        resolvedAt: input.status === "resolved" ? now : null,
        updatedAt: now
      })
      .where(eq(reports.id, report.id));

    await audit(db, actor.id, "report.status_updated", "report", report.id, request, {
      status: input.status
    });

    const updated = await getReportById(env, report.id);
    return json(reportResponseSchema.parse({ report: serializeReport(updated) }));
  }

  return null;
}

async function getReportById(env: Env, reportId: string) {
  const db = getDb(env);
  const [report] = await db
    .select({
      id: reports.id,
      customerId: reports.customerId,
      conversationId: reports.conversationId,
      departmentId: reports.departmentId,
      customerName: users.name,
      title: reports.title,
      body: reports.body,
      status: reports.status,
      source: reports.source,
      resolvedBy: reports.resolvedBy,
      resolvedAt: reports.resolvedAt,
      createdAt: reports.createdAt,
      updatedAt: reports.updatedAt
    })
    .from(reports)
    .innerJoin(users, eq(reports.customerId, users.id))
    .where(eq(reports.id, reportId))
    .limit(1);

  if (!report) throw new HttpError(404, "Report not found.");
  return report;
}

async function getReportWithConversation(env: Env, reportId: string) {
  const db = getDb(env);
  const [report] = await db
    .select({
      id: reports.id,
      assignedAgentId: conversations.assignedAgentId
    })
    .from(reports)
    .leftJoin(conversations, eq(reports.conversationId, conversations.id))
    .where(eq(reports.id, reportId))
    .limit(1);

  if (!report) throw new HttpError(404, "Report not found.");
  return report;
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

function serializeReport(report: {
  id: string;
  customerId: string;
  conversationId: string | null;
  departmentId: string | null;
  customerName: string | null;
  title: string;
  body: string;
  status: string;
  source: string;
  resolvedBy: string | null;
  resolvedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: report.id,
    customerId: report.customerId,
    conversationId: report.conversationId,
    departmentId: report.departmentId,
    customerName: report.customerName,
    title: report.title,
    body: report.body,
    status: report.status,
    source: report.source,
    resolvedBy: report.resolvedBy,
    resolvedAt: report.resolvedAt?.toISOString() ?? null,
    createdAt: report.createdAt.toISOString(),
    updatedAt: report.updatedAt.toISOString()
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
