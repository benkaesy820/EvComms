import { announcementComments, announcementReactions, announcements, auditLogs } from "@evbus/db";
import {
  announcementCommentRequestSchema,
  announcementReactionRequestSchema,
  announcementResponseSchema,
  announcementsResponseSchema,
  createAnnouncementRequestSchema
} from "@evbus/shared";
import { and, desc, eq, gt, isNull, or } from "drizzle-orm";
import { requireUser } from "./auth";
import { getDb } from "./db";
import { HttpError, json, readJson } from "./http";
import type { Env } from "./index";

export async function handleAnnouncements(request: Request, env: Env, pathname: string) {
  if (pathname === "/announcements" && request.method === "GET") {
    const actor = await requireUser(request, env);
    const db = getDb(env);
    const audience = actor.role === "customer" ? "customers" : "agents";
    const rows = await db
      .select()
      .from(announcements)
      .where(
        and(
          or(eq(announcements.audience, "everyone"), eq(announcements.audience, audience)),
          or(isNull(announcements.expiresAt), gt(announcements.expiresAt, new Date()))
        )
      )
      .orderBy(desc(announcements.createdAt))
      .limit(50);

    return json(announcementsResponseSchema.parse({ announcements: rows.map(serializeAnnouncement) }));
  }

  if (pathname === "/public/announcements" && request.method === "GET") {
    const db = getDb(env);
    const rows = await db
      .select()
      .from(announcements)
      .where(and(eq(announcements.showPublic, 1), or(isNull(announcements.expiresAt), gt(announcements.expiresAt, new Date()))))
      .orderBy(desc(announcements.createdAt))
      .limit(10);

    return json(announcementsResponseSchema.parse({ announcements: rows.map(serializeAnnouncement) }));
  }

  if (pathname === "/admin/announcements" && request.method === "POST") {
    const actor = await requireUser(request, env);
    if (actor.role !== "super_admin") {
      throw new HttpError(403, "Super Admin access required.");
    }

    const input = await readJson(request, createAnnouncementRequestSchema);
    const db = getDb(env);
    const id = crypto.randomUUID();
    await db.insert(announcements).values({
      id,
      authorId: actor.id,
      audience: input.audience,
      title: input.title,
      body: input.body,
      imageFileId: input.imageFileId ?? null,
      showPublic: input.showPublic ? 1 : 0,
      expiresAt: input.expiresAt ? new Date(input.expiresAt) : null
    });

    await audit(db, actor.id, "announcement.created", "announcement", id, request, {
      audience: input.audience,
      showPublic: input.showPublic ?? false
    });

    const [announcement] = await db.select().from(announcements).where(eq(announcements.id, id)).limit(1);
    if (!announcement) throw new HttpError(500, "Announcement was not saved.");
    return json(announcementResponseSchema.parse({ announcement: serializeAnnouncement(announcement) }), 201);
  }

  const reactionMatch = pathname.match(/^\/announcements\/([^/]+)\/reaction$/);
  if (reactionMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const announcementId = reactionMatch[1];
    if (!announcementId) throw new HttpError(404, "Announcement not found.");
    await requireAnnouncementVisible(env, actor.role, announcementId);
    const input = await readJson(request, announcementReactionRequestSchema);
    const db = getDb(env);

    await db
      .insert(announcementReactions)
      .values({
        id: crypto.randomUUID(),
        announcementId,
        userId: actor.id,
        reaction: input.reaction
      })
      .onDuplicateKeyUpdate({
        set: { reaction: input.reaction }
      });

    return json({ ok: true });
  }

  const commentMatch = pathname.match(/^\/announcements\/([^/]+)\/comments$/);
  if (commentMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const announcementId = commentMatch[1];
    if (!announcementId) throw new HttpError(404, "Announcement not found.");
    await requireAnnouncementVisible(env, actor.role, announcementId);
    const input = await readJson(request, announcementCommentRequestSchema);
    const db = getDb(env);
    const id = crypto.randomUUID();
    await db.insert(announcementComments).values({
      id,
      announcementId,
      userId: actor.id,
      body: input.body
    });
    return json({ ok: true, id }, 201);
  }

  return null;
}

async function requireAnnouncementVisible(env: Env, role: string, announcementId: string) {
  const db = getDb(env);
  const audience = role === "customer" ? "customers" : "agents";
  const [announcement] = await db
    .select({ id: announcements.id })
    .from(announcements)
    .where(
      and(
        eq(announcements.id, announcementId),
        or(eq(announcements.audience, "everyone"), eq(announcements.audience, audience)),
        or(isNull(announcements.expiresAt), gt(announcements.expiresAt, new Date()))
      )
    )
    .limit(1);

  if (!announcement) throw new HttpError(404, "Announcement not found.");
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

function serializeAnnouncement(announcement: {
  id: string;
  authorId: string;
  audience: string;
  title: string;
  body: string;
  imageFileId: string | null;
  showPublic: number;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: announcement.id,
    authorId: announcement.authorId,
    audience: announcement.audience,
    title: announcement.title,
    body: announcement.body,
    imageFileId: announcement.imageFileId,
    showPublic: announcement.showPublic !== 0,
    expiresAt: announcement.expiresAt?.toISOString() ?? null,
    createdAt: announcement.createdAt.toISOString(),
    updatedAt: announcement.updatedAt.toISOString()
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
