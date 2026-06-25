import { auditLogs, files } from "@evbus/db";
import { fileResponseSchema } from "@evbus/shared";
import { and, eq, gte, sql } from "drizzle-orm";
import { requireUser } from "./auth";
import { getDb } from "./db";
import { HttpError, json } from "./http";
import type { Env } from "./index";
import { getAppSettings } from "./settings";

type AllowedMime =
  | "image/jpeg"
  | "image/png"
  | "image/webp"
  | "application/pdf"
  | "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

const allowedTypes: Record<AllowedMime, "image" | "document"> = {
  "image/jpeg": "image",
  "image/png": "image",
  "image/webp": "image",
  "application/pdf": "document",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document"
};

export async function handleFiles(request: Request, env: Env, pathname: string) {
  if (pathname === "/files" && request.method === "POST") {
    const actor = await requireUser(request, env);
    const form = await request.formData();
    const upload = form.get("file");
    if (!(upload instanceof File)) {
      throw new HttpError(400, "File is required.");
    }

    const settings = await getAppSettings(env);
    const db = getDb(env);
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [dailyUploads] = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(files)
      .where(and(eq(files.ownerId, actor.id), gte(files.createdAt, since)));

    if (Number(dailyUploads?.count ?? 0) >= settings.dailyUploadLimit) {
      throw new HttpError(429, "Daily upload limit reached.");
    }

    const bytes = new Uint8Array(await upload.arrayBuffer());
    const detectedMime = detectMime(bytes, upload.type);
    if (!detectedMime) {
      throw new HttpError(400, "File type is not allowed.");
    }
    const kind = allowedTypes[detectedMime];

    const maxBytes =
      kind === "image" ? settings.maxImageSizeMb * 1024 * 1024 : settings.maxDocumentSizeMb * 1024 * 1024;
    if (bytes.byteLength > maxBytes) {
      throw new HttpError(400, "File is too large.");
    }

    const hash = await sha256Hex(bytes);
    const [existing] = await db.select().from(files).where(eq(files.sha256Hash, hash)).limit(1);
    if (existing) {
      return json(fileResponseSchema.parse({ file: serializeFile(existing) }));
    }

    if (!env.FILE_BUCKET) {
      throw new HttpError(503, "File storage is not configured.");
    }

    const id = crypto.randomUUID();
    const storageKey = `${kind}/${hash}`;
    await env.FILE_BUCKET.put(storageKey, bytes, {
      httpMetadata: {
        contentType: detectedMime
      }
    });

    await db.insert(files).values({
      id,
      ownerId: actor.id,
      storageKey,
      sha256Hash: hash,
      mimeType: detectedMime,
      originalFilename: upload.name.slice(0, 255) || "upload",
      sizeBytes: bytes.byteLength,
      kind,
      metadataStripped: 0
    });

    await audit(db, actor.id, "file.uploaded", "file", id, request, {
      kind,
      mimeType: detectedMime,
      sizeBytes: bytes.byteLength
    });

    const [file] = await db.select().from(files).where(eq(files.id, id)).limit(1);
    if (!file) throw new HttpError(500, "File was not saved.");
    return json(fileResponseSchema.parse({ file: serializeFile(file) }), 201);
  }

  const fileMatch = pathname.match(/^\/files\/([^/]+)$/);
  if (fileMatch && request.method === "GET") {
    const actor = await requireUser(request, env);
    const fileId = fileMatch[1];
    if (!fileId) throw new HttpError(404, "File not found.");
    const db = getDb(env);
    const [file] = await db.select().from(files).where(and(eq(files.id, fileId), eq(files.ownerId, actor.id))).limit(1);
    if (!file) throw new HttpError(404, "File not found.");
    return json(fileResponseSchema.parse({ file: serializeFile(file) }));
  }

  return null;
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

function serializeFile(file: {
  id: string;
  ownerId: string;
  mimeType: string;
  originalFilename: string;
  sizeBytes: number;
  kind: string;
  metadataStripped: number;
  createdAt: Date;
}) {
  return {
    id: file.id,
    ownerId: file.ownerId,
    mimeType: file.mimeType,
    originalFilename: file.originalFilename,
    sizeBytes: file.sizeBytes,
    kind: file.kind,
    metadataStripped: file.metadataStripped !== 0,
    createdAt: file.createdAt.toISOString()
  };
}

function detectMime(bytes: Uint8Array, declaredType: string): AllowedMime | null {
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (matches(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (matchesAscii(bytes, 0, "RIFF") && matchesAscii(bytes, 8, "WEBP")) return "image/webp";
  if (matchesAscii(bytes, 0, "%PDF")) return "application/pdf";
  if (matches(bytes, [0x50, 0x4b, 0x03, 0x04]) && declaredType.includes("wordprocessingml")) {
    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  }
  return null;
}

function matches(bytes: Uint8Array, prefix: number[]) {
  return prefix.every((value, index) => bytes[index] === value);
}

function matchesAscii(bytes: Uint8Array, offset: number, value: string) {
  return [...value].every((char, index) => bytes[offset + index] === char.charCodeAt(0));
}

async function sha256Hex(bytes: Uint8Array) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer as ArrayBuffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getIpPrefix(request: Request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".");
  return ip.split(":").slice(0, 4).join(":");
}
