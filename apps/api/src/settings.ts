import { auditLogs, settings } from "@evbus/db";
import {
  appConfig,
  appSettingsSchema,
  settingsResponseSchema,
  updateSettingsRequestSchema
} from "@evbus/shared";
import { eq } from "drizzle-orm";
import { requireUser } from "./auth";
import { getDb } from "./db";
import { HttpError, json, readJson } from "./http";
import type { Env } from "./index";

const settingsKey = "app";
const settingsCacheMs = 30_000;

export const defaultSettings = appSettingsSchema.parse({
  siteName: appConfig.siteName,
  companyName: appConfig.companyName,
  tagline: appConfig.tagline,
  supportEmail: "ev@gmail.com",
  maxActiveConversationsPerAgent: 20,
  emailNotificationDebounceMinutes: 5
});
type AppSettings = typeof defaultSettings;
let cachedSettings: { value: AppSettings; expiresAt: number } | null = null;
let settingsLoad: Promise<AppSettings> | null = null;

export async function handleSettings(request: Request, env: Env, pathname: string) {
  if (pathname === "/settings" && request.method === "GET") {
    return json(settingsResponseSchema.parse({ settings: await getAppSettings(env) }));
  }

  if (pathname === "/admin/settings" && request.method === "PUT") {
    const actor = await requireUser(request, env);
    if (actor.role !== "super_admin") {
      throw new HttpError(403, "Super Admin access required.");
    }

    const input = await readJson(request, updateSettingsRequestSchema);
    const nextSettings = { ...(await getAppSettings(env)), ...input };
    const parsed = appSettingsSchema.parse(nextSettings);
    const db = getDb(env);

    await db
      .insert(settings)
      .values({
        key: settingsKey,
        value: parsed,
        updatedBy: actor.id,
        updatedAt: new Date()
      })
      .onDuplicateKeyUpdate({
        set: {
          value: parsed,
          updatedBy: actor.id,
          updatedAt: new Date()
        }
      });

    cachedSettings = { value: parsed, expiresAt: Date.now() + settingsCacheMs };
    await db.insert(auditLogs).values({
      id: crypto.randomUUID(),
      actorId: actor.id,
      action: "settings.updated",
      targetType: "settings",
      targetId: settingsKey,
      metadata: input,
      ipPrefix: getIpPrefix(request)
    });

    return json(settingsResponseSchema.parse({ settings: parsed }));
  }

  return null;
}

export async function getAppSettings(env: Env) {
  const now = Date.now();
  if (cachedSettings && cachedSettings.expiresAt > now) return cachedSettings.value;
  if (settingsLoad) return settingsLoad;

  settingsLoad = (async () => {
    const db = getDb(env);
    const [row] = await db
      .select({ value: settings.value })
      .from(settings)
      .where(eq(settings.key, settingsKey))
      .limit(1);

    const value = row ? appSettingsSchema.parse({ ...defaultSettings, ...asRecord(row.value) }) : defaultSettings;
    cachedSettings = { value, expiresAt: Date.now() + settingsCacheMs };
    return value;
  })().finally(() => {
    settingsLoad = null;
  });

  return settingsLoad;
}

function asRecord(value: unknown) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : {};
}

function getIpPrefix(request: Request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;

  if (ip.includes(".")) {
    return ip.split(".").slice(0, 3).join(".");
  }

  return ip.split(":").slice(0, 4).join(":");
}
