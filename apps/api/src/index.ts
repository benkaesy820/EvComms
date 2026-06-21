import { appConfig, healthResponseSchema } from "@evbus/shared";
import { handleAdmin } from "./admin";
import { handleAuth } from "./auth";
import { handleConversations } from "./conversations";
import { HttpError, json, notFound } from "./http";
import { processNotificationJobs } from "./notifications";
import { handleSettings } from "./settings";
import { RealtimeRoom } from "./realtime-room";

export { RealtimeRoom };

export interface Env {
  APP_ENV: string;
  TIDB_DATABASE_URL?: string;
  BREVO_API_KEY?: string;
  EMAIL_FROM?: string;
  EMAIL_FROM_NAME?: string;
  SMTP_USER?: string;
  REALTIME_ROOM: DurableObjectNamespace<RealtimeRoom>;
}

const allowedOrigins = new Set(["http://localhost:5173", "http://127.0.0.1:5173"]);
const baseCorsHeaders = {
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS"
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      if (request.method === "OPTIONS") {
        return withCors(new Response(null), request);
      }

      const url = new URL(request.url);

      if (url.pathname === "/health" && request.method === "GET") {
        return withCors(
          json(
            healthResponseSchema.parse({
              ok: true,
              service: appConfig.siteName,
              environment: env.APP_ENV,
              time: new Date().toISOString()
            })
          ),
          request
        );
      }

      const authResponse = await handleAuth(request, env, url.pathname, ctx);
      if (authResponse) return withCors(authResponse, request);

      const adminResponse = await handleAdmin(request, env, url.pathname);
      if (adminResponse) return withCors(adminResponse, request);

      const settingsResponse = await handleSettings(request, env, url.pathname);
      if (settingsResponse) return withCors(settingsResponse, request);

      const conversationResponse = await handleConversations(request, env, url.pathname, ctx);
      if (conversationResponse) return withCors(conversationResponse, request);

      return withCors(notFound(), request);
    } catch (error) {
      if (error instanceof HttpError) {
        return withCors(json({ error: error.message }, error.status), request);
      }

      console.error(error);
      return withCors(json({ error: "Internal server error." }, 500), request);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(processNotificationJobs(env, { dryRun: false, limit: 25 }));
  }
};

function withCors(response: Response, request: Request) {
  if (response.status === 101) {
    return response;
  }

  const next = new Response(response.body, response);
  const origin = request.headers.get("Origin");

  for (const [key, value] of Object.entries(baseCorsHeaders)) {
    next.headers.set(key, value);
  }
  if (origin && allowedOrigins.has(origin)) {
    next.headers.set("Access-Control-Allow-Origin", origin);
    next.headers.append("Vary", "Origin");
  }

  return next;
}
