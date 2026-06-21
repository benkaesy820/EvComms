import { auditLogs, conversations, messages, users } from "@evbus/db";
import {
  conversationResponseSchema,
  conversationsResponseSchema,
  closeConversationRequestSchema,
  createMessageRequestSchema,
  createMessageResponseSchema,
  messagesResponseSchema,
  reassignConversationRequestSchema
} from "@evbus/shared";
import { and, desc, eq, ne, sql } from "drizzle-orm";
import { requireUser } from "./auth";
import { getDb } from "./db";
import { HttpError, json, readJson } from "./http";
import type { Env } from "./index";
import { enqueueNotification } from "./notifications";
import { getAppSettings } from "./settings";

export async function handleConversations(
  request: Request,
  env: Env,
  pathname: string,
  ctx?: ExecutionContext
) {
  if (pathname === "/realtime" && request.method === "GET") {
    const actor = await requireUser(request, env);
    const conversationId = new URL(request.url).searchParams.get("conversationId");
    const conversation = await requireConversationAccess(env, actor, conversationId ?? undefined);
    const room = env.REALTIME_ROOM.getByName(getConversationRoomName(conversation.id));
    return room.fetch(request);
  }

  if (pathname === "/conversations/me" && request.method === "GET") {
    const actor = await requireUser(request, env);

    if (actor.role !== "customer") {
      throw new HttpError(403, "Customer access required.");
    }

    const conversation = await getOrCreateCustomerConversation(env, actor.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(conversation) }));
  }

  if (pathname === "/admin/conversations" && request.method === "GET") {
    const actor = await requireUser(request, env);

    if (actor.role !== "super_admin" && actor.role !== "agent") {
      throw new HttpError(403, "Agent access required.");
    }

    const db = getDb(env);
    let query = db
      .select({
        id: conversations.id,
        customerId: conversations.customerId,
        assignedAgentId: conversations.assignedAgentId,
        status: conversations.status,
        lastMessageAt: conversations.lastMessageAt,
        lastMessagePreview: conversations.lastMessagePreview,
        closedAt: conversations.closedAt,
        closedBy: conversations.closedBy,
        closingNote: conversations.closingNote,
        createdAt: conversations.createdAt,
        updatedAt: conversations.updatedAt,
        customerName: users.name,
        customerEmail: users.email
      })
      .from(conversations)
      .innerJoin(users, eq(conversations.customerId, users.id))
      .$dynamic();

    if (actor.role === "agent") {
      query = query.where(eq(conversations.assignedAgentId, actor.id));
    }

    const rows = await query.orderBy(desc(conversations.lastMessageAt), desc(conversations.createdAt)).limit(100);

    return json(
      conversationsResponseSchema.parse({
        conversations: rows.map((row) => ({
          ...serializeConversation(row),
          customerName: row.customerName,
          customerEmail: row.customerEmail,
          lastMessagePreview: row.lastMessagePreview
        }))
      })
    );
  }

  const messagesMatch = pathname.match(/^\/conversations\/([^/]+)\/messages$/);
  const reassignMatch = pathname.match(/^\/admin\/conversations\/([^/]+)\/reassign$/);
  if (reassignMatch && request.method === "POST") {
    const actor = await requireUser(request, env);

    if (actor.role !== "super_admin") {
      throw new HttpError(403, "Super Admin access required.");
    }

    const input = await readJson(request, reassignConversationRequestSchema);
    const conversation = await requireConversationAccess(env, actor, reassignMatch[1]);
    const db = getDb(env);

    if (input.agentId) {
      const [agent] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, input.agentId), eq(users.role, "agent"), eq(users.status, "approved")))
        .limit(1);

      if (!agent) {
        throw new HttpError(404, "Approved agent not found.");
      }
    }

    const now = new Date();
    await db
      .update(conversations)
      .set({ assignedAgentId: input.agentId, updatedAt: now })
      .where(eq(conversations.id, conversation.id));

    await audit(db, actor.id, "conversation.reassigned", "conversation", conversation.id, request, {
      agentId: input.agentId
    });

    await enqueueNotification(env, {
      recipientId: input.agentId,
      type: "conversation.reassigned",
      dedupeKey: `conversation-reassigned:${conversation.id}:${input.agentId ?? "unassigned"}:${now.getTime()}`,
      payload: {
        conversationId: conversation.id,
        customerId: conversation.customerId,
        assignedBy: actor.id
      }
    });

    const updated = await getConversationById(env, conversation.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(updated) }));
  }

  const closeMatch = pathname.match(/^\/conversations\/([^/]+)\/close$/);
  if (closeMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, closeMatch[1]);

    if (actor.role === "customer") {
      throw new HttpError(403, "Customers cannot close conversations.");
    }

    if (conversation.status === "closed") {
      throw new HttpError(409, "Conversation is already closed.");
    }

    const input = await readJson(request, closeConversationRequestSchema);
    const db = getDb(env);
    const now = new Date();

    await db
      .update(conversations)
      .set({
        status: "closed",
        closedAt: now,
        closedBy: actor.id,
        closingNote: input.note,
        updatedAt: now
      })
      .where(eq(conversations.id, conversation.id));

    await audit(db, actor.id, "conversation.closed", "conversation", conversation.id, request, {
      note: input.note
    });

    await enqueueNotification(env, {
      recipientId: conversation.customerId,
      type: "conversation.closed",
      dedupeKey: `conversation-closed:${conversation.id}:${now.getTime()}`,
      payload: {
        conversationId: conversation.id,
        closedBy: actor.id,
        note: input.note
      }
    });

    const updated = await getConversationById(env, conversation.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(updated) }));
  }

  const reopenMatch = pathname.match(/^\/conversations\/([^/]+)\/reopen$/);
  if (reopenMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, reopenMatch[1]);

    if (actor.role === "customer") {
      throw new HttpError(403, "Customers cannot reopen conversations.");
    }

    if (conversation.status === "open") {
      throw new HttpError(409, "Conversation is already open.");
    }

    const db = getDb(env);
    const now = new Date();

    await db
      .update(conversations)
      .set({
        status: "open",
        closedAt: null,
        closedBy: null,
        closingNote: null,
        updatedAt: now
      })
      .where(eq(conversations.id, conversation.id));

    await audit(db, actor.id, "conversation.reopened", "conversation", conversation.id, request);

    const updated = await getConversationById(env, conversation.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(updated) }));
  }

  if (messagesMatch && request.method === "GET") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, messagesMatch[1]);
    const db = getDb(env);
    const rows = await db
      .select({
        id: messages.id,
        conversationId: messages.conversationId,
        senderId: messages.senderId,
        senderName: users.name,
        senderRole: users.role,
        body: messages.body,
        createdAt: messages.createdAt
      })
      .from(messages)
      .innerJoin(users, eq(messages.senderId, users.id))
      .where(eq(messages.conversationId, conversation.id))
      .orderBy(desc(messages.createdAt))
      .limit(200);

    return json(messagesResponseSchema.parse({ messages: rows.reverse().map(serializeMessage) }));
  }

  if (messagesMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, messagesMatch[1]);
    if (conversation.status === "closed") {
      throw new HttpError(409, "Conversation is closed. Reopen it before sending a message.");
    }
    const input = await readJson(request, createMessageRequestSchema);
    const db = getDb(env);
    const messageId = crypto.randomUUID();
    const now = new Date();

    await db.insert(messages).values({
      id: messageId,
      conversationId: conversation.id,
      senderId: actor.id,
      body: input.body,
      createdAt: now
    });

    await db
      .update(conversations)
      .set({ lastMessageAt: now, lastMessagePreview: input.body.slice(0, 180), updatedAt: now })
      .where(eq(conversations.id, conversation.id));

    await audit(db, actor.id, "conversation.message.created", "message", messageId, request, {
      conversationId: conversation.id
    });

    const [message] = await db
      .select({
        id: messages.id,
        conversationId: messages.conversationId,
        senderId: messages.senderId,
        senderName: users.name,
        senderRole: users.role,
        body: messages.body,
        createdAt: messages.createdAt
      })
      .from(messages)
      .innerJoin(users, eq(messages.senderId, users.id))
      .where(eq(messages.id, messageId))
      .limit(1);

    if (!message) {
      throw new HttpError(500, "Message was not saved.");
    }

    const serializedMessage = serializeMessage(message);
    const notifications = enqueueMessageNotifications(env, conversation, actor.id, serializedMessage).catch(
      (error) => {
        console.error(error);
      }
    );
    if (ctx) {
      ctx.waitUntil(notifications);
    } else {
      await notifications;
    }

    await broadcastConversationEvent(env, conversation.id, {
      type: "message.created",
      message: serializedMessage
    });

    return json(createMessageResponseSchema.parse({ message: serializedMessage }), 201);
  }

  return null;
}

async function enqueueMessageNotifications(
  env: Env,
  conversation: {
    id: string;
    customerId: string;
    assignedAgentId: string | null;
  },
  senderId: string,
  message: ReturnType<typeof serializeMessage>
) {
  const recipientIds = new Set<string>();
  const settings = await getAppSettings(env);

  if (senderId === conversation.customerId) {
    if (conversation.assignedAgentId) recipientIds.add(conversation.assignedAgentId);
  } else {
    recipientIds.add(conversation.customerId);
  }

  for (const recipientId of recipientIds) {
    const debounceMs = settings.emailNotificationDebounceMinutes * 60_000;
    const dedupeBucket = Math.floor(Date.now() / debounceMs);
    await enqueueNotification(env, {
      recipientId,
      type: "conversation.message",
      dedupeKey: `conversation-message:${conversation.id}:recipient:${recipientId}:bucket:${dedupeBucket}`,
      nextAttemptAt: new Date(Date.now() + settings.emailNotificationDebounceMinutes * 60_000),
      payload: {
        conversationId: conversation.id,
        messageId: message.id,
        senderId,
        count: 1,
        preview: message.body.slice(0, 160)
      }
    });
  }
}

async function getConversationById(env: Env, conversationId: string) {
  const db = getDb(env);
  const [conversation] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, conversationId))
    .limit(1);

  if (!conversation) {
    throw new HttpError(404, "Conversation not found.");
  }

  return conversation;
}

function getConversationRoomName(conversationId: string) {
  return `conversation:${conversationId}`;
}

async function broadcastConversationEvent(env: Env, conversationId: string, event: unknown) {
  const room = env.REALTIME_ROOM.getByName(getConversationRoomName(conversationId));
  await room.broadcast(JSON.stringify(event));
}

async function getOrCreateCustomerConversation(env: Env, customerId: string) {
  const db = getDb(env);
  const [existing] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.customerId, customerId))
    .limit(1);

  if (existing) return existing;

  const id = crypto.randomUUID();
  const assignedAgentId = await chooseAgentForConversation(env);

  try {
    await db.insert(conversations).values({
      id,
      customerId,
      assignedAgentId,
      status: "open"
    });
  } catch (error) {
    if (!(error instanceof Error) || !/Duplicate entry|1062/.test(error.message)) throw error;

    const [createdByConcurrentRequest] = await db
      .select()
      .from(conversations)
      .where(eq(conversations.customerId, customerId))
      .limit(1);

    if (createdByConcurrentRequest) return createdByConcurrentRequest;
    throw error;
  }

  const [created] = await db.select().from(conversations).where(eq(conversations.id, id)).limit(1);

  if (!created) {
    throw new HttpError(500, "Conversation was not created.");
  }

  return created;
}

export async function chooseAgentForConversation(env: Env, excludeAgentId?: string) {
  const db = getDb(env);
  const settings = await getAppSettings(env);
  const filters = [eq(users.role, "agent"), eq(users.status, "approved")];
  if (excludeAgentId) filters.push(ne(users.id, excludeAgentId));

  const approvedAgents = await db
    .select({
      id: users.id,
      activeConversationCount: sql<number>`COUNT(conversations.id)`
    })
    .from(users)
    .leftJoin(
      conversations,
      and(eq(conversations.assignedAgentId, users.id), eq(conversations.status, "open"))
    )
    .where(and(...filters))
    .groupBy(users.id)
    .having(sql`COUNT(conversations.id) < ${settings.maxActiveConversationsPerAgent}`)
    .orderBy(sql`COUNT(conversations.id)`, users.createdAt)
    .limit(1);

  return approvedAgents[0]?.id ?? null;
}

async function requireConversationAccess(
  env: Env,
  actor: Awaited<ReturnType<typeof requireUser>>,
  conversationId: string | undefined
) {
  if (!conversationId) {
    throw new HttpError(404, "Conversation not found.");
  }

  const db = getDb(env);
  const [conversation] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, conversationId))
    .limit(1);

  if (!conversation) {
    throw new HttpError(404, "Conversation not found.");
  }

  if (actor.role === "customer" && conversation.customerId !== actor.id) {
    throw new HttpError(403, "You cannot access this conversation.");
  }

  if (actor.role === "agent" && conversation.assignedAgentId !== actor.id) {
    throw new HttpError(403, "Conversation is not assigned to you.");
  }

  return conversation;
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

function serializeConversation(conversation: {
  id: string;
  customerId: string;
  assignedAgentId: string | null;
  status: string;
  lastMessageAt: Date | null;
  lastMessagePreview?: string | null;
  closedAt: Date | null;
  closedBy: string | null;
  closingNote: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: conversation.id,
    customerId: conversation.customerId,
    assignedAgentId: conversation.assignedAgentId,
    status: conversation.status,
    lastMessageAt: conversation.lastMessageAt?.toISOString() ?? null,
    closedAt: conversation.closedAt?.toISOString() ?? null,
    closedBy: conversation.closedBy,
    closingNote: conversation.closingNote,
    createdAt: conversation.createdAt.toISOString(),
    updatedAt: conversation.updatedAt.toISOString()
  };
}

function serializeMessage(message: {
  id: string;
  conversationId: string;
  senderId: string;
  senderName: string;
  senderRole: string;
  body: string;
  createdAt: Date;
}) {
  return {
    id: message.id,
    conversationId: message.conversationId,
    senderId: message.senderId,
    senderName: message.senderName,
    senderRole: message.senderRole,
    body: message.body,
    createdAt: message.createdAt.toISOString()
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
