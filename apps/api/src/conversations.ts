import { agentDepartments, auditLogs, conversations, files, messageAttachments, messages, reports, users } from "@evbus/db";
import {
  conversationListQuerySchema,
  conversationResponseSchema,
  conversationsResponseSchema,
  closeConversationRequestSchema,
  createMessageRequestSchema,
  createMessageResponseSchema,
  messageListQuerySchema,
  messagesResponseSchema,
  reassignConversationRequestSchema
} from "@evbus/shared";
import { and, desc, eq, inArray, like, lt, ne, or, sql } from "drizzle-orm";
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
        departmentId: conversations.departmentId,
        status: conversations.status,
        lastMessageAt: conversations.lastMessageAt,
        lastCustomerMessageAt: conversations.lastCustomerMessageAt,
        lastAgentMessageAt: conversations.lastAgentMessageAt,
        lastMessagePreview: conversations.lastMessagePreview,
        customerUnreadCount: conversations.customerUnreadCount,
        agentUnreadCount: conversations.agentUnreadCount,
        closedAt: conversations.closedAt,
        closedBy: conversations.closedBy,
        closingNote: conversations.closingNote,
        registrationNote: conversations.registrationNote,
        createdAt: conversations.createdAt,
        updatedAt: conversations.updatedAt,
        customerName: users.name,
        customerEmail: users.email
      })
      .from(conversations)
      .innerJoin(users, eq(conversations.customerId, users.id))
      .$dynamic();

    const filters = [];
    const listQuery = conversationListQuerySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
    if (listQuery.status) filters.push(eq(conversations.status, listQuery.status));
    if (listQuery.assigned === "unassigned") filters.push(sql`${conversations.assignedAgentId} IS NULL`);
    if (listQuery.search) {
      const term = `%${listQuery.search}%`;
      filters.push(or(like(users.name, term), like(users.email, term)));
    }
    if (listQuery.cursor) filters.push(lt(conversations.updatedAt, new Date(listQuery.cursor)));
    if (listQuery.waiting === "true") {
      filters.push(sql`${conversations.status} = 'open'
        AND ${conversations.lastCustomerMessageAt} IS NOT NULL
        AND (${conversations.lastAgentMessageAt} IS NULL OR ${conversations.lastCustomerMessageAt} > ${conversations.lastAgentMessageAt})`);
    }
    if (listQuery.waiting === "false") {
      filters.push(sql`NOT (${conversations.status} = 'open'
        AND ${conversations.lastCustomerMessageAt} IS NOT NULL
        AND (${conversations.lastAgentMessageAt} IS NULL OR ${conversations.lastCustomerMessageAt} > ${conversations.lastAgentMessageAt}))`);
    }

    if (actor.role === "agent") {
      filters.push(eq(conversations.assignedAgentId, actor.id));
    } else if (listQuery.assigned === "mine") {
      filters.push(eq(conversations.assignedAgentId, actor.id));
    }

    if (filters.length) {
      query = query.where(and(...filters));
    }

    const waitingRank = sql`CASE WHEN ${conversations.status} = 'open'
      AND ${conversations.lastCustomerMessageAt} IS NOT NULL
      AND (${conversations.lastAgentMessageAt} IS NULL OR ${conversations.lastCustomerMessageAt} > ${conversations.lastAgentMessageAt})
      THEN 0 ELSE 1 END`;
    const waitingSince = sql`CASE WHEN ${conversations.status} = 'open'
      AND ${conversations.lastCustomerMessageAt} IS NOT NULL
      AND (${conversations.lastAgentMessageAt} IS NULL OR ${conversations.lastCustomerMessageAt} > ${conversations.lastAgentMessageAt})
      THEN ${conversations.lastCustomerMessageAt} ELSE NULL END`;
    const rows = await query
      .orderBy(waitingRank, waitingSince, desc(conversations.lastMessageAt), desc(conversations.createdAt))
      .limit(listQuery.limit);

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

    await broadcastConversationEvent(env, conversation.id, {
      type: "conversation.assigned",
      conversationId: conversation.id,
      assignedAgentId: input.agentId
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

    await broadcastConversationEvent(env, conversation.id, {
      type: "conversation.closed",
      conversationId: conversation.id,
      closedBy: actor.id,
      closingNote: input.note
    });

    const updated = await getConversationById(env, conversation.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(updated) }));
  }

  const reopenMatch = pathname.match(/^\/conversations\/([^/]+)\/reopen$/);
  if (reopenMatch && request.method === "POST") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, reopenMatch[1]);

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

    await broadcastConversationEvent(env, conversation.id, {
      type: "conversation.reopened",
      conversationId: conversation.id,
      reopenedBy: actor.id
    });

    const updated = await getConversationById(env, conversation.id);
    return json(conversationResponseSchema.parse({ conversation: serializeConversation(updated) }));
  }

  if (messagesMatch && request.method === "GET") {
    const actor = await requireUser(request, env);
    const conversation = await requireConversationAccess(env, actor, messagesMatch[1]);
    const db = getDb(env);
    const listQuery = messageListQuerySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
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
      .where(
        listQuery.before
          ? and(eq(messages.conversationId, conversation.id), lt(messages.createdAt, new Date(listQuery.before)))
          : eq(messages.conversationId, conversation.id)
      )
      .orderBy(desc(messages.createdAt))
      .limit(listQuery.limit);

    const orderedRows = rows.reverse();
    const attachmentsByMessageId = await getMessageAttachments(
      db,
      orderedRows.map((message) => message.id)
    );

    await markConversationRead(db, actor.role, conversation);
    await broadcastConversationEvent(env, conversation.id, {
      type: "conversation.read",
      conversationId: conversation.id,
      readerRole: actor.role
    });

    return json(
      messagesResponseSchema.parse({
        messages: orderedRows.map((message) =>
          serializeMessage(message, attachmentsByMessageId.get(message.id) ?? [])
        )
      })
    );
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
    const body = input.body ?? "";
    const attachmentIds = [...new Set(input.attachmentIds ?? [])];
    const attachedFiles = await getOwnedFiles(db, actor.id, attachmentIds);
    if (attachedFiles.length !== attachmentIds.length) {
      throw new HttpError(400, "One or more attachments are invalid.");
    }
    const attachedFilesById = new Map(attachedFiles.map((file) => [file.id, file]));
    const serializedAttachments = attachmentIds.map((fileId) => serializeFile(attachedFilesById.get(fileId)!));
    const preview = body || `${attachmentIds.length} attachment${attachmentIds.length === 1 ? "" : "s"}`;

    await db.insert(messages).values({
      id: messageId,
      conversationId: conversation.id,
      senderId: actor.id,
      body,
      createdAt: now
    });

    const isCustomerMessage = actor.role === "customer";
    const nextAssignedAgentId =
      isCustomerMessage && !conversation.assignedAgentId
        ? await chooseAgentForConversation(env, undefined, conversation.departmentId)
        : conversation.assignedAgentId;

    await db
      .update(conversations)
      .set({
        assignedAgentId: nextAssignedAgentId,
        lastMessageAt: now,
        lastCustomerMessageAt: isCustomerMessage ? now : conversation.lastCustomerMessageAt,
        lastAgentMessageAt: isCustomerMessage ? conversation.lastAgentMessageAt : now,
        lastMessagePreview: preview.slice(0, 180),
        customerUnreadCount: isCustomerMessage ? conversation.customerUnreadCount : sql`${conversations.customerUnreadCount} + 1`,
        agentUnreadCount: isCustomerMessage ? sql`${conversations.agentUnreadCount} + 1` : 0,
        updatedAt: now
      })
      .where(eq(conversations.id, conversation.id));
    if (attachmentIds.length) {
      await db.insert(messageAttachments).values(
        attachmentIds.map((fileId) => ({
          id: crypto.randomUUID(),
          messageId,
          fileId
        }))
      );
    }

    await audit(db, actor.id, "conversation.message.created", "message", messageId, request, {
      conversationId: conversation.id,
      attachmentCount: attachmentIds.length
    });

    if (isCustomerMessage && !conversation.assignedAgentId) {
      await audit(
        db,
        actor.id,
        nextAssignedAgentId ? "conversation.auto_assigned" : "conversation.assignment_queued",
        "conversation",
        conversation.id,
        request,
        { assignedAgentId: nextAssignedAgentId }
      );
      await broadcastConversationEvent(env, conversation.id, {
        type: "conversation.assigned",
        conversationId: conversation.id,
        assignedAgentId: nextAssignedAgentId
      });
    }

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

    const serializedMessage = serializeMessage(message, serializedAttachments);
    const notifications = enqueueMessageNotifications(
      env,
      { ...conversation, assignedAgentId: nextAssignedAgentId },
      actor.id,
      serializedMessage
    ).catch(
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

export async function getOrCreateCustomerConversation(env: Env, customerId: string) {
  const db = getDb(env);
  const [existing] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.customerId, customerId))
    .limit(1);

  const [customer] = await db
    .select({ registrationNote: users.registrationNote })
    .from(users)
    .where(eq(users.id, customerId))
    .limit(1);

  if (existing) {
    if (!existing.registrationNote && customer?.registrationNote) {
      await db
        .update(conversations)
        .set({ registrationNote: customer.registrationNote, updatedAt: new Date() })
        .where(eq(conversations.id, existing.id));
      await linkRegistrationReports(db, customerId, existing.id);
      return { ...existing, registrationNote: customer.registrationNote };
    }
    await linkRegistrationReports(db, customerId, existing.id);
    return existing;
  }

  const id = crypto.randomUUID();

  try {
    await db.insert(conversations).values({
      id,
      customerId,
      assignedAgentId: null,
      departmentId: null,
      registrationNote: customer?.registrationNote ?? null,
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
  await linkRegistrationReports(db, customerId, created.id);

  return created;
}

async function linkRegistrationReports(db: ReturnType<typeof getDb>, customerId: string, conversationId: string) {
  await db
    .update(reports)
    .set({ conversationId, updatedAt: new Date() })
    .where(and(eq(reports.customerId, customerId), eq(reports.source, "registration"), sql`${reports.conversationId} IS NULL`));
}

export async function chooseAgentForConversation(env: Env, excludeAgentId?: string, departmentId?: string | null) {
  const db = getDb(env);
  const settings = await getAppSettings(env);
  const filters = [eq(users.role, "agent"), eq(users.status, "approved")];
  if (excludeAgentId) filters.push(ne(users.id, excludeAgentId));

  let approvedAgentQuery = db
    .select({
      id: users.id,
      activeConversationCount: sql<number>`COUNT(conversations.id)`
    })
    .from(users)
    .leftJoin(
      conversations,
      and(eq(conversations.assignedAgentId, users.id), eq(conversations.status, "open"))
    )
    .$dynamic();

  if (departmentId) {
    approvedAgentQuery = approvedAgentQuery.innerJoin(
      agentDepartments,
      and(eq(agentDepartments.agentId, users.id), eq(agentDepartments.departmentId, departmentId))
    );
  }

  const approvedAgents = await approvedAgentQuery
    .where(and(...filters))
    .groupBy(users.id)
    .having(sql`COUNT(conversations.id) < ${settings.maxActiveConversationsPerAgent}`)
    .orderBy(sql`COUNT(conversations.id)`, users.createdAt)
    .limit(1);

  if (approvedAgents[0]?.id) return approvedAgents[0].id;

  const superAdminFilters = [eq(users.role, "super_admin"), eq(users.status, "approved")];
  if (excludeAgentId) superAdminFilters.push(ne(users.id, excludeAgentId));
  const fallbackAdmins = await db
    .select({
      id: users.id,
      activeConversationCount: sql<number>`COUNT(conversations.id)`
    })
    .from(users)
    .leftJoin(
      conversations,
      and(eq(conversations.assignedAgentId, users.id), eq(conversations.status, "open"))
    )
    .where(and(...superAdminFilters))
    .groupBy(users.id)
    .orderBy(sql`COUNT(conversations.id)`, users.createdAt)
    .limit(1);

  return fallbackAdmins[0]?.id ?? null;
}

async function markConversationRead(
  db: ReturnType<typeof getDb>,
  actorRole: string,
  conversation: { id: string; customerUnreadCount: number; agentUnreadCount: number }
) {
  if (actorRole === "customer") {
    if (conversation.customerUnreadCount === 0) return;
    await db
      .update(conversations)
      .set({ customerUnreadCount: 0 })
      .where(eq(conversations.id, conversation.id));
    return;
  }

  if (conversation.agentUnreadCount === 0) return;
  await db
    .update(conversations)
    .set({ agentUnreadCount: 0 })
    .where(eq(conversations.id, conversation.id));
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

async function getOwnedFiles(db: ReturnType<typeof getDb>, ownerId: string, fileIds: string[]) {
  if (!fileIds.length) return [];

  return db
    .select({
      id: files.id,
      ownerId: files.ownerId,
      mimeType: files.mimeType,
      originalFilename: files.originalFilename,
      sizeBytes: files.sizeBytes,
      kind: files.kind,
      metadataStripped: files.metadataStripped,
      createdAt: files.createdAt
    })
    .from(files)
    .where(and(eq(files.ownerId, ownerId), inArray(files.id, fileIds)))
    .limit(fileIds.length);
}

async function getMessageAttachments(db: ReturnType<typeof getDb>, messageIds: string[]) {
  const attachments = new Map<string, ReturnType<typeof serializeFile>[]>();
  if (!messageIds.length) return attachments;

  const rows = await db
    .select({
      messageId: messageAttachments.messageId,
      id: files.id,
      ownerId: files.ownerId,
      mimeType: files.mimeType,
      originalFilename: files.originalFilename,
      sizeBytes: files.sizeBytes,
      kind: files.kind,
      metadataStripped: files.metadataStripped,
      createdAt: files.createdAt
    })
    .from(messageAttachments)
    .innerJoin(files, eq(messageAttachments.fileId, files.id))
    .where(inArray(messageAttachments.messageId, messageIds));

  for (const row of rows) {
    const list = attachments.get(row.messageId) ?? [];
    list.push(serializeFile(row));
    attachments.set(row.messageId, list);
  }

  return attachments;
}

function serializeConversation(conversation: {
  id: string;
  customerId: string;
  assignedAgentId: string | null;
  departmentId?: string | null;
  status: string;
  lastMessageAt: Date | null;
  lastCustomerMessageAt?: Date | null;
  lastAgentMessageAt?: Date | null;
  lastMessagePreview?: string | null;
  customerUnreadCount?: number;
  agentUnreadCount?: number;
  closedAt: Date | null;
  closedBy: string | null;
  closingNote: string | null;
  registrationNote?: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: conversation.id,
    customerId: conversation.customerId,
    assignedAgentId: conversation.assignedAgentId,
    departmentId: conversation.departmentId ?? null,
    status: conversation.status,
    lastMessageAt: conversation.lastMessageAt?.toISOString() ?? null,
    lastCustomerMessageAt: conversation.lastCustomerMessageAt?.toISOString() ?? null,
    lastAgentMessageAt: conversation.lastAgentMessageAt?.toISOString() ?? null,
    customerUnreadCount: conversation.customerUnreadCount ?? 0,
    agentUnreadCount: conversation.agentUnreadCount ?? 0,
    closedAt: conversation.closedAt?.toISOString() ?? null,
    closedBy: conversation.closedBy,
    closingNote: conversation.closingNote,
    registrationNote: conversation.registrationNote ?? null,
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
}, attachments: ReturnType<typeof serializeFile>[] = []) {
  return {
    id: message.id,
    conversationId: message.conversationId,
    senderId: message.senderId,
    senderName: message.senderName,
    senderRole: message.senderRole,
    body: message.body,
    attachments,
    createdAt: message.createdAt.toISOString()
  };
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

function getIpPrefix(request: Request) {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip) return null;

  if (ip.includes(".")) {
    return ip.split(".").slice(0, 3).join(".");
  }

  return ip.split(":").slice(0, 4).join(":");
}
