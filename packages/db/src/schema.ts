import {
  index,
  int,
  json,
  mysqlTable,
  text,
  timestamp,
  uniqueIndex,
  varchar
} from "drizzle-orm/mysql-core";

export const users = mysqlTable(
  "users",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    role: varchar("role", { length: 32 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    email: varchar("email", { length: 320 }).notNull(),
    phone: varchar("phone", { length: 32 }),
    passwordHash: varchar("password_hash", { length: 255 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    registrationNote: text("registration_note"),
    emailNotificationsEnabled: int("email_notifications_enabled").notNull().default(1),
    pushNotificationsEnabled: int("push_notifications_enabled").notNull().default(1),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [uniqueIndex("users_email_unique").on(table.email)]
);

export const sessions = mysqlTable(
  "sessions",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    tokenHash: varchar("token_hash", { length: 64 }).notNull(),
    userAgent: varchar("user_agent", { length: 512 }),
    ipPrefix: varchar("ip_prefix", { length: 64 }),
    expiresAt: timestamp("expires_at").notNull(),
    revokedAt: timestamp("revoked_at"),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("sessions_token_hash_unique").on(table.tokenHash),
    index("sessions_user_id_idx").on(table.userId)
  ]
);

export const passwordResetTokens = mysqlTable(
  "password_reset_tokens",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    tokenHash: varchar("token_hash", { length: 64 }).notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    usedAt: timestamp("used_at"),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("password_reset_tokens_hash_unique").on(table.tokenHash),
    index("password_reset_tokens_user_id_idx").on(table.userId)
  ]
);

export const authRateLimits = mysqlTable(
  "auth_rate_limits",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    scope: varchar("scope", { length: 32 }).notNull(),
    identifierHash: varchar("identifier_hash", { length: 64 }).notNull(),
    attempts: int("attempts").notNull().default(0),
    lockedUntil: timestamp("locked_until"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("auth_rate_limits_scope_identifier_unique").on(table.scope, table.identifierHash),
    index("auth_rate_limits_locked_until_idx").on(table.lockedUntil)
  ]
);

export const auditLogs = mysqlTable(
  "audit_logs",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    actorId: varchar("actor_id", { length: 36 }),
    action: varchar("action", { length: 96 }).notNull(),
    targetType: varchar("target_type", { length: 64 }).notNull(),
    targetId: varchar("target_id", { length: 64 }),
    metadata: json("metadata"),
    ipPrefix: varchar("ip_prefix", { length: 64 }),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    index("audit_logs_actor_id_idx").on(table.actorId),
    index("audit_logs_action_idx").on(table.action),
    index("audit_logs_target_idx").on(table.targetType, table.targetId),
    index("audit_logs_created_at_idx").on(table.createdAt)
  ]
);

export const conversations = mysqlTable(
  "conversations",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    customerId: varchar("customer_id", { length: 36 }).notNull(),
    assignedAgentId: varchar("assigned_agent_id", { length: 36 }),
    departmentId: varchar("department_id", { length: 36 }),
    status: varchar("status", { length: 32 }).notNull(),
    lastMessageAt: timestamp("last_message_at"),
    lastCustomerMessageAt: timestamp("last_customer_message_at"),
    lastAgentMessageAt: timestamp("last_agent_message_at"),
    lastMessagePreview: varchar("last_message_preview", { length: 180 }),
    customerUnreadCount: int("customer_unread_count").notNull().default(0),
    agentUnreadCount: int("agent_unread_count").notNull().default(0),
    closedAt: timestamp("closed_at"),
    closedBy: varchar("closed_by", { length: 36 }),
    closingNote: text("closing_note"),
    registrationNote: text("registration_note"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("conversations_customer_id_unique").on(table.customerId),
    index("conversations_assigned_agent_id_idx").on(table.assignedAgentId),
    index("conversations_department_id_idx").on(table.departmentId),
    index("conversations_status_last_message_idx").on(table.status, table.lastMessageAt),
    index("conversations_waiting_idx").on(table.status, table.lastCustomerMessageAt, table.lastAgentMessageAt)
  ]
);

export const messages = mysqlTable(
  "messages",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    conversationId: varchar("conversation_id", { length: 36 }).notNull(),
    senderId: varchar("sender_id", { length: 36 }).notNull(),
    body: text("body").notNull(),
    readAt: timestamp("read_at"),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    index("messages_conversation_created_idx").on(table.conversationId, table.createdAt),
    index("messages_sender_id_idx").on(table.senderId)
  ]
);

export const files = mysqlTable(
  "files",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    ownerId: varchar("owner_id", { length: 36 }).notNull(),
    storageKey: varchar("storage_key", { length: 512 }).notNull(),
    sha256Hash: varchar("sha256_hash", { length: 64 }).notNull(),
    mimeType: varchar("mime_type", { length: 128 }).notNull(),
    originalFilename: varchar("original_filename", { length: 255 }).notNull(),
    sizeBytes: int("size_bytes").notNull(),
    kind: varchar("kind", { length: 32 }).notNull(),
    metadataStripped: int("metadata_stripped").notNull().default(0),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("files_sha256_hash_unique").on(table.sha256Hash),
    index("files_owner_id_idx").on(table.ownerId),
    index("files_storage_key_idx").on(table.storageKey)
  ]
);

export const messageAttachments = mysqlTable(
  "message_attachments",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    messageId: varchar("message_id", { length: 36 }).notNull(),
    fileId: varchar("file_id", { length: 36 }).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("message_attachments_message_file_unique").on(table.messageId, table.fileId),
    index("message_attachments_message_id_idx").on(table.messageId),
    index("message_attachments_file_id_idx").on(table.fileId)
  ]
);

export const settings = mysqlTable("settings", {
  key: varchar("setting_key", { length: 96 }).primaryKey(),
  value: json("value_json").notNull(),
  updatedBy: varchar("updated_by", { length: 36 }),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});

export const departments = mysqlTable(
  "departments",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    name: varchar("name", { length: 80 }).notNull(),
    active: int("active").notNull().default(1),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [uniqueIndex("departments_name_unique").on(table.name)]
);

export const agentDepartments = mysqlTable(
  "agent_departments",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    agentId: varchar("agent_id", { length: 36 }).notNull(),
    departmentId: varchar("department_id", { length: 36 }).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("agent_departments_agent_department_unique").on(table.agentId, table.departmentId),
    index("agent_departments_agent_id_idx").on(table.agentId),
    index("agent_departments_department_id_idx").on(table.departmentId)
  ]
);

export const reports = mysqlTable(
  "reports",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    customerId: varchar("customer_id", { length: 36 }).notNull(),
    conversationId: varchar("conversation_id", { length: 36 }),
    departmentId: varchar("department_id", { length: 36 }),
    title: varchar("title", { length: 160 }).notNull(),
    body: text("body").notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    source: varchar("source", { length: 32 }).notNull(),
    resolvedBy: varchar("resolved_by", { length: 36 }),
    resolvedAt: timestamp("resolved_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    index("reports_customer_id_idx").on(table.customerId),
    index("reports_conversation_id_idx").on(table.conversationId),
    index("reports_department_id_idx").on(table.departmentId),
    index("reports_status_created_idx").on(table.status, table.createdAt)
  ]
);

export const pushSubscriptions = mysqlTable(
  "push_subscriptions",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    endpoint: varchar("endpoint", { length: 2048 }).notNull(),
    endpointHash: varchar("endpoint_hash", { length: 64 }).notNull(),
    p256dh: varchar("p256dh", { length: 512 }).notNull(),
    auth: varchar("auth", { length: 512 }).notNull(),
    userAgent: varchar("user_agent", { length: 512 }),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("push_subscriptions_endpoint_hash_unique").on(table.endpointHash),
    index("push_subscriptions_user_id_idx").on(table.userId)
  ]
);

export const announcements = mysqlTable(
  "announcements",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    authorId: varchar("author_id", { length: 36 }).notNull(),
    audience: varchar("audience", { length: 32 }).notNull(),
    title: varchar("title", { length: 160 }).notNull(),
    body: text("body").notNull(),
    imageFileId: varchar("image_file_id", { length: 36 }),
    showPublic: int("show_public").notNull().default(0),
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    index("announcements_audience_created_idx").on(table.audience, table.createdAt),
    index("announcements_expires_at_idx").on(table.expiresAt),
    index("announcements_author_id_idx").on(table.authorId)
  ]
);

export const announcementReactions = mysqlTable(
  "announcement_reactions",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    announcementId: varchar("announcement_id", { length: 36 }).notNull(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    reaction: varchar("reaction", { length: 32 }).notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("announcement_reactions_announcement_user_unique").on(table.announcementId, table.userId),
    index("announcement_reactions_user_id_idx").on(table.userId)
  ]
);

export const announcementComments = mysqlTable(
  "announcement_comments",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    announcementId: varchar("announcement_id", { length: 36 }).notNull(),
    userId: varchar("user_id", { length: 36 }).notNull(),
    body: text("body").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    index("announcement_comments_announcement_created_idx").on(table.announcementId, table.createdAt),
    index("announcement_comments_user_id_idx").on(table.userId)
  ]
);

export const notificationJobs = mysqlTable(
  "notification_jobs",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    recipientId: varchar("recipient_id", { length: 36 }).notNull(),
    channel: varchar("channel", { length: 32 }).notNull(),
    type: varchar("type", { length: 96 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    dedupeKey: varchar("dedupe_key", { length: 255 }),
    payload: json("payload").notNull(),
    attempts: int("attempts").notNull().default(0),
    nextAttemptAt: timestamp("next_attempt_at").defaultNow().notNull(),
    sentAt: timestamp("sent_at"),
    provider: varchar("provider", { length: 32 }),
    lastError: text("last_error"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("notification_jobs_dedupe_key_unique").on(table.dedupeKey),
    index("notification_jobs_status_next_attempt_idx").on(table.status, table.nextAttemptAt),
    index("notification_jobs_recipient_id_idx").on(table.recipientId)
  ]
);
