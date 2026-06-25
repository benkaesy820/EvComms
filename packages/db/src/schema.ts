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
  (table) => [index("audit_logs_actor_id_idx").on(table.actorId)]
);

export const conversations = mysqlTable(
  "conversations",
  {
    id: varchar("id", { length: 36 }).primaryKey(),
    customerId: varchar("customer_id", { length: 36 }).notNull(),
    assignedAgentId: varchar("assigned_agent_id", { length: 36 }),
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
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull()
  },
  (table) => [
    uniqueIndex("conversations_customer_id_unique").on(table.customerId),
    index("conversations_assigned_agent_id_idx").on(table.assignedAgentId),
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
    createdAt: timestamp("created_at").defaultNow().notNull()
  },
  (table) => [
    index("messages_conversation_created_idx").on(table.conversationId, table.createdAt),
    index("messages_sender_id_idx").on(table.senderId)
  ]
);

export const settings = mysqlTable("settings", {
  key: varchar("setting_key", { length: 96 }).primaryKey(),
  value: json("value_json").notNull(),
  updatedBy: varchar("updated_by", { length: 36 }),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});

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
