import { z } from "zod";

export const userRoleSchema = z.enum(["customer", "agent", "super_admin"]);

export const accountStatusSchema = z.enum([
  "pending",
  "approved",
  "rejected",
  "suspended"
]);

export const healthResponseSchema = z.object({
  ok: z.boolean(),
  service: z.string(),
  environment: z.string(),
  time: z.string().datetime()
});

export const publicUserSchema = z.object({
  id: z.string(),
  role: userRoleSchema,
  name: z.string(),
  email: z.string().email(),
  phone: z.string().nullable(),
  status: accountStatusSchema,
  registrationNote: z.string().nullable().optional()
});

export const registerRequestSchema = z.object({
  name: z.string().trim().min(2).max(160),
  email: z.string().trim().email().max(320),
  phone: z
    .string()
    .trim()
    .regex(/^(\+233|0)[235]\d{8}$/, "Enter a valid Ghana phone number."),
  registrationNote: z.string().trim().max(2000).optional(),
  password: z
    .string()
    .min(12)
    .max(128)
    .regex(/[A-Za-z]/, "Password must include a letter.")
    .regex(/\d/, "Password must include a number.")
    .regex(/[^A-Za-z0-9]/, "Password must include a symbol.")
});

export const loginRequestSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(128)
});

export const requestPasswordResetSchema = z.object({
  email: z.string().trim().email().max(320)
});

export const resetPasswordSchema = z.object({
  token: z.string().trim().min(32).max(256),
  password: registerRequestSchema.shape.password
});

export const authResponseSchema = z.object({
  user: publicUserSchema
});

export const accountPreferencesSchema = z.object({
  emailNotificationsEnabled: z.boolean()
});

export const accountPreferencesResponseSchema = z.object({
  preferences: accountPreferencesSchema
});

export const updateAccountPreferencesRequestSchema = accountPreferencesSchema.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one preference is required."
);

export const sessionSchema = z.object({
  id: z.string(),
  current: z.boolean(),
  userAgent: z.string().nullable(),
  ipPrefix: z.string().nullable(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime()
});

export const sessionsResponseSchema = z.object({
  sessions: z.array(sessionSchema)
});

export const pendingUsersResponseSchema = z.object({
  users: z.array(publicUserSchema)
});

export const rejectUserRequestSchema = z.object({
  reason: z.string().trim().max(500).optional()
});

export const createAgentRequestSchema = registerRequestSchema.omit({ registrationNote: true }).extend({
  phone: z
    .string()
    .trim()
    .regex(/^(\+233|0)[235]\d{8}$/, "Enter a valid Ghana phone number.")
    .optional()
});

export const usersResponseSchema = z.object({
  users: z.array(publicUserSchema)
});

export const conversationSchema = z.object({
  id: z.string(),
  customerId: z.string(),
  assignedAgentId: z.string().nullable(),
  status: z.enum(["open", "closed"]),
  lastMessageAt: z.string().datetime().nullable(),
  lastCustomerMessageAt: z.string().datetime().nullable(),
  lastAgentMessageAt: z.string().datetime().nullable(),
  customerUnreadCount: z.number().int().min(0),
  agentUnreadCount: z.number().int().min(0),
  closedAt: z.string().datetime().nullable(),
  closedBy: z.string().nullable(),
  closingNote: z.string().nullable(),
  registrationNote: z.string().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const messageSchema = z.object({
  id: z.string(),
  conversationId: z.string(),
  senderId: z.string(),
  senderName: z.string(),
  senderRole: userRoleSchema,
  body: z.string(),
  createdAt: z.string().datetime()
});

export const conversationSummarySchema = conversationSchema.extend({
  customerName: z.string(),
  customerEmail: z.string().email(),
  lastMessagePreview: z.string().nullable()
});

export const conversationResponseSchema = z.object({
  conversation: conversationSchema
});

export const conversationsResponseSchema = z.object({
  conversations: z.array(conversationSummarySchema)
});

export const messagesResponseSchema = z.object({
  messages: z.array(messageSchema)
});

export const createMessageRequestSchema = z.object({
  body: z.string().trim().min(1).max(5000)
});

export const createMessageResponseSchema = z.object({
  message: messageSchema
});

export const reassignConversationRequestSchema = z.object({
  agentId: z.string().min(1).nullable()
});

export const closeConversationRequestSchema = z.object({
  note: z.string().trim().min(1).max(1000)
});

export const realtimeEventSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("connected")
  }),
  z.object({
    type: z.literal("message.created"),
    message: messageSchema
  }),
  z.object({
    type: z.literal("conversation.assigned"),
    conversationId: z.string(),
    assignedAgentId: z.string().nullable()
  }),
  z.object({
    type: z.literal("conversation.closed"),
    conversationId: z.string(),
    closedBy: z.string(),
    closingNote: z.string()
  }),
  z.object({
    type: z.literal("conversation.reopened"),
    conversationId: z.string(),
    reopenedBy: z.string()
  }),
  z.object({
    type: z.literal("conversation.read"),
    conversationId: z.string(),
    readerRole: userRoleSchema
  }),
  z.object({
    type: z.literal("settings.updated")
  })
]);

export const notificationJobSchema = z.object({
  id: z.string(),
  recipientId: z.string(),
  recipientEmail: z.string().email().nullable(),
  channel: z.string(),
  type: z.string(),
  status: z.string(),
  dedupeKey: z.string().nullable(),
  attempts: z.number(),
  nextAttemptAt: z.string().datetime(),
  sentAt: z.string().datetime().nullable(),
  provider: z.string().nullable(),
  lastError: z.string().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const notificationJobsResponseSchema = z.object({
  jobs: z.array(notificationJobSchema)
});

export const processNotificationJobsRequestSchema = z.object({
  dryRun: z.boolean().optional().default(false),
  limit: z.number().int().min(1).max(25).optional().default(5)
});

export const processedNotificationJobSchema = z.object({
  id: z.string(),
  status: z.enum(["sent", "failed", "skipped", "dry_run"]),
  error: z.string().nullable()
});

export const processNotificationJobsResponseSchema = z.object({
  dryRun: z.boolean(),
  processed: z.number(),
  sent: z.number(),
  failed: z.number(),
  skipped: z.number(),
  jobs: z.array(processedNotificationJobSchema)
});

export const okResponseSchema = z.object({
  ok: z.boolean()
});

export const auditLogSchema = z.object({
  id: z.string(),
  actorId: z.string().nullable(),
  actorEmail: z.string().email().nullable(),
  action: z.string(),
  targetType: z.string(),
  targetId: z.string().nullable(),
  metadata: z.unknown().nullable(),
  ipPrefix: z.string().nullable(),
  createdAt: z.string().datetime()
});

export const auditLogsResponseSchema = z.object({
  logs: z.array(auditLogSchema)
});

export const adminHealthResponseSchema = z.object({
  ok: z.boolean(),
  time: z.string().datetime(),
  database: z.object({
    ok: z.boolean(),
    latencyMs: z.number()
  }),
  conversations: z.object({
    open: z.number(),
    unassigned: z.number(),
    waiting: z.number()
  }),
  notifications: z.object({
    queued: z.number(),
    failed: z.number(),
    sending: z.number()
  })
});

export const departmentSchema = z.object({
  id: z.string(),
  name: z.string(),
  active: z.boolean(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const departmentsResponseSchema = z.object({
  departments: z.array(departmentSchema)
});

export const createDepartmentRequestSchema = z.object({
  name: z.string().trim().min(2).max(80)
});

export const updateAgentDepartmentsRequestSchema = z.object({
  departmentIds: z.array(z.string().min(1)).max(20)
});

export const reportStatusSchema = z.enum(["pending", "investigating", "resolved"]);

export const reportSchema = z.object({
  id: z.string(),
  customerId: z.string(),
  conversationId: z.string().nullable(),
  departmentId: z.string().nullable(),
  customerName: z.string().nullable(),
  title: z.string(),
  body: z.string(),
  status: reportStatusSchema,
  source: z.enum(["registration", "customer"]),
  resolvedBy: z.string().nullable(),
  resolvedAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const reportsResponseSchema = z.object({
  reports: z.array(reportSchema)
});

export const reportResponseSchema = z.object({
  report: reportSchema
});

export const createReportRequestSchema = z.object({
  title: z.string().trim().min(2).max(160),
  body: z.string().trim().min(1).max(5000),
  departmentId: z.string().min(1).optional()
});

export const updateReportStatusRequestSchema = z.object({
  status: reportStatusSchema
});

export const appSettingsSchema = z.object({
  siteName: z.string().trim().min(1).max(80),
  companyName: z.string().trim().min(1).max(120),
  tagline: z.string().trim().min(1).max(240),
  supportEmail: z.string().trim().email().max(320),
  subsidiaries: z.array(z.string().trim().min(1).max(80)).max(12),
  departments: z.array(z.string().trim().min(1).max(80)).max(20),
  maxActiveConversationsPerAgent: z.number().int().min(1).max(200),
  emailNotificationDebounceMinutes: z.number().int().min(1).max(30)
});

export const settingsResponseSchema = z.object({
  settings: appSettingsSchema
});

export const updateSettingsRequestSchema = appSettingsSchema.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one setting is required."
);
