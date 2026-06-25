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
  emailNotificationsEnabled: z.boolean(),
  pushNotificationsEnabled: z.boolean().optional()
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
  departmentId: z.string().nullable().optional(),
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

export const fileRecordSchema = z.object({
  id: z.string(),
  ownerId: z.string(),
  mimeType: z.string(),
  originalFilename: z.string(),
  sizeBytes: z.number().int(),
  kind: z.enum(["image", "document"]),
  metadataStripped: z.boolean(),
  createdAt: z.string().datetime()
});

export const fileResponseSchema = z.object({
  file: fileRecordSchema
});

export const messageSchema = z.object({
  id: z.string(),
  conversationId: z.string(),
  senderId: z.string(),
  senderName: z.string(),
  senderRole: userRoleSchema,
  body: z.string(),
  attachments: z.array(fileRecordSchema).default([]),
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

export const createMessageRequestSchema = z
  .object({
    body: z.string().trim().max(5000).optional().default(""),
    attachmentIds: z.array(z.string().min(1)).max(5).optional().default([])
  })
  .refine((value) => value.body.length > 0 || value.attachmentIds.length > 0, {
    message: "Message body or attachment is required."
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

export const conversationListQuerySchema = z.object({
  status: z.enum(["open", "closed"]).optional(),
  assigned: z.enum(["mine", "unassigned", "any"]).optional(),
  waiting: z.enum(["true", "false"]).optional(),
  search: z.string().trim().max(160).optional(),
  cursor: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional().default(50)
});

export const messageListQuerySchema = z.object({
  before: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional().default(50)
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

export const notificationJobsQuerySchema = z.object({
  status: z.string().trim().max(32).optional(),
  cursor: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional().default(25)
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

export const auditLogsQuerySchema = z.object({
  action: z.string().trim().max(96).optional(),
  actorId: z.string().trim().max(64).optional(),
  targetType: z.string().trim().max(64).optional(),
  targetId: z.string().trim().max(64).optional(),
  cursor: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional().default(50)
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

export const reportsQuerySchema = z.object({
  status: reportStatusSchema.optional(),
  departmentId: z.string().trim().min(1).optional(),
  cursor: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional().default(50)
});

export const pushSubscriptionSchema = z.object({
  endpoint: z.string().url().max(2048),
  p256dh: z.string().min(20).max(512),
  auth: z.string().min(10).max(512)
});

export const pushSubscriptionsResponseSchema = z.object({
  subscriptions: z.array(pushSubscriptionSchema.pick({ endpoint: true }))
});

export const announcementAudienceSchema = z.enum(["customers", "agents", "everyone"]);

export const announcementSchema = z.object({
  id: z.string(),
  authorId: z.string(),
  audience: announcementAudienceSchema,
  title: z.string(),
  body: z.string(),
  imageFileId: z.string().nullable(),
  showPublic: z.boolean(),
  expiresAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const announcementsResponseSchema = z.object({
  announcements: z.array(announcementSchema)
});

export const announcementResponseSchema = z.object({
  announcement: announcementSchema
});

export const createAnnouncementRequestSchema = z.object({
  audience: announcementAudienceSchema,
  title: z.string().trim().min(2).max(160),
  body: z.string().trim().min(1).max(10000),
  imageFileId: z.string().min(1).optional(),
  showPublic: z.boolean().optional().default(false),
  expiresAt: z.string().datetime().optional()
});

export const announcementReactionRequestSchema = z.object({
  reaction: z.enum(["up", "down", "like", "love"])
});

export const announcementCommentRequestSchema = z.object({
  body: z.string().trim().min(1).max(2000)
});

export const appSettingsSchema = z.object({
  siteName: z.string().trim().min(1).max(80),
  companyName: z.string().trim().min(1).max(120),
  tagline: z.string().trim().min(1).max(240),
  supportEmail: z.string().trim().email().max(320),
  subsidiaries: z.array(z.string().trim().min(1).max(80)).max(12),
  departments: z.array(z.string().trim().min(1).max(80)).max(20),
  maxActiveConversationsPerAgent: z.number().int().min(1).max(200),
  maxActiveSessionsPerUser: z.number().int().min(1).max(10),
  maxImageSizeMb: z.number().int().min(1).max(25),
  maxDocumentSizeMb: z.number().int().min(1).max(50),
  dailyUploadLimit: z.number().int().min(1).max(500),
  emailNotificationDebounceMinutes: z.number().int().min(1).max(30),
  pushNotificationsEnabled: z.boolean()
});

export const settingsResponseSchema = z.object({
  settings: appSettingsSchema
});

export const updateSettingsRequestSchema = appSettingsSchema.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one setting is required."
);
