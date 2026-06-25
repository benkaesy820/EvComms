import type { z } from "zod";
import type {
  accountStatusSchema,
  accountPreferencesResponseSchema,
  adminHealthResponseSchema,
  auditLogsResponseSchema,
  authResponseSchema,
  closeConversationRequestSchema,
  createDepartmentRequestSchema,
  conversationResponseSchema,
  conversationSchema,
  conversationsResponseSchema,
  conversationSummarySchema,
  createAgentRequestSchema,
  createMessageRequestSchema,
  createMessageResponseSchema,
  createReportRequestSchema,
  departmentSchema,
  departmentsResponseSchema,
  healthResponseSchema,
  loginRequestSchema,
  messageSchema,
  messagesResponseSchema,
  notificationJobSchema,
  notificationJobsResponseSchema,
  pendingUsersResponseSchema,
  publicUserSchema,
  realtimeEventSchema,
  reassignConversationRequestSchema,
  rejectUserRequestSchema,
  reportResponseSchema,
  reportSchema,
  reportsResponseSchema,
  requestPasswordResetSchema,
  registerRequestSchema,
  resetPasswordSchema,
  settingsResponseSchema,
  sessionsResponseSchema,
  updateAccountPreferencesRequestSchema,
  updateAgentDepartmentsRequestSchema,
  updateReportStatusRequestSchema,
  updateSettingsRequestSchema,
  usersResponseSchema,
  userRoleSchema
} from "./schemas";

export type UserRole = z.infer<typeof userRoleSchema>;
export type AccountStatus = z.infer<typeof accountStatusSchema>;
export type AccountPreferencesResponse = z.infer<typeof accountPreferencesResponseSchema>;
export type UpdateAccountPreferencesRequest = z.infer<typeof updateAccountPreferencesRequestSchema>;
export type SessionsResponse = z.infer<typeof sessionsResponseSchema>;
export type AuditLogsResponse = z.infer<typeof auditLogsResponseSchema>;
export type AdminHealthResponse = z.infer<typeof adminHealthResponseSchema>;
export type Department = z.infer<typeof departmentSchema>;
export type DepartmentsResponse = z.infer<typeof departmentsResponseSchema>;
export type CreateDepartmentRequest = z.infer<typeof createDepartmentRequestSchema>;
export type UpdateAgentDepartmentsRequest = z.infer<typeof updateAgentDepartmentsRequestSchema>;
export type Report = z.infer<typeof reportSchema>;
export type ReportsResponse = z.infer<typeof reportsResponseSchema>;
export type ReportResponse = z.infer<typeof reportResponseSchema>;
export type CreateReportRequest = z.infer<typeof createReportRequestSchema>;
export type UpdateReportStatusRequest = z.infer<typeof updateReportStatusRequestSchema>;
export type HealthResponse = z.infer<typeof healthResponseSchema>;
export type PublicUser = z.infer<typeof publicUserSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type RequestPasswordReset = z.infer<typeof requestPasswordResetSchema>;
export type ResetPassword = z.infer<typeof resetPasswordSchema>;
export type AuthResponse = z.infer<typeof authResponseSchema>;
export type PendingUsersResponse = z.infer<typeof pendingUsersResponseSchema>;
export type RejectUserRequest = z.infer<typeof rejectUserRequestSchema>;
export type CreateAgentRequest = z.infer<typeof createAgentRequestSchema>;
export type UsersResponse = z.infer<typeof usersResponseSchema>;
export type Conversation = z.infer<typeof conversationSchema>;
export type ConversationSummary = z.infer<typeof conversationSummarySchema>;
export type Message = z.infer<typeof messageSchema>;
export type ConversationResponse = z.infer<typeof conversationResponseSchema>;
export type ConversationsResponse = z.infer<typeof conversationsResponseSchema>;
export type MessagesResponse = z.infer<typeof messagesResponseSchema>;
export type CreateMessageRequest = z.infer<typeof createMessageRequestSchema>;
export type CreateMessageResponse = z.infer<typeof createMessageResponseSchema>;
export type RealtimeEvent = z.infer<typeof realtimeEventSchema>;
export type ReassignConversationRequest = z.infer<typeof reassignConversationRequestSchema>;
export type CloseConversationRequest = z.infer<typeof closeConversationRequestSchema>;
export type NotificationJob = z.infer<typeof notificationJobSchema>;
export type NotificationJobsResponse = z.infer<typeof notificationJobsResponseSchema>;
export type SettingsResponse = z.infer<typeof settingsResponseSchema>;
export type UpdateSettingsRequest = z.infer<typeof updateSettingsRequestSchema>;
