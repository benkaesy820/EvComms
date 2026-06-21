import {
  authResponseSchema,
  conversationResponseSchema,
  conversationsResponseSchema,
  type CloseConversationRequest,
  type RequestPasswordReset,
  type ResetPassword,
  createMessageResponseSchema,
  healthResponseSchema,
  messagesResponseSchema,
  type CreateMessageRequest,
  type CreateAgentRequest,
  pendingUsersResponseSchema,
  realtimeEventSchema,
  usersResponseSchema,
  type RealtimeEvent,
  type ReassignConversationRequest,
  type LoginRequest,
  type RegisterRequest,
  type RejectUserRequest,
  settingsResponseSchema,
  type UpdateSettingsRequest,
  notificationJobsResponseSchema,
  processNotificationJobsResponseSchema,
  type NotificationJob
} from "@evbus/shared";

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8787";
const realtimeBaseUrl = apiBaseUrl.replace(/^http/, "ws");

export async function getHealth() {
  const response = await fetch(`${apiBaseUrl}/health`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }

  return healthResponseSchema.parse(await response.json());
}

export async function register(input: RegisterRequest) {
  return requestAuth("/auth/register", input);
}

export async function login(input: LoginRequest) {
  return requestAuth("/auth/login", input);
}

export async function getMe() {
  const response = await fetch(`${apiBaseUrl}/auth/me`, {
    credentials: "include"
  });

  if (!response.ok) {
    return null;
  }

  return authResponseSchema.parse(await response.json()).user;
}

export async function logout() {
  const response = await fetch(`${apiBaseUrl}/auth/logout`, {
    method: "POST",
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Logout failed.");
  }
}

export async function requestPasswordReset(input: RequestPasswordReset) {
  await requestOk("/auth/request-password-reset", input);
}

export async function resetPassword(input: ResetPassword) {
  await requestOk("/auth/reset-password", input);
}

export async function getSettings() {
  const response = await fetch(`${apiBaseUrl}/settings`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load settings.");
  }

  return settingsResponseSchema.parse(await response.json()).settings;
}

export async function updateSettings(input: UpdateSettingsRequest) {
  const response = await fetch(`${apiBaseUrl}/admin/settings`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Could not update settings.");
  }

  return settingsResponseSchema.parse(body).settings;
}

export async function getPendingUsers() {
  const response = await fetch(`${apiBaseUrl}/admin/pending-users`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load pending users.");
  }

  return pendingUsersResponseSchema.parse(await response.json()).users;
}

export async function approveUser(userId: string) {
  return requestAdminUser(`/admin/users/${userId}/approve`);
}

export async function rejectUser(userId: string, input: RejectUserRequest = {}) {
  return requestAdminUser(`/admin/users/${userId}/reject`, input);
}

export async function getAgents() {
  const response = await fetch(`${apiBaseUrl}/admin/agents`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load agents.");
  }

  return usersResponseSchema.parse(await response.json()).users;
}

export async function getCustomers() {
  const response = await fetch(`${apiBaseUrl}/admin/customers`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load customers.");
  }

  return usersResponseSchema.parse(await response.json()).users;
}

export async function createAgent(input: CreateAgentRequest) {
  return requestAdminUser("/admin/agents", input);
}

export async function suspendUser(userId: string) {
  return requestAdminUser(`/admin/users/${userId}/suspend`);
}

export async function getNotificationJobs() {
  const response = await fetch(`${apiBaseUrl}/admin/notification-jobs`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load notification jobs.");
  }

  return notificationJobsResponseSchema.parse(await response.json()).jobs;
}

export async function processNotificationJobs(input: { dryRun?: boolean; limit?: number } = {}) {
  const response = await fetch(`${apiBaseUrl}/admin/notification-jobs/process`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Could not process notification jobs.");
  }

  return processNotificationJobsResponseSchema.parse(body);
}

export async function getMyConversation() {
  const response = await fetch(`${apiBaseUrl}/conversations/me`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load conversation.");
  }

  return conversationResponseSchema.parse(await response.json()).conversation;
}

export async function getAdminConversations() {
  const response = await fetch(`${apiBaseUrl}/admin/conversations`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load conversations.");
  }

  return conversationsResponseSchema.parse(await response.json()).conversations;
}

export async function getMessages(conversationId: string) {
  const response = await fetch(`${apiBaseUrl}/conversations/${conversationId}/messages`, {
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error("Could not load messages.");
  }

  return messagesResponseSchema.parse(await response.json()).messages;
}

export async function sendMessage(conversationId: string, input: CreateMessageRequest) {
  const response = await fetch(`${apiBaseUrl}/conversations/${conversationId}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Could not send message.");
  }

  return createMessageResponseSchema.parse(body).message;
}

export async function reassignConversation(
  conversationId: string,
  input: ReassignConversationRequest
) {
  return requestConversation(`/admin/conversations/${conversationId}/reassign`, input);
}

export async function closeConversation(conversationId: string, input: CloseConversationRequest) {
  return requestConversation(`/conversations/${conversationId}/close`, input);
}

export async function reopenConversation(conversationId: string) {
  return requestConversation(`/conversations/${conversationId}/reopen`, {});
}

export function connectConversationRealtime(
  conversationId: string,
  onEvent: (event: RealtimeEvent) => void
) {
  const socket = new WebSocket(
    `${realtimeBaseUrl}/realtime?conversationId=${encodeURIComponent(conversationId)}`
  );

  socket.addEventListener("message", (event) => {
    try {
      const parsed = realtimeEventSchema.safeParse(JSON.parse(String(event.data)));
      if (parsed.success) onEvent(parsed.data);
    } catch {
      // Ignore malformed realtime events; durable state is still fetched over HTTP.
    }
  });

  return socket;
}

async function requestAuth(path: string, input: LoginRequest | RegisterRequest) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Request failed.");
  }

  return authResponseSchema.parse(body).user;
}

async function requestAdminUser(path: string, input?: RejectUserRequest | CreateAgentRequest) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input ?? {})
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Request failed.");
  }

  return authResponseSchema.parse(body).user;
}

async function requestConversation(
  path: string,
  input: ReassignConversationRequest | CloseConversationRequest | Record<string, never>
) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Request failed.");
  }

  return conversationResponseSchema.parse(body).conversation;
}

async function requestOk(path: string, input: RequestPasswordReset | ResetPassword) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify(input)
  });

  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.error ?? "Request failed.");
  }
}
