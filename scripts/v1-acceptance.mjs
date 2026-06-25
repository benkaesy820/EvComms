import assert from "node:assert/strict";
import fs from "node:fs";
import { connect } from "@tidbcloud/serverless";

const apiBaseUrl = process.env.API_BASE_URL ?? "http://127.0.0.1:8787";
const webBaseUrl = process.env.WEB_BASE_URL ?? "http://127.0.0.1:5173";
const runId = crypto.randomUUID();
const seededAdminEmail = `acceptance-admin-${runId}@example.com`;
const adminPassword = process.env.ACCEPTANCE_ADMIN_PASSWORD ?? "Safe-admin-password-123";
const adminEmail = process.env.ACCEPTANCE_ADMIN_EMAIL ?? (await seedAcceptanceAdmin(seededAdminEmail, adminPassword));
const customerEmail = `acceptance-${runId}@example.com`;
const agentEmail = `acceptance-agent-${runId}@example.com`;
const password = "Safe-password-123";

async function request(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  return { response, body };
}

async function api(path, options = {}) {
  const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
  return request(`${apiBaseUrl}${path}`, {
    ...options,
    headers: {
      ...(options.body && !isFormData ? { "content-type": "application/json" } : {}),
      ...(options.cookie ? { cookie: options.cookie } : {}),
      ...options.headers
    }
  });
}

async function login(email, loginPassword) {
  const result = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password: loginPassword })
  });
  const cookie = result.response.headers.get("set-cookie")?.split(";")[0];
  return { ...result, cookie };
}

const health = await request(`${apiBaseUrl}/health`);
assert.equal(health.response.status, 200);
assert.equal(health.body.ok, true);

const settings = await api("/settings");
assert.equal(settings.response.status, 200);
assert.equal(typeof settings.body.settings.siteName, "string");
assert.equal(typeof settings.body.settings.emailNotificationDebounceMinutes, "number");

const corsHealth = await fetch(`${apiBaseUrl}/health`, {
  headers: { Origin: "http://127.0.0.1:5173" }
});
assert.equal(corsHealth.headers.get("access-control-allow-origin"), "http://127.0.0.1:5173");
const corsPreflight = await fetch(`${apiBaseUrl}/auth/login`, {
  method: "OPTIONS",
  headers: {
    Origin: "http://127.0.0.1:5173",
    "Access-Control-Request-Method": "POST"
  }
});
assert.equal(corsPreflight.headers.get("access-control-allow-origin"), "http://127.0.0.1:5173");

const anonymousSession = await api("/auth/me");
assert.equal(anonymousSession.response.status, 401);
assert.equal((await api("/admin/customers")).response.status, 401);
assert.equal((await api("/admin/notification-jobs")).response.status, 401);

const registrationInput = {
  name: "Acceptance Customer",
  email: customerEmail,
  phone: "+233501234567",
  registrationNote: "I need help with my first support request.",
  password
};
const registration = await api("/auth/register", {
  method: "POST",
  body: JSON.stringify(registrationInput)
});
assert.equal(registration.response.status, 201);
assert.equal(registration.body.user.email, customerEmail);
assert.equal(registration.body.user.status, "pending");
assert.equal(registration.body.user.role, "customer");
assert.equal(registration.body.user.registrationNote, registrationInput.registrationNote);

const duplicateRegistration = await api("/auth/register", {
  method: "POST",
  body: JSON.stringify(registrationInput)
});
assert.equal(duplicateRegistration.response.status, 409);

const pendingCustomerLogin = await login(customerEmail, password);
assert.equal(pendingCustomerLogin.response.status, 403);

const passwordReset = await api("/auth/request-password-reset", {
  method: "POST",
  body: JSON.stringify({ email: `missing-${runId}@example.com` })
});
assert.equal(passwordReset.response.status, 200);
assert.equal(passwordReset.body.ok, true);

const checked = [
  "health",
  "settings",
  "anonymous auth",
  "anonymous admin denied",
  "customer registration",
  "duplicate registration",
  "pending customer login denied",
  "password reset request"
];

if (adminEmail && adminPassword) {
  const adminLogin = await login(adminEmail, adminPassword);
  assert.equal(adminLogin.response.status, 200);
  assert.equal(adminLogin.body.user.role, "super_admin");
  assert.ok(adminLogin.cookie);

  const adminCookie = adminLogin.cookie;
  const pendingUsers = await api("/admin/pending-users", { cookie: adminCookie });
  assert.equal(pendingUsers.response.status, 200);
  const pendingCustomer = pendingUsers.body.users.find((user) => user.email === customerEmail);
  assert.ok(pendingCustomer);

  const approval = await api(`/admin/users/${pendingCustomer.id}/approve`, {
    method: "POST",
    cookie: adminCookie
  });
  assert.equal(approval.response.status, 200);
  assert.equal(approval.body.user.status, "approved");

  const agentCreation = await api("/admin/agents", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({
      name: "Acceptance Agent",
      email: agentEmail,
      phone: "+233551234567",
      password
    })
  });
  assert.equal(agentCreation.response.status, 201);
  assert.equal(agentCreation.body.user.role, "agent");

  const departmentCreation = await api("/admin/departments", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({ name: `Acceptance Department ${runId.slice(0, 8)}` })
  });
  assert.equal(departmentCreation.response.status, 201);
  const departmentId = departmentCreation.body.departments[0].id;

  const agentDepartments = await api(`/admin/agents/${agentCreation.body.user.id}/departments`, {
    method: "PUT",
    cookie: adminCookie,
    body: JSON.stringify({ departmentIds: [departmentId] })
  });
  assert.equal(agentDepartments.response.status, 200);
  assert.equal(agentDepartments.body.ok, true);

  const customerLogin = await login(customerEmail, password);
  assert.equal(customerLogin.response.status, 200);
  assert.equal(customerLogin.body.user.role, "customer");
  assert.ok(customerLogin.cookie);

  assert.equal((await api("/admin/customers", { cookie: customerLogin.cookie })).response.status, 403);
  assert.equal((await api("/admin/conversations", { cookie: customerLogin.cookie })).response.status, 403);
  const customerSessions = await api("/auth/sessions", { cookie: customerLogin.cookie });
  assert.equal(customerSessions.response.status, 200);
  assert.equal(customerSessions.body.sessions.some((session) => session.current), true);
  const preferences = await api("/account/preferences", { cookie: customerLogin.cookie });
  assert.equal(preferences.response.status, 200);
  assert.equal(preferences.body.preferences.emailNotificationsEnabled, true);
  const preferencesUpdate = await api("/account/preferences", {
    method: "PUT",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ emailNotificationsEnabled: false, pushNotificationsEnabled: true })
  });
  assert.equal(preferencesUpdate.response.status, 200);
  assert.equal(preferencesUpdate.body.preferences.emailNotificationsEnabled, false);
  assert.equal(preferencesUpdate.body.preferences.pushNotificationsEnabled, true);
  const pushEndpoint = `https://push.example.com/${runId}`;
  const pushSave = await api("/push-subscriptions", {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({
      endpoint: pushEndpoint,
      p256dh: "p256dh-key-material-123456",
      auth: "auth-secret-123"
    })
  });
  assert.equal(pushSave.response.status, 200);
  const pushList = await api("/push-subscriptions", { cookie: customerLogin.cookie });
  assert.equal(pushList.response.status, 200);
  assert.equal(pushList.body.subscriptions.some((subscription) => subscription.endpoint === pushEndpoint), true);
  const pushDelete = await api("/push-subscriptions", {
    method: "DELETE",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ endpoint: pushEndpoint })
  });
  assert.equal(pushDelete.response.status, 200);
  const pushListAfterDelete = await api("/push-subscriptions", { cookie: customerLogin.cookie });
  assert.equal(pushListAfterDelete.response.status, 200);
  assert.equal(pushListAfterDelete.body.subscriptions.some((subscription) => subscription.endpoint === pushEndpoint), false);

  const customerAnnouncement = await api("/admin/announcements", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({
      audience: "customers",
      title: `Acceptance customer announcement ${runId.slice(0, 8)}`,
      body: "Customer-visible announcement body.",
      showPublic: true
    })
  });
  assert.equal(customerAnnouncement.response.status, 201);
  const publicAnnouncements = await api("/public/announcements");
  assert.equal(publicAnnouncements.response.status, 200);
  assert.equal(
    publicAnnouncements.body.announcements.some((announcement) => announcement.id === customerAnnouncement.body.announcement.id),
    true
  );
  const customerAnnouncements = await api("/announcements", { cookie: customerLogin.cookie });
  assert.equal(customerAnnouncements.response.status, 200);
  assert.equal(
    customerAnnouncements.body.announcements.some((announcement) => announcement.id === customerAnnouncement.body.announcement.id),
    true
  );
  assert.equal((await api("/admin/announcements", {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ audience: "everyone", title: "Nope", body: "Nope" })
  })).response.status, 403);
  const announcementReaction = await api(`/announcements/${customerAnnouncement.body.announcement.id}/reaction`, {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ reaction: "like" })
  });
  assert.equal(announcementReaction.response.status, 200);
  const announcementComment = await api(`/announcements/${customerAnnouncement.body.announcement.id}/comments`, {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ body: "Looks good." })
  });
  assert.equal(announcementComment.response.status, 201);

  const uploadForm = new FormData();
  uploadForm.set(
    "file",
    new File([Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])], "acceptance.png", {
      type: "image/png"
    })
  );
  const uploadAttempt = await api("/files", {
    method: "POST",
    cookie: customerLogin.cookie,
    body: uploadForm
  });
  assert.ok([201, 503].includes(uploadAttempt.response.status));

  const customerConversation = await api("/conversations/me", { cookie: customerLogin.cookie });
  assert.equal(customerConversation.response.status, 200);
  assert.equal(customerConversation.body.conversation.registrationNote, registrationInput.registrationNote);
  const customerReport = await api("/reports", {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({
      title: "Acceptance report",
      body: "The V2 report queue should receive this.",
      departmentId
    })
  });
  assert.equal(customerReport.response.status, 201);
  assert.equal(customerReport.body.report.status, "pending");
  const customerReports = await api("/reports", { cookie: customerLogin.cookie });
  assert.equal(customerReports.response.status, 200);
  assert.equal(customerReports.body.reports.some((report) => report.id === customerReport.body.report.id), true);
  const customerReportsFiltered = await api(`/reports?status=pending&departmentId=${departmentId}&limit=5`, {
    cookie: customerLogin.cookie
  });
  assert.equal(customerReportsFiltered.response.status, 200);
  assert.equal(customerReportsFiltered.body.reports.some((report) => report.id === customerReport.body.report.id), true);
  const attachmentId = await seedAcceptanceFile(customerLogin.body.user.id, runId);
  const customerMessage = await api(`/conversations/${customerConversation.body.conversation.id}/messages`, {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ body: "Hello from acceptance.", attachmentIds: attachmentId ? [attachmentId] : [] })
  });
  assert.equal(customerMessage.response.status, 201);
  if (attachmentId) {
    assert.equal(customerMessage.body.message.attachments[0].id, attachmentId);
  }
  const latestMessages = await api(`/conversations/${customerConversation.body.conversation.id}/messages?limit=1`, {
    cookie: customerLogin.cookie
  });
  assert.equal(latestMessages.response.status, 200);
  assert.equal(latestMessages.body.messages.length, 1);
  if (attachmentId) {
    assert.equal(latestMessages.body.messages[0].attachments[0].id, attachmentId);
  }
  const assignedConversations = await api("/admin/conversations", { cookie: adminCookie });
  assert.equal(assignedConversations.response.status, 200);
  assert.notEqual(
    assignedConversations.body.conversations.find((conversation) => conversation.id === customerConversation.body.conversation.id)
      ?.assignedAgentId,
    null
  );
  const waitingConversations = await api("/admin/conversations?waiting=true&limit=5", { cookie: adminCookie });
  assert.equal(waitingConversations.response.status, 200);

  const agentLogin = await login(agentEmail, password);
  assert.equal(agentLogin.response.status, 200);
  assert.equal(agentLogin.body.user.role, "agent");
  assert.ok(agentLogin.cookie);

  assert.equal((await api("/admin/agents", { cookie: agentLogin.cookie })).response.status, 403);
  assert.equal((await api("/admin/customers", { cookie: agentLogin.cookie })).response.status, 403);
  assert.equal((await api("/admin/notification-jobs/process", {
    method: "POST",
    cookie: agentLogin.cookie,
    body: JSON.stringify({ dryRun: true, limit: 1 })
  })).response.status, 403);
  assert.equal((await api("/conversations/me", { cookie: agentLogin.cookie })).response.status, 403);
  const agentConversations = await api("/admin/conversations", { cookie: agentLogin.cookie });
  assert.equal(agentConversations.response.status, 200);
  const mineConversations = await api("/admin/conversations?assigned=mine&limit=5", { cookie: agentLogin.cookie });
  assert.equal(mineConversations.response.status, 200);
  const agentAnnouncement = await api("/admin/announcements", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({
      audience: "agents",
      title: `Acceptance agent announcement ${runId.slice(0, 8)}`,
      body: "Agent-visible announcement body."
    })
  });
  assert.equal(agentAnnouncement.response.status, 201);
  const agentAnnouncements = await api("/announcements", { cookie: agentLogin.cookie });
  assert.equal(agentAnnouncements.response.status, 200);
  assert.equal(
    agentAnnouncements.body.announcements.some((announcement) => announcement.id === customerAnnouncement.body.announcement.id),
    false
  );
  assert.equal(
    agentAnnouncements.body.announcements.some((announcement) => announcement.id === agentAnnouncement.body.announcement.id),
    true
  );

  const notificationDryRun = await api("/admin/notification-jobs/process", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({ dryRun: true, limit: 10 })
  });
  assert.equal(notificationDryRun.response.status, 200);
  assert.equal(notificationDryRun.body.dryRun, true);
  const notificationJobs = await api("/admin/notification-jobs?status=queued&limit=5", { cookie: adminCookie });
  assert.equal(notificationJobs.response.status, 200);
  const adminHealth = await api("/admin/health", { cookie: adminCookie });
  assert.equal(adminHealth.response.status, 200);
  assert.equal(adminHealth.body.ok, true);
  const auditLogs = await api("/admin/audit-logs?limit=10", { cookie: adminCookie });
  assert.equal(auditLogs.response.status, 200);
  assert.equal(auditLogs.body.logs.length > 0, true);
  const filteredAuditLogs = await api("/admin/audit-logs?action=announcement.created&limit=10", { cookie: adminCookie });
  assert.equal(filteredAuditLogs.response.status, 200);
  assert.equal(filteredAuditLogs.body.logs.some((log) => log.targetId === customerAnnouncement.body.announcement.id), true);
  const adminReports = await api(`/admin/reports?status=pending&departmentId=${departmentId}&limit=5`, { cookie: adminCookie });
  assert.equal(adminReports.response.status, 200);
  assert.equal(adminReports.body.reports.some((report) => report.id === customerReport.body.report.id), true);
  const reportStatus = await api(`/admin/reports/${customerReport.body.report.id}/status`, {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({ status: "resolved" })
  });
  assert.equal(reportStatus.response.status, 200);
  assert.equal(reportStatus.body.report.status, "resolved");

  checked.push(
    "super admin login",
      "super admin approval",
      "agent creation",
      "department creation",
      "agent department assignment",
      "session listing",
      "notification preferences",
      "push subscription lifecycle",
      "announcement lifecycle",
      "file storage guard",
      "registration note handoff",
      "customer reports",
      "filtered reports",
      "first message assignment",
      "message attachments",
      "conversation filters",
      "customer role boundaries",
      "agent role boundaries",
      "agent announcements",
      "agent notification processing denied",
      "notification dry run",
      "notification job filters",
      "admin health",
      "audit logs",
      "filtered audit logs",
      "admin reports"
    );
}

const web = await fetch(webBaseUrl);
assert.equal(web.status, 200);
assert.match(await web.text(), /<div id="root"><\/div>/);
checked.push("web shell");

console.log(
  JSON.stringify({
    ok: true,
    apiBaseUrl,
    webBaseUrl,
    checked,
    skipped: []
  })
);

async function seedAcceptanceAdmin(email, passwordValue) {
  const databaseUrl = process.env.TIDB_DATABASE_URL ?? readDevVar("TIDB_DATABASE_URL");
  if (!databaseUrl) return null;

  const connection = connect({ url: databaseUrl });
  await connection.execute(
    `INSERT INTO users (id, role, name, email, phone, password_hash, status)
      VALUES (?, 'super_admin', 'Acceptance Admin', ?, '+233501234568', ?, 'approved')
      ON DUPLICATE KEY UPDATE
        password_hash = VALUES(password_hash),
        status = 'approved',
        updated_at = CURRENT_TIMESTAMP`,
    [crypto.randomUUID(), email, await hashPassword(passwordValue)]
  );
  return email;
}

async function seedAcceptanceFile(ownerId, suffix) {
  const databaseUrl = process.env.TIDB_DATABASE_URL ?? readDevVar("TIDB_DATABASE_URL");
  if (!databaseUrl) return null;

  const id = crypto.randomUUID();
  const connection = connect({ url: databaseUrl });
  await connection.execute(
    `INSERT INTO files (id, owner_id, storage_key, sha256_hash, mime_type, original_filename, size_bytes, kind, metadata_stripped)
      VALUES (?, ?, ?, ?, 'image/png', 'acceptance.png', 8, 'image', 1)`,
    [id, ownerId, `acceptance/${id}.png`, crypto.randomUUID().replaceAll("-", "").slice(0, 64)]
  );
  return id;
}

function readDevVar(key) {
  if (!fs.existsSync("apps/api/.dev.vars")) return null;

  for (const line of fs.readFileSync("apps/api/.dev.vars", "utf8").split(/\r?\n/)) {
    const match = line.match(/^([^#=]+)=(.*)$/);
    if (match?.[1]?.trim() === key) return match[2].trim().replace(/^"|"$/g, "");
  }

  return null;
}

async function hashPassword(passwordValue) {
  const salt = randomToken(16);
  const iterations = 150_000;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passwordValue),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode(salt),
      iterations
    },
    key,
    256
  );

  return `pbkdf2_sha256$${iterations}$${salt}$${base64Url(new Uint8Array(bits))}`;
}

function randomToken(bytes) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return base64Url(values);
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
