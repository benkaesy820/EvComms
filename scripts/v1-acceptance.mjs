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
  return request(`${apiBaseUrl}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
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
    body: JSON.stringify({ emailNotificationsEnabled: false })
  });
  assert.equal(preferencesUpdate.response.status, 200);
  assert.equal(preferencesUpdate.body.preferences.emailNotificationsEnabled, false);
  const customerConversation = await api("/conversations/me", { cookie: customerLogin.cookie });
  assert.equal(customerConversation.response.status, 200);
  const customerMessage = await api(`/conversations/${customerConversation.body.conversation.id}/messages`, {
    method: "POST",
    cookie: customerLogin.cookie,
    body: JSON.stringify({ body: "Hello from acceptance." })
  });
  assert.equal(customerMessage.response.status, 201);
  const assignedConversations = await api("/admin/conversations", { cookie: adminCookie });
  assert.equal(assignedConversations.response.status, 200);
  assert.notEqual(
    assignedConversations.body.conversations.find((conversation) => conversation.id === customerConversation.body.conversation.id)
      ?.assignedAgentId,
    null
  );

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

  const notificationDryRun = await api("/admin/notification-jobs/process", {
    method: "POST",
    cookie: adminCookie,
    body: JSON.stringify({ dryRun: true, limit: 10 })
  });
  assert.equal(notificationDryRun.response.status, 200);
  assert.equal(notificationDryRun.body.dryRun, true);
  const adminHealth = await api("/admin/health", { cookie: adminCookie });
  assert.equal(adminHealth.response.status, 200);
  assert.equal(adminHealth.body.ok, true);
  const auditLogs = await api("/admin/audit-logs?limit=10", { cookie: adminCookie });
  assert.equal(auditLogs.response.status, 200);
  assert.equal(auditLogs.body.logs.length > 0, true);

  checked.push(
    "super admin login",
      "super admin approval",
      "agent creation",
      "session listing",
      "notification preferences",
      "first message assignment",
      "customer role boundaries",
      "agent role boundaries",
      "agent notification processing denied",
      "notification dry run",
      "admin health",
      "audit logs"
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
