import {
  appConfig,
  type Conversation,
  type ConversationSummary,
  type Message,
  type NotificationJob,
  type PublicUser
} from "@evbus/shared";
import { type FormEvent, useEffect, useState } from "react";
import {
  approveUser,
  closeConversation,
  connectConversationRealtime,
  createAgent,
  getAdminConversations,
  getAgents,
  getCustomers,
  getHealth,
  getMe,
  getNotificationJobs,
  getSettings,
  getMessages,
  getMyConversation,
  getPendingUsers,
  login,
  logout,
  register,
  rejectUser,
  requestPasswordReset,
  resetPassword,
  reassignConversation,
  reopenConversation,
  sendMessage,
  processNotificationJobs,
  suspendUser,
  updateSettings
} from "./api";

type HealthState = "checking" | "ok" | "error";
type Mode = "login" | "signup";
type AppSettings = Awaited<ReturnType<typeof getSettings>>;

export function App() {
  const [health, setHealth] = useState<HealthState>("checking");
  const [mode, setMode] = useState<Mode>("signup");
  const [user, setUser] = useState<PublicUser | null>(null);
  const [agents, setAgents] = useState<PublicUser[]>([]);
  const [customers, setCustomers] = useState<PublicUser[]>([]);
  const [notificationJobs, setNotificationJobs] = useState<NotificationJob[]>([]);
  const [pendingUsers, setPendingUsers] = useState<PublicUser[]>([]);
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [message, setMessage] = useState("");
  const [settings, setSettings] = useState<AppSettings | null>(null);

  useEffect(() => {
    let cancelled = false;

    Promise.allSettled([getHealth(), getMe(), getSettings()]).then(
      ([healthResult, userResult, settingsResult]) => {
        if (cancelled) return;
        setHealth(healthResult.status === "fulfilled" ? "ok" : "error");
        if (userResult.status === "fulfilled") setUser(userResult.value);
        if (settingsResult.status === "fulfilled") setSettings(settingsResult.value);
      }
    );

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (user?.role !== "super_admin") {
      setPendingUsers([]);
      setAgents([]);
      setCustomers([]);
      setNotificationJobs([]);
      return;
    }

    void loadPendingUsers();
    void loadAgents();
    void loadCustomers();
    void loadNotificationJobs();
  }, [user?.role]);

  useEffect(() => {
    setConversation(null);
    setConversations([]);
    setSelectedConversationId(null);
    setMessages([]);

    if (user?.role === "customer" && user.status === "approved") {
      void loadCustomerConversation();
    }

    if (user?.role === "super_admin" || user?.role === "agent") {
      void loadAdminConversations();
    }
  }, [user?.id, user?.role, user?.status]);

  useEffect(() => {
    if (!selectedConversationId) return;
    void loadMessages(selectedConversationId);
  }, [selectedConversationId]);

  useEffect(() => {
    if (!selectedConversationId || !user) return;

    const socket = connectConversationRealtime(selectedConversationId, (event) => {
      if (event.type !== "message.created") return;

      setMessages((current) => {
        if (current.some((item) => item.id === event.message.id)) return current;
        return [...current, event.message];
      });

      if (user.role === "super_admin") {
        void loadAdminConversations();
      }
    });

    socket.addEventListener("close", () => {
      void loadMessages(selectedConversationId);
    });

    return () => {
      socket.close();
    };
  }, [selectedConversationId, user?.id]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");

    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");

    try {
      if (mode === "login") {
        const nextUser = await login({ email, password });
        setUser(nextUser);
        setMessage("Logged in.");
        return;
      }

      const nextUser = await register({
        name: String(form.get("name") ?? ""),
        email,
        phone: String(form.get("phone") ?? ""),
        password
      });
      setUser(nextUser);
      setMessage("Signup received. Your account is pending approval.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Something went wrong.");
    }
  }

  async function onLogout() {
    await logout();
    setUser(null);
    setMessage("Logged out.");
  }

  async function onRequestPasswordReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);

    try {
      await requestPasswordReset({ email: String(form.get("email") ?? "") });
      event.currentTarget.reset();
      setMessage("If that account exists, a reset email is on its way.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not request reset.");
    }
  }

  async function onResetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);

    try {
      await resetPassword({
        token: String(form.get("token") ?? ""),
        password: String(form.get("password") ?? "")
      });
      event.currentTarget.reset();
      setMessage("Password reset. You can log in now.");
      setMode("login");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not reset password.");
    }
  }

  async function loadCustomerConversation() {
    try {
      const nextConversation = await getMyConversation();
      setConversation(nextConversation);
      setSelectedConversationId(nextConversation.id);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load conversation.");
    }
  }

  async function loadAdminConversations() {
    try {
      const nextConversations = await getAdminConversations();
      setConversations(nextConversations);
      setSelectedConversationId((current) => current ?? nextConversations[0]?.id ?? null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load conversations.");
    }
  }

  async function loadAgents() {
    try {
      setAgents(await getAgents());
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load agents.");
    }
  }

  async function loadCustomers() {
    try {
      setCustomers(await getCustomers());
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load customers.");
    }
  }

  async function loadNotificationJobs() {
    try {
      setNotificationJobs(await getNotificationJobs());
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load notification jobs.");
    }
  }

  async function loadMessages(conversationId: string) {
    try {
      setMessages(await getMessages(conversationId));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load messages.");
    }
  }

  async function onSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConversationId) return;

    const form = new FormData(event.currentTarget);
    const body = String(form.get("body") ?? "");

    try {
      const sentMessage = await sendMessage(selectedConversationId, { body });
      setMessages((current) => {
        if (current.some((item) => item.id === sentMessage.id)) return current;
        return [...current, sentMessage];
      });
      event.currentTarget.reset();
      if (user?.role === "super_admin" || user?.role === "agent") await loadAdminConversations();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not send message.");
    }
  }

  async function refreshConversationState(conversationId: string) {
    if (user?.role === "customer") {
      await loadCustomerConversation();
    }
    if (user?.role === "super_admin" || user?.role === "agent") {
      await loadAdminConversations();
      setSelectedConversationId(conversationId);
    }
  }

  async function onReassign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConversationId) return;

    const form = new FormData(event.currentTarget);
    const agentId = String(form.get("agentId") ?? "") || null;

    try {
      await reassignConversation(selectedConversationId, { agentId });
      setMessage(agentId ? "Conversation reassigned." : "Conversation unassigned.");
      await loadAdminConversations();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not reassign conversation.");
    }
  }

  async function onCloseConversation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConversationId) return;

    const form = new FormData(event.currentTarget);
    const note = String(form.get("note") ?? "");

    try {
      await closeConversation(selectedConversationId, { note });
      event.currentTarget.reset();
      setMessage("Conversation closed.");
      await refreshConversationState(selectedConversationId);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not close conversation.");
    }
  }

  async function onReopenConversation() {
    if (!selectedConversationId) return;

    try {
      await reopenConversation(selectedConversationId);
      setMessage("Conversation reopened.");
      await refreshConversationState(selectedConversationId);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not reopen conversation.");
    }
  }

  async function loadPendingUsers() {
    try {
      setPendingUsers(await getPendingUsers());
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load pending users.");
    }
  }

  async function onApprove(userId: string) {
    try {
      await approveUser(userId);
      setMessage("Customer approved.");
      await loadPendingUsers();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not approve customer.");
    }
  }

  async function onReject(userId: string) {
    try {
      await rejectUser(userId, { reason: "Rejected by Super Admin." });
      setMessage("Customer rejected.");
      await loadPendingUsers();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not reject customer.");
    }
  }

  async function onCreateAgent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);

    try {
      await createAgent({
        name: String(form.get("name") ?? ""),
        email: String(form.get("email") ?? ""),
        phone: String(form.get("phone") ?? "") || undefined,
        password: String(form.get("password") ?? "")
      });
      event.currentTarget.reset();
      setMessage("Agent created.");
      await loadAgents();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not create agent.");
    }
  }

  async function onSuspendUser(userId: string, label: string) {
    if (!window.confirm(`Suspend ${label}? Active sessions will be revoked.`)) return;

    try {
      await suspendUser(userId);
      setMessage(`${label} suspended.`);
      await Promise.all([loadAgents(), loadCustomers(), loadAdminConversations()]);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not suspend user.");
    }
  }

  async function onProcessNotifications() {
    try {
      const result = await processNotificationJobs({ limit: 10 });
      setMessage(`Notifications processed: ${result.processed}, sent: ${result.sent}, failed: ${result.failed}.`);
      await loadNotificationJobs();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not process notifications.");
    }
  }

  async function onUpdateSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);

    try {
      const nextSettings = await updateSettings({
        siteName: String(form.get("siteName") ?? ""),
        companyName: String(form.get("companyName") ?? ""),
        tagline: String(form.get("tagline") ?? ""),
        supportEmail: String(form.get("supportEmail") ?? ""),
        maxActiveConversationsPerAgent: Number(form.get("maxActiveConversationsPerAgent")),
        emailNotificationDebounceMinutes: Number(form.get("emailNotificationDebounceMinutes"))
      });
      setSettings(nextSettings);
      setMessage("Settings updated.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not update settings.");
    }
  }

  const selectedConversation =
    conversation?.id === selectedConversationId
      ? conversation
      : conversations.find((item) => item.id === selectedConversationId) ?? null;
  const roleLabel = user?.role.replace("_", " ") ?? "Guest";

  return (
    <main className="appShell">
      <section className="hero">
        <div>
          <p className="eyebrow">{settings?.companyName ?? appConfig.companyName}</p>
          <h1>{settings?.siteName ?? appConfig.siteName}</h1>
        </div>
        <p className="tagline">{settings?.tagline ?? appConfig.tagline}</p>
        <div className="statusRow" data-state={health}>
          <span className="statusDot" />
          <span>{health === "ok" ? "Live" : health === "checking" ? "Checking" : "Offline"}</span>
        </div>
      </section>

      <section className="panel" aria-labelledby="next-title">
        <div className="sectionHeader">
          <h2 id="next-title">{user ? "Session" : mode === "signup" ? "Create Account" : "Log In"}</h2>
          <span className="pill">{roleLabel}</span>
        </div>
        {user ? (
          <div className="stack">
            <p>
              <strong>{user.name}</strong>
              <span className="muted"> {user.email}</span>
            </p>
            <span className="statusBadge" data-status={user.status}>{user.status}</span>
            <button type="button" onClick={onLogout}>
              Log out
            </button>
          </div>
        ) : (
          <form className="stack" onSubmit={onSubmit}>
            {mode === "signup" ? (
              <>
                <label>
                  Name
                  <input name="name" autoComplete="name" required minLength={2} />
                </label>
                <label>
                  Ghana phone
                  <input name="phone" autoComplete="tel" placeholder="+233501234567" required />
                </label>
              </>
            ) : null}
            <label>
              Email
              <input name="email" type="email" autoComplete="email" required />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                required
                minLength={mode === "signup" ? 12 : 1}
              />
            </label>
            <button type="submit">{mode === "signup" ? "Sign up" : "Log in"}</button>
            <button
              type="button"
              className="textButton"
              onClick={() => {
                setMode(mode === "signup" ? "login" : "signup");
                setMessage("");
              }}
            >
              {mode === "signup" ? "Use existing account" : "Create an account"}
            </button>
          </form>
        )}
        {message ? <p className="notice">{message}</p> : null}
      </section>

      {user?.role === "super_admin" ? (
        <section className="panel metricsPanel" aria-label="Workspace summary">
          <div className="metric">
            <strong>{pendingUsers.length}</strong>
            <span>Pending</span>
          </div>
          <div className="metric">
            <strong>{agents.length}</strong>
            <span>Agents</span>
          </div>
          <div className="metric">
            <strong>{customers.length}</strong>
            <span>Customers</span>
          </div>
          <div className="metric">
            <strong>{notificationJobs.length}</strong>
            <span>Jobs</span>
          </div>
        </section>
      ) : null}

      {!user && mode === "login" ? (
        <section className="panel" aria-labelledby="reset-title">
          <h2 id="reset-title">Password Reset</h2>
          <form className="stack" onSubmit={onRequestPasswordReset}>
            <label>
              Email
              <input name="email" type="email" autoComplete="email" required />
            </label>
            <button type="submit" className="secondaryButton">
              Send Reset Email
            </button>
          </form>
          <form className="stack compactForm" onSubmit={onResetPassword}>
            <label>
              Reset token
              <input name="token" required />
            </label>
            <label>
              New password
              <input name="password" type="password" required minLength={12} />
            </label>
            <button type="submit">Reset Password</button>
          </form>
        </section>
      ) : null}

      {user?.role === "super_admin" ? (
        <section className="panel" aria-labelledby="settings-title">
          <div className="sectionHeader">
            <h2 id="settings-title">Settings</h2>
            <button type="button" className="secondaryButton" onClick={() => void getSettings().then(setSettings)}>
              Refresh
            </button>
          </div>
          {settings ? (
            <form className="stack compactForm" onSubmit={onUpdateSettings}>
              <label>
                Site name
                <input name="siteName" defaultValue={settings.siteName} required maxLength={80} />
              </label>
              <label>
                Company
                <input name="companyName" defaultValue={settings.companyName} required maxLength={120} />
              </label>
              <label>
                Tagline
                <input name="tagline" defaultValue={settings.tagline} required maxLength={240} />
              </label>
              <label>
                Support email
                <input name="supportEmail" type="email" defaultValue={settings.supportEmail} required />
              </label>
              <label>
                Max active chats
                <input
                  name="maxActiveConversationsPerAgent"
                  type="number"
                  min={1}
                  max={200}
                  defaultValue={settings.maxActiveConversationsPerAgent}
                  required
                />
              </label>
              <label>
                Email debounce minutes
                <input
                  name="emailNotificationDebounceMinutes"
                  type="number"
                  min={1}
                  max={30}
                  defaultValue={settings.emailNotificationDebounceMinutes}
                  required
                />
              </label>
              <button type="submit">Save Settings</button>
            </form>
          ) : null}
        </section>
      ) : null}

      {user?.role === "super_admin" ? (
        <section className="panel" aria-labelledby="pending-title">
          <div className="sectionHeader">
            <h2 id="pending-title">Pending Customers</h2>
            <button type="button" className="secondaryButton" onClick={loadPendingUsers}>
              Refresh
            </button>
          </div>
          {pendingUsers.length === 0 ? (
            <p>No pending customers.</p>
          ) : (
            <div className="userList">
              {pendingUsers.map((pendingUser) => (
                <article className="userRow" key={pendingUser.id}>
                  <div>
                    <strong>{pendingUser.name}</strong>
                    <p>{pendingUser.email}</p>
                    <p>{pendingUser.phone}</p>
                  </div>
                  <div className="actions">
                    <button type="button" onClick={() => onApprove(pendingUser.id)}>
                      Approve
                    </button>
                    <button
                      type="button"
                      className="dangerButton"
                      onClick={() => onReject(pendingUser.id)}
                    >
                      Reject
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}

      {user?.role === "super_admin" ? (
        <section className="panel" aria-labelledby="agents-title">
          <div className="sectionHeader">
            <h2 id="agents-title">Agents</h2>
            <button type="button" className="secondaryButton" onClick={loadAgents}>
              Refresh
            </button>
          </div>
          <form className="stack compactForm" onSubmit={onCreateAgent}>
            <label>
              Name
              <input name="name" autoComplete="name" required minLength={2} />
            </label>
            <label>
              Email
              <input name="email" type="email" autoComplete="email" required />
            </label>
            <label>
              Phone
              <input name="phone" autoComplete="tel" placeholder="+233501234567" />
            </label>
            <label>
              Temporary password
              <input name="password" type="password" required minLength={12} />
            </label>
            <button type="submit">Create Agent</button>
          </form>
          {agents.length === 0 ? (
            <p>No agents yet.</p>
          ) : (
            <div className="userList">
              {agents.map((agent) => (
                <article className="userRow" key={agent.id}>
                  <div>
                    <strong>{agent.name}</strong>
                    <p>{agent.email}</p>
                    <p>{agent.status}</p>
                  </div>
                  <div className="actions">
                    <button
                      type="button"
                      className="dangerButton"
                      disabled={agent.status === "suspended"}
                      onClick={() => onSuspendUser(agent.id, agent.name)}
                    >
                      Suspend
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}

      {user?.role === "super_admin" ? (
        <section className="panel" aria-labelledby="customers-title">
          <div className="sectionHeader">
            <h2 id="customers-title">Customers</h2>
            <button type="button" className="secondaryButton" onClick={loadCustomers}>
              Refresh
            </button>
          </div>
          {customers.length === 0 ? (
            <p>No customers yet.</p>
          ) : (
            <div className="userList">
              {customers.map((customer) => (
                <article className="userRow" key={customer.id}>
                  <div>
                    <strong>{customer.name}</strong>
                    <p>{customer.email}</p>
                    <p>{customer.status}</p>
                  </div>
                  <div className="actions">
                    <button
                      type="button"
                      className="dangerButton"
                      disabled={customer.status === "suspended"}
                      onClick={() => onSuspendUser(customer.id, customer.name)}
                    >
                      Suspend
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}

      {user?.role === "super_admin" ? (
        <section className="panel" aria-labelledby="notifications-title">
          <div className="sectionHeader">
            <h2 id="notifications-title">Notifications</h2>
            <div className="actions">
              <button type="button" className="secondaryButton" onClick={loadNotificationJobs}>
                Refresh
              </button>
              <button type="button" onClick={onProcessNotifications}>
                Process
              </button>
            </div>
          </div>
          {notificationJobs.length === 0 ? (
            <p>No notification jobs.</p>
          ) : (
            <div className="userList">
              {notificationJobs.map((job) => (
                <article className="userRow" key={job.id}>
                  <div>
                    <strong>{job.type}</strong>
                    <p>{job.status}</p>
                    <p>Attempts: {job.attempts}</p>
                  </div>
                  <p>{new Date(job.createdAt).toLocaleString()}</p>
                </article>
              ))}
            </div>
          )}
        </section>
      ) : null}

      {user?.status === "approved" &&
      (user.role === "customer" || user.role === "super_admin" || user.role === "agent") ? (
        <section className="panel chatPanel" aria-labelledby="chat-title">
          <div className="sectionHeader">
            <h2 id="chat-title">{user.role === "customer" ? "Support Thread" : "Conversations"}</h2>
            {user.role === "super_admin" || user.role === "agent" ? (
              <button type="button" className="secondaryButton" onClick={loadAdminConversations}>
                Refresh
              </button>
            ) : null}
          </div>

          {user.role === "super_admin" || user.role === "agent" ? (
            <div className="conversationList">
              {conversations.length === 0 ? (
                <p>{user.role === "agent" ? "No assigned conversations yet." : "No conversations yet."}</p>
              ) : (
                conversations.map((item) => (
                  <button
                    type="button"
                    className="conversationButton"
                    data-active={item.id === selectedConversationId}
                    key={item.id}
                    onClick={() => setSelectedConversationId(item.id)}
                  >
                    <strong>{item.customerName}</strong>
                    <span>{item.lastMessagePreview ?? item.customerEmail}</span>
                  </button>
                ))
              )}
            </div>
          ) : null}

          {selectedConversationId || conversation ? (
            <>
              {selectedConversation ? (
                <div className="conversationControls">
                  <p>
                    Status: <strong>{selectedConversation.status}</strong>
                    {selectedConversation.closingNote ? ` - ${selectedConversation.closingNote}` : ""}
                  </p>

                  {user.role === "super_admin" ? (
                    <form className="inlineForm" onSubmit={onReassign}>
                      <select
                        name="agentId"
                        defaultValue={selectedConversation.assignedAgentId ?? ""}
                        aria-label="Assigned agent"
                      >
                        <option value="">Unassigned</option>
                        {agents.map((agent) => (
                          <option value={agent.id} key={agent.id}>
                            {agent.name}
                          </option>
                        ))}
                      </select>
                      <button type="submit" className="secondaryButton">
                        Reassign
                      </button>
                    </form>
                  ) : null}

                  {selectedConversation.status === "closed" ? (
                    <button type="button" className="secondaryButton" onClick={onReopenConversation}>
                      Reopen
                    </button>
                  ) : user.role !== "customer" ? (
                    <form className="inlineForm" onSubmit={onCloseConversation}>
                      <input name="note" placeholder="Closing note" required maxLength={1000} />
                      <button type="submit">Close</button>
                    </form>
                  ) : null}
                </div>
              ) : null}

              <div className="messageList" aria-live="polite">
                {messages.length === 0 ? (
                  <p>No messages yet.</p>
                ) : (
                  messages.map((item) => (
                    <article
                      className="messageBubble"
                      data-own={item.senderId === user.id}
                      key={item.id}
                    >
                      <strong>{item.senderName}</strong>
                      <p>{item.body}</p>
                    </article>
                  ))
                )}
              </div>
              <form className="messageForm" onSubmit={onSendMessage}>
                <input
                  name="body"
                  placeholder={
                    selectedConversation?.status === "closed"
                      ? "Reopen this conversation before sending"
                      : "Type a message"
                  }
                  required
                  maxLength={5000}
                  disabled={selectedConversation?.status === "closed"}
                />
                <button type="submit" disabled={selectedConversation?.status === "closed"}>
                  Send
                </button>
              </form>
            </>
          ) : null}
        </section>
      ) : null}
    </main>
  );
}
