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
  getMessages,
  getMyConversation,
  getNotificationJobs,
  getPendingUsers,
  getSettings,
  login,
  logout,
  processNotificationJobs,
  reassignConversation,
  register,
  rejectUser,
  reopenConversation,
  requestPasswordReset,
  resetPassword,
  sendMessage,
  suspendUser,
  updateSettings
} from "./api";
import { AuthPage } from "./AuthPage";
import { AppLayout, type AppPage } from "./layouts/AppLayout";
import { LandingPage } from "./LandingPage";
import { AccountStatePage } from "./pages/AccountStatePage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { ConversationsPage } from "./pages/ConversationsPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { AgentsPage, CustomersPage } from "./pages/PeoplePages";
import { SettingsPage } from "./pages/SettingsPage";

type HealthState = "checking" | "ok" | "error";
type Mode = "login" | "signup";
type PublicView = "home" | "auth";
type AppSettings = Awaited<ReturnType<typeof getSettings>>;

const defaultSubsidiaries = ["Accra Office", "Kumasi Office"];
const defaultDepartments = ["General Support", "Billing", "Technical Support"];

function splitList(value: FormDataEntryValue | null) {
  return String(value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function App() {
  const [health, setHealth] = useState<HealthState>("checking");
  const [mode, setMode] = useState<Mode>("signup");
  const [publicView, setPublicView] = useState<PublicView>("home");
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
  const [activePage, setActivePage] = useState<AppPage>("conversations");

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
      setActivePage("conversations");
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
    if (user?.role !== "super_admin" && activePage !== "conversations") {
      setActivePage("conversations");
    }
  }, [activePage, user?.role]);

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
    setPublicView("home");
    setActivePage("conversations");
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
        subsidiaries: splitList(form.get("subsidiaries")),
        departments: splitList(form.get("departments")),
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
  const siteName = settings?.siteName ?? appConfig.siteName;
  const companyName = settings?.companyName ?? appConfig.companyName;
  const tagline = settings?.tagline ?? appConfig.tagline;
  const supportEmail = settings?.supportEmail;
  const subsidiaries = settings?.subsidiaries.length ? settings.subsidiaries : defaultSubsidiaries;
  const departments = settings?.departments.length ? settings.departments : defaultDepartments;

  if (!user && publicView === "home") {
    return (
      <LandingPage
        companyName={companyName}
        departments={departments}
        health={health}
        siteName={siteName}
        subsidiaries={subsidiaries}
        tagline={tagline}
        onLogin={() => {
          setMode("login");
          setPublicView("auth");
        }}
        onSignup={() => {
          setMode("signup");
          setPublicView("auth");
        }}
      />
    );
  }

  if (!user) {
    return (
      <AuthPage
        companyName={companyName}
        message={message}
        mode={mode}
        siteName={siteName}
        supportEmail={supportEmail}
        tagline={tagline}
        onBackHome={() => {
          setPublicView("home");
          setMessage("");
        }}
        onModeChange={(nextMode) => {
          setMode(nextMode);
          setMessage("");
        }}
        onRequestPasswordReset={onRequestPasswordReset}
        onResetPassword={onResetPassword}
        onSubmit={onSubmit}
      />
    );
  }

  const conversationCount = conversations.length || (conversation ? 1 : 0);

  return (
    <AppLayout
      activePage={activePage}
      companyName={companyName}
      counts={{
        agents: agents.length,
        conversations: conversationCount,
        customers: customers.length,
        departments: departments.length,
        notifications: notificationJobs.length,
        pending: pendingUsers.length
      }}
      health={health}
      siteName={siteName}
      user={user}
      onLogout={onLogout}
      onNavigate={setActivePage}
    >
      <div className="grid h-full min-h-0 gap-4">
        {message ? (
          <p className="rounded-md border border-primary/20 bg-primary/10 px-3 py-2 text-sm font-medium text-primary">
            {message}
          </p>
        ) : null}
        {user.status !== "approved" ? (
          <AccountStatePage user={user} />
        ) : activePage === "conversations" ? (
          <ConversationsPage
            agents={agents}
            conversations={conversations}
            messages={messages}
            selectedConversation={selectedConversation}
            selectedConversationId={selectedConversationId}
            user={user}
            onCloseConversation={onCloseConversation}
            onReassign={onReassign}
            onRefresh={loadAdminConversations}
            onReopenConversation={onReopenConversation}
            onSelectConversation={setSelectedConversationId}
            onSendMessage={onSendMessage}
          />
        ) : activePage === "approvals" && user.role === "super_admin" ? (
          <ApprovalsPage
            pendingUsers={pendingUsers}
            onApprove={onApprove}
            onRefresh={loadPendingUsers}
            onReject={onReject}
          />
        ) : activePage === "agents" && user.role === "super_admin" ? (
          <AgentsPage
            people={agents}
            onCreateAgent={onCreateAgent}
            onRefresh={loadAgents}
            onSuspend={onSuspendUser}
          />
        ) : activePage === "customers" && user.role === "super_admin" ? (
          <CustomersPage people={customers} onRefresh={loadCustomers} onSuspend={onSuspendUser} />
        ) : activePage === "notifications" && user.role === "super_admin" ? (
          <NotificationsPage
            jobs={notificationJobs}
            onProcess={onProcessNotifications}
            onRefresh={loadNotificationJobs}
          />
        ) : activePage === "settings" && user.role === "super_admin" ? (
          <SettingsPage
            settings={settings}
            onRefresh={() => void getSettings().then(setSettings)}
            onSubmit={onUpdateSettings}
          />
        ) : (
          <ConversationsPage
            agents={agents}
            conversations={conversations}
            messages={messages}
            selectedConversation={selectedConversation}
            selectedConversationId={selectedConversationId}
            user={user}
            onCloseConversation={onCloseConversation}
            onReassign={onReassign}
            onRefresh={loadAdminConversations}
            onReopenConversation={onReopenConversation}
            onSelectConversation={setSelectedConversationId}
            onSendMessage={onSendMessage}
          />
        )}
      </div>
    </AppLayout>
  );
}
