import {
  appConfig,
  type Conversation,
  type ConversationSummary,
  type Message,
  type NotificationJob,
  type PublicUser
} from "@evbus/shared";
import { type ComponentType, type FormEvent, type ReactNode, useEffect, useState } from "react";
import {
  Bell,
  Building2,
  LogOut,
  MessageSquareText,
  RefreshCw,
  Send,
  Settings,
  ShieldCheck,
  UserCheck,
  Users
} from "lucide-react";
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
import { AuthPage } from "./AuthPage";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Input } from "./components/ui/input";
import { LandingPage } from "./LandingPage";

type HealthState = "checking" | "ok" | "error";
type Mode = "login" | "signup";
type PublicView = "home" | "auth";
type AppSettings = Awaited<ReturnType<typeof getSettings>>;
type WorkspaceNavItem = {
  count: number;
  href: string;
  icon: ComponentType<{ className?: string }>;
  label: string;
};

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
    setPublicView("home");
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
  const roleLabel = user?.role.replace("_", " ") ?? "Guest";
  const siteName = settings?.siteName ?? appConfig.siteName;
  const companyName = settings?.companyName ?? appConfig.companyName;
  const tagline = settings?.tagline ?? appConfig.tagline;
  const supportEmail = settings?.supportEmail;
  const subsidiaries = settings?.subsidiaries.length ? settings.subsidiaries : defaultSubsidiaries;
  const departments = settings?.departments.length ? settings.departments : defaultDepartments;
  const navItems: WorkspaceNavItem[] = [
    {
      count: conversations.length || (conversation ? 1 : 0),
      href: "#conversations",
      icon: MessageSquareText,
      label: "Conversations"
    },
    { count: pendingUsers.length, href: "#approvals", icon: UserCheck, label: "Approvals" },
    { count: agents.length + customers.length, href: "#people", icon: Users, label: "People" },
    { count: notificationJobs.length, href: "#notifications", icon: Bell, label: "Notifications" },
    { count: departments.length, href: "#settings", icon: Settings, label: "Settings" }
  ];

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

  return (
    <main className="min-h-svh bg-[#f6f8f5] text-foreground">
      <header className="sticky top-0 z-20 border-b border-border bg-white/88 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 md:px-6">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-md bg-primary text-sm font-bold text-primary-foreground">
              EV
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">{companyName}</p>
              <h1 className="text-lg font-semibold leading-tight">{siteName} Workspace</h1>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={health === "ok" ? "success" : health === "checking" ? "secondary" : "warning"}>
              {health === "ok" ? "Live" : health === "checking" ? "Checking" : "Offline"}
            </Badge>
            <Badge variant="outline" className="capitalize">{roleLabel}</Badge>
            <Button type="button" variant="outline" size="sm" onClick={onLogout}>
              <LogOut className="h-4 w-4" />
              Log out
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto grid w-full max-w-7xl gap-4 px-4 py-4 md:px-6 lg:grid-cols-[220px_minmax(0,1fr)_300px]">
        <aside className="hidden lg:block">
          <nav className="sticky top-[76px] grid gap-2" aria-label="Workspace">
            {navItems.map(({ count, href, icon: Icon, label }) => {
              if (user.role !== "super_admin" && label !== "Conversations") return null;
              return (
                <a
                  className="flex items-center justify-between rounded-md border border-transparent px-3 py-2 text-sm font-semibold text-muted-foreground transition hover:border-border hover:bg-white hover:text-foreground"
                  href={href}
                  key={label}
                >
                  <span className="inline-flex items-center gap-2">
                    <Icon className="h-4 w-4" />
                    {label}
                  </span>
                  <span className="text-xs">{count}</span>
                </a>
              );
            })}
          </nav>
        </aside>

        <div className="grid min-w-0 gap-4">
          {message ? (
            <p className="rounded-md border border-primary/20 bg-primary/10 px-3 py-2 text-sm font-medium text-primary">
              {message}
            </p>
          ) : null}

          {user.role === "super_admin" ? (
            <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Workspace summary">
              <Metric icon={<UserCheck className="h-4 w-4" />} label="Pending" value={pendingUsers.length} />
              <Metric icon={<Users className="h-4 w-4" />} label="Agents" value={agents.length} />
              <Metric icon={<Users className="h-4 w-4" />} label="Customers" value={customers.length} />
              <Metric icon={<Bell className="h-4 w-4" />} label="Jobs" value={notificationJobs.length} />
            </section>
          ) : null}

          {user.status === "approved" ? (
            <Card id="conversations" className="overflow-hidden">
              <CardHeader className="border-b border-border">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <CardTitle>{user.role === "customer" ? "Support Thread" : "Conversation Workspace"}</CardTitle>
                    <CardDescription>
                      {user.role === "customer"
                        ? "Your direct line to the Ev Bus team."
                        : "Inbox first: pick a customer, reply, close, or reassign."}
                    </CardDescription>
                  </div>
                  {user.role === "super_admin" || user.role === "agent" ? (
                    <Button type="button" variant="outline" size="sm" onClick={loadAdminConversations}>
                      <RefreshCw className="h-4 w-4" />
                      Refresh
                    </Button>
                  ) : null}
                </div>
              </CardHeader>
              <CardContent className="grid gap-0 p-0 xl:grid-cols-[280px_minmax(0,1fr)]">
                {user.role === "super_admin" || user.role === "agent" ? (
                  <div className="border-b border-border bg-muted/40 p-3 xl:border-b-0 xl:border-r">
                    <div className="mb-3 flex items-center justify-between">
                      <span className="text-sm font-semibold">Inbox</span>
                      <Badge variant="secondary">{conversations.length}</Badge>
                    </div>
                    <div className="grid max-h-[420px] gap-2 overflow-auto pr-1">
                      {conversations.length === 0 ? (
                        <p className="rounded-md border border-dashed border-border bg-background p-3 text-sm text-muted-foreground">
                          {user.role === "agent" ? "No assigned conversations yet." : "No conversations yet."}
                        </p>
                      ) : (
                        conversations.map((item) => (
                          <button
                            type="button"
                            className="grid gap-1 rounded-md border border-border bg-background p-3 text-left text-sm transition hover:border-primary/40 hover:bg-white data-[active=true]:border-primary data-[active=true]:bg-primary/10"
                            data-active={item.id === selectedConversationId}
                            key={item.id}
                            onClick={() => setSelectedConversationId(item.id)}
                          >
                            <strong className="truncate">{item.customerName}</strong>
                            <span className="truncate text-muted-foreground">
                              {item.lastMessagePreview ?? item.customerEmail}
                            </span>
                          </button>
                        ))
                      )}
                    </div>
                  </div>
                ) : null}

                <div className="grid min-w-0 gap-3 p-3">
                  {selectedConversation ? (
                    <div className="grid gap-3 rounded-md border border-border bg-muted/30 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold">
                            Status: <span className="capitalize">{selectedConversation.status}</span>
                          </p>
                          {selectedConversation.closingNote ? (
                            <p className="mt-1 text-sm text-muted-foreground">{selectedConversation.closingNote}</p>
                          ) : null}
                        </div>

                        {selectedConversation.status === "closed" ? (
                          <Button type="button" variant="outline" size="sm" onClick={onReopenConversation}>
                            Reopen
                          </Button>
                        ) : null}
                      </div>

                      {user.role === "super_admin" ? (
                        <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onReassign}>
                          <select
                            name="agentId"
                            className="h-10 rounded-md border border-input bg-background px-3 text-sm"
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
                          <Button type="submit" variant="outline">Reassign</Button>
                        </form>
                      ) : null}

                      {selectedConversation.status !== "closed" && user.role !== "customer" ? (
                        <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onCloseConversation}>
                          <Input name="note" placeholder="Closing note" required maxLength={1000} />
                          <Button type="submit">Close</Button>
                        </form>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="grid min-h-[360px] max-h-[560px] content-start gap-3 overflow-auto rounded-md border border-border bg-[#fbfcfa] p-3">
                    {messages.length === 0 ? (
                      <p className="self-center justify-self-center text-sm text-muted-foreground">No messages yet.</p>
                    ) : (
                      messages.map((item) => (
                        <article
                          className="grid w-[min(86%,640px)] gap-1 rounded-md border border-border bg-white px-3 py-2 text-sm shadow-sm data-[own=true]:justify-self-end data-[own=true]:border-primary/30 data-[own=true]:bg-primary/10"
                          data-own={item.senderId === user.id}
                          key={item.id}
                        >
                          <strong className="text-xs text-muted-foreground">{item.senderName}</strong>
                          <p className="leading-6">{item.body}</p>
                        </article>
                      ))
                    )}
                  </div>

                  <form className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]" onSubmit={onSendMessage}>
                    <Input
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
                    <Button type="submit" disabled={selectedConversation?.status === "closed"}>
                      <Send className="h-4 w-4" />
                      Send
                    </Button>
                  </form>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Account pending</CardTitle>
                <CardDescription>Your account must be approved before the support thread opens.</CardDescription>
              </CardHeader>
            </Card>
          )}

          {user.role === "super_admin" ? (
            <>
              <Card id="approvals">
                <CardHeader className="border-b border-border">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <CardTitle>Pending Customers</CardTitle>
                      <CardDescription>Approve or reject access requests.</CardDescription>
                    </div>
                    <Button type="button" variant="outline" size="sm" onClick={loadPendingUsers}>
                      <RefreshCw className="h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-2 p-3">
                  {pendingUsers.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No pending customers.</p>
                  ) : (
                    pendingUsers.map((pendingUser) => (
                      <div
                        className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-background p-3"
                        key={pendingUser.id}
                      >
                        <div className="min-w-0">
                          <strong>{pendingUser.name}</strong>
                          <p className="truncate text-sm text-muted-foreground">{pendingUser.email}</p>
                          <p className="text-sm text-muted-foreground">{pendingUser.phone}</p>
                        </div>
                        <div className="flex gap-2">
                          <Button type="button" size="sm" onClick={() => onApprove(pendingUser.id)}>
                            Approve
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="destructive"
                            onClick={() => onReject(pendingUser.id)}
                          >
                            Reject
                          </Button>
                        </div>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>

              <section id="people" className="grid gap-4 xl:grid-cols-2">
                <Card>
                  <CardHeader className="border-b border-border">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <CardTitle>Agents</CardTitle>
                        <CardDescription>Create and manage support staff.</CardDescription>
                      </div>
                      <Button type="button" variant="outline" size="sm" onClick={loadAgents}>
                        <RefreshCw className="h-4 w-4" />
                        Refresh
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="grid gap-3 p-3">
                    <form className="grid gap-2 sm:grid-cols-2" onSubmit={onCreateAgent}>
                      <Input name="name" autoComplete="name" placeholder="Name" required minLength={2} />
                      <Input name="email" type="email" autoComplete="email" placeholder="Email" required />
                      <Input name="phone" autoComplete="tel" placeholder="+233501234567" />
                      <Input name="password" type="password" placeholder="Temporary password" required minLength={12} />
                      <Button type="submit" className="sm:col-span-2">Create Agent</Button>
                    </form>
                    <PeopleList people={agents} onSuspend={onSuspendUser} />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="border-b border-border">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <CardTitle>Customers</CardTitle>
                        <CardDescription>Review approved customers and suspensions.</CardDescription>
                      </div>
                      <Button type="button" variant="outline" size="sm" onClick={loadCustomers}>
                        <RefreshCw className="h-4 w-4" />
                        Refresh
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="p-3">
                    <PeopleList people={customers} onSuspend={onSuspendUser} />
                  </CardContent>
                </Card>
              </section>

              <Card id="notifications">
                <CardHeader className="border-b border-border">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <CardTitle>Notifications</CardTitle>
                      <CardDescription>Queued delivery work and manual processing.</CardDescription>
                    </div>
                    <div className="flex gap-2">
                      <Button type="button" variant="outline" size="sm" onClick={loadNotificationJobs}>
                        <RefreshCw className="h-4 w-4" />
                        Refresh
                      </Button>
                      <Button type="button" size="sm" onClick={onProcessNotifications}>
                        Process
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-2 p-3">
                  {notificationJobs.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No notification jobs.</p>
                  ) : (
                    notificationJobs.map((job) => (
                      <div
                        className="grid gap-1 rounded-md border border-border bg-background p-3 text-sm sm:grid-cols-[1fr_auto]"
                        key={job.id}
                      >
                        <div>
                          <strong>{job.type}</strong>
                          <p className="text-muted-foreground">
                            {job.status} - attempts: {job.attempts}
                          </p>
                        </div>
                        <p className="text-muted-foreground">{new Date(job.createdAt).toLocaleString()}</p>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>

              <Card id="settings">
                <CardHeader className="border-b border-border">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <CardTitle>Settings</CardTitle>
                      <CardDescription>Brand, routing labels, capacity, and notification timing.</CardDescription>
                    </div>
                    <Button type="button" variant="outline" size="sm" onClick={() => void getSettings().then(setSettings)}>
                      <RefreshCw className="h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                </CardHeader>
                {settings ? (
                  <CardContent className="p-3">
                    <form className="grid gap-3 md:grid-cols-2" onSubmit={onUpdateSettings}>
                      <Input name="siteName" defaultValue={settings.siteName} required maxLength={80} />
                      <Input name="companyName" defaultValue={settings.companyName} required maxLength={120} />
                      <Input name="tagline" defaultValue={settings.tagline} required maxLength={240} />
                      <Input name="supportEmail" type="email" defaultValue={settings.supportEmail} required />
                      <Input
                        name="subsidiaries"
                        defaultValue={settings.subsidiaries.join(", ")}
                        placeholder="Accra Office, Kumasi Office"
                        required
                      />
                      <Input
                        name="departments"
                        defaultValue={settings.departments.join(", ")}
                        placeholder="General Support, Billing, Technical Support"
                        required
                      />
                      <Input
                        name="maxActiveConversationsPerAgent"
                        type="number"
                        min={1}
                        max={200}
                        defaultValue={settings.maxActiveConversationsPerAgent}
                        required
                      />
                      <Input
                        name="emailNotificationDebounceMinutes"
                        type="number"
                        min={1}
                        max={30}
                        defaultValue={settings.emailNotificationDebounceMinutes}
                        required
                      />
                      <Button type="submit" className="md:col-span-2">Save Settings</Button>
                    </form>
                  </CardContent>
                ) : null}
              </Card>
            </>
          ) : null}
        </div>

        <aside className="grid gap-4 self-start lg:sticky lg:top-[76px]">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-primary" />
                Session
              </CardTitle>
              <CardDescription>{user.email}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              <div>
                <p className="font-semibold">{user.name}</p>
                <Badge className="mt-2 capitalize" variant={user.status === "approved" ? "success" : "warning"}>
                  {user.status}
                </Badge>
              </div>
              <Button type="button" variant="outline" onClick={onLogout}>
                <LogOut className="h-4 w-4" />
                Log out
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5 text-primary" />
                Routing Context
              </CardTitle>
              <CardDescription>Configured labels for the next routing pass.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <LabelStack label="Subsidiaries" values={subsidiaries} />
              <LabelStack label="Departments" values={departments} />
            </CardContent>
          </Card>
        </aside>
      </div>
    </main>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <span className="grid h-9 w-9 place-items-center rounded-md bg-primary/10 text-primary">{icon}</span>
        <strong className="text-2xl">{value}</strong>
      </div>
      <p className="mt-2 text-sm font-medium text-muted-foreground">{label}</p>
    </div>
  );
}

function PeopleList({
  onSuspend,
  people
}: {
  onSuspend: (userId: string, label: string) => void;
  people: PublicUser[];
}) {
  if (people.length === 0) {
    return <p className="text-sm text-muted-foreground">No records yet.</p>;
  }

  return (
    <div className="grid gap-2">
      {people.map((person) => (
        <div
          className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-background p-3"
          key={person.id}
        >
          <div className="min-w-0">
            <strong>{person.name}</strong>
            <p className="truncate text-sm text-muted-foreground">{person.email}</p>
            <Badge className="mt-1 capitalize" variant={person.status === "approved" ? "success" : "warning"}>
              {person.status}
            </Badge>
          </div>
          <Button
            type="button"
            size="sm"
            variant="destructive"
            disabled={person.status === "suspended"}
            onClick={() => onSuspend(person.id, person.name)}
          >
            Suspend
          </Button>
        </div>
      ))}
    </div>
  );
}

function LabelStack({ label, values }: { label: string; values: string[] }) {
  return (
    <div>
      <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</p>
      <div className="flex flex-wrap gap-2">
        {values.map((value) => (
          <Badge variant="outline" key={value}>
            {value}
          </Badge>
        ))}
      </div>
    </div>
  );
}
