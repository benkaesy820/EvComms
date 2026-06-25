import type { ComponentType, ReactNode } from "react";
import type { PublicUser } from "@evbus/shared";
import {
  Bell,
  LogOut,
  MessageSquareText,
  Settings,
  UserCheck,
  Users
} from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";

export type AppPage = "conversations" | "approvals" | "agents" | "customers" | "notifications" | "settings";

type NavItem = {
  count?: number;
  icon: ComponentType<{ className?: string }>;
  id: AppPage;
  label: string;
  roles: PublicUser["role"][];
};

type AppLayoutProps = {
  activePage: AppPage;
  children: ReactNode;
  companyName: string;
  counts: {
    agents: number;
    conversations: number;
    customers: number;
    departments: number;
    notifications: number;
    pending: number;
  };
  health: "checking" | "ok" | "error";
  onNavigate: (page: AppPage) => void;
  onLogout: () => void;
  siteName: string;
  user: PublicUser;
};

export function AppLayout({
  activePage,
  children,
  companyName,
  counts,
  health,
  onLogout,
  onNavigate,
  siteName,
  user
}: AppLayoutProps) {
  const roleLabel = user.role.replace("_", " ");
  const navItems: NavItem[] = [
    {
      count: counts.conversations,
      icon: MessageSquareText,
      id: "conversations",
      label: "Conversations",
      roles: ["customer", "agent", "super_admin"]
    },
    { count: counts.pending, icon: UserCheck, id: "approvals", label: "Approvals", roles: ["super_admin"] },
    { count: counts.agents, icon: Users, id: "agents", label: "Agents", roles: ["super_admin"] },
    { count: counts.customers, icon: Users, id: "customers", label: "Customers", roles: ["super_admin"] },
    {
      count: counts.notifications,
      icon: Bell,
      id: "notifications",
      label: "Notifications",
      roles: ["super_admin"]
    },
    { count: counts.departments, icon: Settings, id: "settings", label: "Settings", roles: ["super_admin"] }
  ];
  const visibleNavItems = navItems.filter((item) => item.roles.includes(user.role));

  return (
    <main className="grid h-svh overflow-hidden bg-[#eef3ef] text-foreground lg:grid-cols-[220px_minmax(0,1fr)]">
      <aside className="hidden border-r border-border bg-[#f7faf7] lg:grid lg:grid-rows-[auto_1fr_auto]">
        <div className="border-b border-border px-3 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-primary text-xs font-bold text-primary-foreground">
              EV
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                {companyName}
              </p>
              <h1 className="truncate text-sm font-semibold leading-tight">{siteName}</h1>
            </div>
          </div>
        </div>

        <nav className="grid content-start gap-1 px-3 py-3" aria-label="Workspace">
          {visibleNavItems
            .map(({ count, icon: Icon, id, label }) => (
              <button
                type="button"
                className="flex h-9 w-full min-w-0 items-center justify-between rounded-md px-3 text-sm font-semibold transition data-[active=true]:bg-primary data-[active=true]:text-primary-foreground data-[active=false]:text-muted-foreground data-[active=false]:hover:bg-white data-[active=false]:hover:text-foreground"
                data-active={activePage === id}
                key={id}
                onClick={() => onNavigate(id)}
              >
                <span className="inline-flex min-w-0 items-center gap-2">
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="truncate">{label}</span>
                </span>
                {typeof count === "number" ? (
                  <span className="shrink-0 rounded-full bg-black/5 px-2 py-0.5 text-[11px]">{count}</span>
                ) : null}
              </button>
            ))}
        </nav>

        <div className="min-w-0 border-t border-border p-2.5">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">{user.name}</p>
            <p className="truncate text-xs text-muted-foreground">{user.email}</p>
          </div>
          <div className="mt-2 flex min-w-0 flex-wrap items-center gap-1.5">
            <HealthBadge health={health} />
            <Badge variant="outline" className="capitalize">{roleLabel}</Badge>
          </div>
        </div>
      </aside>

      <section className="grid min-h-0 grid-rows-[52px_auto_minmax(0,1fr)] lg:grid-rows-[52px_minmax(0,1fr)]">
        <header className="flex items-center justify-between gap-3 border-b border-border bg-white px-4">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">{activeTitle(activePage)}</p>
            <p className="truncate text-xs text-muted-foreground">{siteName} support operations</p>
          </div>
          <div className="flex items-center gap-2">
            <HealthBadge health={health} />
            <Badge variant="outline" className="hidden capitalize sm:inline-flex">{roleLabel}</Badge>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-8 px-3"
              onClick={onLogout}
              aria-label="Log out"
            >
              <LogOut className="h-4 w-4" />
              <span className="hidden sm:inline">Log out</span>
            </Button>
          </div>
        </header>

        <nav
          className="flex gap-1.5 overflow-x-auto border-b border-border bg-[#f7faf7] px-2 py-2 [scrollbar-width:none] lg:hidden [&::-webkit-scrollbar]:hidden"
          aria-label="Workspace"
        >
          {visibleNavItems.map(({ count, icon: Icon, id, label }) => (
            <button
              type="button"
              className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-md px-2.5 text-sm font-semibold transition data-[active=true]:bg-primary data-[active=true]:text-primary-foreground data-[active=false]:bg-white data-[active=false]:text-muted-foreground"
              data-active={activePage === id}
              key={id}
              onClick={() => onNavigate(id)}
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span>{label}</span>
              {typeof count === "number" ? (
                <span className="rounded-full bg-black/5 px-2 py-0.5 text-[11px]">{count}</span>
              ) : null}
            </button>
          ))}
        </nav>

        <div className="min-h-0 min-w-0 overflow-hidden p-1.5 md:p-2">{children}</div>
      </section>
    </main>
  );
}

function activeTitle(page: AppPage) {
  const labels: Record<AppPage, string> = {
    approvals: "Approvals",
    agents: "Agents",
    conversations: "Conversations",
    customers: "Customers",
    notifications: "Notifications",
    settings: "Settings"
  };
  return labels[page];
}

function HealthBadge({ health }: { health: AppLayoutProps["health"] }) {
  return (
    <Badge variant={health === "ok" ? "success" : health === "checking" ? "secondary" : "warning"}>
      {health === "ok" ? "Live" : health === "checking" ? "Checking" : "Offline"}
    </Badge>
  );
}
