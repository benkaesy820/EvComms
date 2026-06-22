import type { ComponentType, ReactNode } from "react";
import type { PublicUser } from "@evbus/shared";
import {
  Bell,
  Building2,
  LogOut,
  MessageSquareText,
  Settings,
  ShieldCheck,
  UserCheck,
  Users
} from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";

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
  departments: string[];
  health: "checking" | "ok" | "error";
  onNavigate: (page: AppPage) => void;
  onLogout: () => void;
  siteName: string;
  subsidiaries: string[];
  user: PublicUser;
};

export function AppLayout({
  activePage,
  children,
  companyName,
  counts,
  departments,
  health,
  onLogout,
  onNavigate,
  siteName,
  subsidiaries,
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

  return (
    <main className="min-h-svh bg-[#f6f8f5] text-foreground">
      <header className="sticky top-0 z-30 border-b border-border bg-white/90 backdrop-blur">
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
            <HealthBadge health={health} />
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
            {navItems
              .filter((item) => item.roles.includes(user.role))
              .map(({ count, icon: Icon, id, label }) => (
                <button
                  type="button"
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-sm font-semibold transition data-[active=true]:border-primary data-[active=true]:bg-primary/10 data-[active=false]:border-transparent data-[active=false]:text-muted-foreground data-[active=false]:hover:border-border data-[active=false]:hover:bg-white data-[active=false]:hover:text-foreground"
                  data-active={activePage === id}
                  key={id}
                  onClick={() => onNavigate(id)}
                >
                  <span className="inline-flex items-center gap-2">
                    <Icon className="h-4 w-4" />
                    {label}
                  </span>
                  {typeof count === "number" ? <span className="text-xs">{count}</span> : null}
                </button>
              ))}
          </nav>
        </aside>

        <div className="min-w-0">{children}</div>

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

function HealthBadge({ health }: { health: AppLayoutProps["health"] }) {
  return (
    <Badge variant={health === "ok" ? "success" : health === "checking" ? "secondary" : "warning"}>
      {health === "ok" ? "Live" : health === "checking" ? "Checking" : "Offline"}
    </Badge>
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
