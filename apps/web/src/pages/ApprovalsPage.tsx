import type { PublicUser } from "@evbus/shared";
import { RefreshCw, UserCheck } from "lucide-react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";

type ApprovalsPageProps = {
  onApprove: (userId: string) => void;
  onRefresh: () => void;
  onReject: (userId: string) => void;
  pendingUsers: PublicUser[];
};

export function ApprovalsPage({ onApprove, onRefresh, onReject, pendingUsers }: ApprovalsPageProps) {
  return (
    <Card className="grid h-full min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-primary" />
              Pending Customers
            </CardTitle>
            <CardDescription>Approve or reject customer access requests.</CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="grid min-h-0 content-start gap-2 overflow-auto p-2.5">
        <div className="rounded-md border border-border bg-[#f7faf7] px-3 py-1.5 text-sm">
          <strong>{pendingUsers.length}</strong>
          <span className="ml-1 text-muted-foreground">waiting for review</span>
        </div>
        {pendingUsers.length === 0 ? (
          <p className="text-sm text-muted-foreground">No pending customers.</p>
        ) : (
          pendingUsers.map((pendingUser) => (
            <div
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-background px-3 py-2"
              key={pendingUser.id}
            >
              <div className="min-w-0">
                <strong>{pendingUser.name}</strong>
                <p className="truncate text-xs text-muted-foreground">{pendingUser.email}</p>
                <p className="text-xs text-muted-foreground">{pendingUser.phone}</p>
              </div>
              <div className="flex gap-2">
                <Button type="button" size="sm" onClick={() => onApprove(pendingUser.id)}>
                  Approve
                </Button>
                <Button type="button" size="sm" variant="destructive" onClick={() => onReject(pendingUser.id)}>
                  Reject
                </Button>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
