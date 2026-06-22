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
    <Card>
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <UserCheck className="h-5 w-5 text-primary" />
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
