import type { NotificationJob } from "@evbus/shared";
import { Bell, RefreshCw } from "lucide-react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";

type NotificationsPageProps = {
  jobs: NotificationJob[];
  onProcess: () => void;
  onRefresh: () => void;
};

export function NotificationsPage({ jobs, onProcess, onRefresh }: NotificationsPageProps) {
  return (
    <Card className="grid h-full min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5 text-primary" />
              Notifications
            </CardTitle>
            <CardDescription>Queued delivery work and manual processing.</CardDescription>
          </div>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
            <Button type="button" size="sm" onClick={onProcess}>
              Process
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid min-h-0 gap-2 overflow-auto p-3">
        {jobs.length === 0 ? (
          <p className="text-sm text-muted-foreground">No notification jobs.</p>
        ) : (
          jobs.map((job) => (
            <div className="grid gap-1 rounded-md border border-border bg-background p-3 text-sm sm:grid-cols-[1fr_auto]" key={job.id}>
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
  );
}
