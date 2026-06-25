import type { FormEvent, ReactNode } from "react";
import { RefreshCw, Settings } from "lucide-react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import type { getSettings } from "../api";

type SettingsValue = Awaited<ReturnType<typeof getSettings>>;

type SettingsPageProps = {
  onRefresh: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  settings: SettingsValue | null;
};

export function SettingsPage({ onRefresh, onSubmit, settings }: SettingsPageProps) {
  return (
    <Card className="grid h-full min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-4 w-4 text-primary" />
              Settings
            </CardTitle>
            <CardDescription>Brand, routing labels, capacity, and notification timing.</CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      {settings ? (
        <CardContent className="min-h-0 overflow-auto p-2.5">
          <form className="grid gap-2.5 md:grid-cols-2 xl:grid-cols-3" onSubmit={onSubmit}>
            <Field label="Site name">
              <Input name="siteName" defaultValue={settings.siteName} required maxLength={80} />
            </Field>
            <Field label="Company name">
              <Input name="companyName" defaultValue={settings.companyName} required maxLength={120} />
            </Field>
            <Field label="Tagline">
              <Input name="tagline" defaultValue={settings.tagline} required maxLength={240} />
            </Field>
            <Field label="Support email">
              <Input name="supportEmail" type="email" defaultValue={settings.supportEmail} required />
            </Field>
            <Field label="Locations">
              <Input
                name="subsidiaries"
                defaultValue={settings.subsidiaries.join(", ")}
                placeholder="Accra Office, Kumasi Office"
                required
              />
            </Field>
            <Field label="Departments">
              <Input
                name="departments"
                defaultValue={settings.departments.join(", ")}
                placeholder="General Support, Billing, Technical Support"
                required
              />
            </Field>
            <Field label="Max active conversations per agent">
              <Input
                name="maxActiveConversationsPerAgent"
                type="number"
                min={1}
                max={200}
                defaultValue={settings.maxActiveConversationsPerAgent}
                required
              />
            </Field>
            <Field label="Max sessions per user">
              <Input
                name="maxActiveSessionsPerUser"
                type="number"
                min={1}
                max={10}
                defaultValue={settings.maxActiveSessionsPerUser}
                required
              />
            </Field>
            <Field label="Max image MB">
              <Input
                name="maxImageSizeMb"
                type="number"
                min={1}
                max={25}
                defaultValue={settings.maxImageSizeMb}
                required
              />
            </Field>
            <Field label="Max document MB">
              <Input
                name="maxDocumentSizeMb"
                type="number"
                min={1}
                max={50}
                defaultValue={settings.maxDocumentSizeMb}
                required
              />
            </Field>
            <Field label="Daily uploads">
              <Input
                name="dailyUploadLimit"
                type="number"
                min={1}
                max={500}
                defaultValue={settings.dailyUploadLimit}
                required
              />
            </Field>
            <Field label="Notification debounce minutes">
              <Input
                name="emailNotificationDebounceMinutes"
                type="number"
                min={1}
                max={30}
                defaultValue={settings.emailNotificationDebounceMinutes}
                required
              />
            </Field>
            <label className="flex min-h-9 items-center justify-between gap-3 rounded-md border border-border bg-background px-3 text-sm font-semibold text-foreground">
              <span>Push notifications</span>
              <input
                name="pushNotificationsEnabled"
                type="checkbox"
                defaultChecked={settings.pushNotificationsEnabled}
                className="h-4 w-4 accent-primary"
              />
            </label>
            <Button type="submit" className="md:col-span-2 xl:col-span-3">Save Settings</Button>
          </form>
        </CardContent>
      ) : null}
    </Card>
  );
}

function Field({ children, label }: { children: ReactNode; label: string }) {
  return (
    <label className="grid gap-1.5 text-sm font-semibold text-foreground">
      <span>{label}</span>
      {children}
    </label>
  );
}
