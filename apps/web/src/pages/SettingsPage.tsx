import type { FormEvent } from "react";
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
    <Card>
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5 text-primary" />
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
        <CardContent className="p-3">
          <form className="grid gap-3 md:grid-cols-2" onSubmit={onSubmit}>
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
  );
}
