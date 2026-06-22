import type { PublicUser } from "@evbus/shared";
import { Clock3, ShieldAlert } from "lucide-react";
import { Card, CardDescription, CardHeader, CardTitle } from "../components/ui/card";

export function AccountStatePage({ user }: { user: PublicUser }) {
  const isPending = user.status === "pending";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {isPending ? <Clock3 className="h-5 w-5 text-primary" /> : <ShieldAlert className="h-5 w-5 text-destructive" />}
          {isPending ? "Account pending" : "Account unavailable"}
        </CardTitle>
        <CardDescription>
          {isPending
            ? "Your account is waiting for Super Admin approval. The support thread opens once approved."
            : `Your account status is ${user.status}. Contact support if this looks wrong.`}
        </CardDescription>
      </CardHeader>
    </Card>
  );
}
