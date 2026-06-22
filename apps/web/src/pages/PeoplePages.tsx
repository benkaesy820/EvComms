import type { FormEvent } from "react";
import type { PublicUser } from "@evbus/shared";
import { RefreshCw, Users } from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";

type PeopleListProps = {
  onSuspend: (userId: string, label: string) => void;
  people: PublicUser[];
};

type AgentsPageProps = PeopleListProps & {
  onCreateAgent: (event: FormEvent<HTMLFormElement>) => void;
  onRefresh: () => void;
};

type CustomersPageProps = PeopleListProps & {
  onRefresh: () => void;
};

export function AgentsPage({ onCreateAgent, onRefresh, onSuspend, people }: AgentsPageProps) {
  return (
    <Card>
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Agents
            </CardTitle>
            <CardDescription>Create and manage support staff.</CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
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
        <PeopleList onSuspend={onSuspend} people={people} />
      </CardContent>
    </Card>
  );
}

export function CustomersPage({ onRefresh, onSuspend, people }: CustomersPageProps) {
  return (
    <Card>
      <CardHeader className="border-b border-border">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Customers
            </CardTitle>
            <CardDescription>Review approved customers and suspensions.</CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={onRefresh}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-3">
        <PeopleList onSuspend={onSuspend} people={people} />
      </CardContent>
    </Card>
  );
}

function PeopleList({ onSuspend, people }: PeopleListProps) {
  if (people.length === 0) return <p className="text-sm text-muted-foreground">No records yet.</p>;

  return (
    <div className="grid gap-2">
      {people.map((person) => (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-background p-3" key={person.id}>
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
