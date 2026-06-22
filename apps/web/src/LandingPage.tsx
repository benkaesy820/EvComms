import { ArrowRight, Building2, CheckCircle2, Clock3, MessageSquareText, ShieldCheck } from "lucide-react";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent } from "./components/ui/card";

type LandingPageProps = {
  companyName: string;
  departments: string[];
  health: "checking" | "ok" | "error";
  siteName: string;
  subsidiaries: string[];
  tagline: string;
  onLogin: () => void;
  onSignup: () => void;
};

export function LandingPage({
  companyName,
  departments,
  health,
  siteName,
  subsidiaries,
  tagline,
  onLogin,
  onSignup
}: LandingPageProps) {
  const statusLabel = health === "ok" ? "Live" : health === "checking" ? "Checking" : "Offline";

  return (
    <main className="min-h-svh bg-[#f7f8f5] text-foreground">
      <section className="relative isolate min-h-[92svh] overflow-hidden">
        <img
          alt=""
          className="absolute inset-0 -z-20 h-full w-full object-cover"
          src="https://images.unsplash.com/photo-1544620347-c4fd4a3d5957?auto=format&fit=crop&w=2200&q=84"
        />
        <div className="absolute inset-0 -z-10 bg-[linear-gradient(90deg,rgba(5,18,17,0.90),rgba(5,18,17,0.66)_44%,rgba(5,18,17,0.32))]" />

        <nav className="mx-auto flex w-full max-w-7xl items-center justify-between gap-3 px-4 py-5 text-white md:px-8">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-md border border-white/20 bg-white/10 font-bold">
              EV
            </div>
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.16em] text-white/60">{companyName}</p>
              <strong className="text-base">{siteName}</strong>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge className="border-white/20 bg-white/10 text-white hover:bg-white/10">{statusLabel}</Badge>
            <Button type="button" variant="secondary" onClick={onLogin}>
              Log in
            </Button>
          </div>
        </nav>

        <div className="mx-auto grid min-h-[calc(92svh-88px)] w-full max-w-7xl items-center gap-8 px-4 pb-8 md:grid-cols-[minmax(0,1fr)_420px] md:px-8">
          <div className="max-w-3xl text-white">
            <Badge className="border-teal-200/30 bg-teal-200/15 text-teal-50 hover:bg-teal-200/15">
              Human support for customers
            </Badge>
            <h1 className="mt-5 text-5xl font-semibold leading-[0.95] tracking-normal md:text-7xl">
              Support that feels direct, private, and accountable.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-white/76">{tagline}</p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Button type="button" size="lg" onClick={onSignup}>
                Start support
                <ArrowRight className="h-4 w-4" />
              </Button>
              <Button
                type="button"
                size="lg"
                variant="outline"
                className="border-white/30 bg-white/10 text-white hover:bg-white/20 hover:text-white"
                onClick={onLogin}
              >
                Existing account
              </Button>
            </div>
          </div>

          <Card className="border-white/20 bg-white/92 shadow-2xl shadow-black/25 backdrop-blur">
            <CardContent className="grid gap-5 p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.14em] text-primary">Support desk</p>
                  <h2 className="mt-2 text-2xl font-semibold">One thread, routed properly.</h2>
                </div>
                <ShieldCheck className="h-6 w-6 text-primary" />
              </div>

              <div className="grid gap-3">
                <PreviewLine icon={<MessageSquareText className="h-4 w-4" />} title="Customer message">
                  "I need help with my booking from Accra."
                </PreviewLine>
                <PreviewLine icon={<Building2 className="h-4 w-4" />} title="Routing context">
                  {departments.slice(0, 2).join(" / ")} - {subsidiaries.slice(0, 2).join(" / ")}
                </PreviewLine>
                <PreviewLine icon={<Clock3 className="h-4 w-4" />} title="Operational promise">
                  Approval first, then one persistent conversation.
                </PreviewLine>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-7xl gap-4 px-4 py-5 md:grid-cols-3 md:px-8">
        {[
          ["Request help", "Customers apply once, then message the team when approved."],
          ["Keep history", "Replies, closure notes, and promises stay in one support thread."],
          ["Respect branches", "Subsidiaries and departments are configured, not hardcoded."]
        ].map(([title, body]) => (
          <Card key={title} className="border-border/80">
            <CardContent className="flex gap-3 p-5">
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
              <div>
                <h2 className="font-semibold">{title}</h2>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{body}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </section>
    </main>
  );
}

function PreviewLine({
  children,
  icon,
  title
}: {
  children: React.ReactNode;
  icon: React.ReactNode;
  title: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
        {icon}
        {title}
      </div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{children}</p>
    </div>
  );
}
