import type { FormEvent } from "react";
import { useState } from "react";
import { ArrowLeft, LockKeyhole, Mail, ShieldCheck, UserRound } from "lucide-react";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Input } from "./components/ui/input";

type AuthMode = "login" | "signup";
type AuthIntent = "access" | "forgot" | "reset";

type AuthPageProps = {
  companyName: string;
  mode: AuthMode;
  message: string;
  siteName: string;
  supportEmail: string | undefined;
  tagline: string;
  onBackHome: () => void;
  onModeChange: (mode: AuthMode) => void;
  onRequestPasswordReset: (event: FormEvent<HTMLFormElement>) => void;
  onResetPassword: (event: FormEvent<HTMLFormElement>) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

export function AuthPage({
  companyName,
  mode,
  message,
  siteName,
  supportEmail,
  tagline,
  onBackHome,
  onModeChange,
  onRequestPasswordReset,
  onResetPassword,
  onSubmit
}: AuthPageProps) {
  const [intent, setIntent] = useState<AuthIntent>("access");
  const isSignup = mode === "signup" && intent === "access";

  return (
    <main className="min-h-svh bg-[radial-gradient(circle_at_top_left,rgba(13,148,136,0.16),transparent_32%),linear-gradient(135deg,#f8fafc,#eef7f3_46%,#f7f4ed)] text-foreground">
      <div className="mx-auto grid min-h-svh w-full max-w-6xl gap-8 px-4 py-5 md:grid-cols-[minmax(0,0.92fr)_minmax(380px,0.68fr)] md:px-8">
        <section className="flex min-h-[42vh] flex-col justify-between rounded-lg border border-white/70 bg-white/55 p-5 shadow-sm backdrop-blur md:min-h-0 md:p-7">
          <div className="flex items-center justify-between gap-3">
            <button
              type="button"
              className="inline-flex items-center gap-2 text-sm font-semibold text-muted-foreground transition hover:text-foreground"
              onClick={onBackHome}
            >
              <ArrowLeft className="h-4 w-4" />
              Back
            </button>
            <Badge variant="success">Secure access</Badge>
          </div>

          <div className="max-w-xl">
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-primary">{companyName}</p>
            <h1 className="mt-4 text-4xl font-semibold tracking-normal text-foreground md:text-6xl">
              One account for every support conversation.
            </h1>
            <p className="mt-5 max-w-lg text-base leading-7 text-muted-foreground">{tagline}</p>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {[
              ["Approval first", "New accounts wait for admin review."],
              ["One thread", "History stays with the customer."],
              ["Private by default", "Only approved users can message."]
            ].map(([title, body]) => (
              <div key={title} className="rounded-lg border border-border bg-background/80 p-4">
                <strong className="text-sm text-foreground">{title}</strong>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{body}</p>
              </div>
            ))}
          </div>
        </section>

        <Card className="self-center border-white/80 bg-white/90 shadow-xl shadow-slate-950/10 backdrop-blur">
          <CardHeader className="gap-3">
            <div className="flex items-center justify-between gap-3">
              <Badge variant="secondary">{siteName}</Badge>
              <ShieldCheck className="h-5 w-5 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl">
                {intent === "forgot"
                  ? "Request a reset"
                  : intent === "reset"
                    ? "Set a new password"
                    : isSignup
                      ? "Create your account"
                      : "Log in"}
              </CardTitle>
              <CardDescription className="mt-2">
                {intent === "access"
                  ? isSignup
                    ? "Apply for customer access. An admin must approve you before chat opens."
                    : "Use your approved account to continue."
                  : intent === "forgot"
                    ? "Enter your email and we will send a reset token if the account exists."
                    : "Paste the reset token and choose a strong new password."}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="grid gap-5">
            {intent === "access" ? (
              <form className="grid gap-4" onSubmit={onSubmit}>
                {isSignup ? (
                  <>
                    <Field icon={<UserRound className="h-4 w-4" />} label="Name">
                      <Input name="name" autoComplete="name" required minLength={2} />
                    </Field>
                    <Field label="Ghana phone">
                      <Input name="phone" autoComplete="tel" placeholder="+233501234567" required />
                    </Field>
                  </>
                ) : null}
                <Field icon={<Mail className="h-4 w-4" />} label="Email">
                  <Input name="email" type="email" autoComplete="email" required />
                </Field>
                <Field icon={<LockKeyhole className="h-4 w-4" />} label="Password">
                  <Input
                    name="password"
                    type="password"
                    autoComplete={isSignup ? "new-password" : "current-password"}
                    required
                    minLength={isSignup ? 12 : 1}
                  />
                </Field>
                <Button type="submit" size="lg" className="w-full">
                  {isSignup ? "Apply for access" : "Log in"}
                </Button>
              </form>
            ) : null}

            {intent === "forgot" ? (
              <form className="grid gap-4" onSubmit={onRequestPasswordReset}>
                <Field icon={<Mail className="h-4 w-4" />} label="Email">
                  <Input name="email" type="email" autoComplete="email" required />
                </Field>
                <Button type="submit" size="lg" className="w-full">
                  Send reset email
                </Button>
              </form>
            ) : null}

            {intent === "reset" ? (
              <form className="grid gap-4" onSubmit={onResetPassword}>
                <Field label="Reset token">
                  <Input name="token" required />
                </Field>
                <Field icon={<LockKeyhole className="h-4 w-4" />} label="New password">
                  <Input name="password" type="password" required minLength={12} />
                </Field>
                <Button type="submit" size="lg" className="w-full">
                  Reset password
                </Button>
              </form>
            ) : null}

            <div className="grid gap-3 text-sm">
              {message ? (
                <p className="rounded-md border border-primary/20 bg-primary/10 px-3 py-2 font-medium text-primary">
                  {message}
                </p>
              ) : null}
              <div className="flex flex-wrap items-center justify-between gap-3 text-muted-foreground">
                {intent === "access" ? (
                  <>
                    <button
                      type="button"
                      className="font-semibold text-primary hover:underline"
                      onClick={() => onModeChange(isSignup ? "login" : "signup")}
                    >
                      {isSignup ? "Use existing account" : "Create an account"}
                    </button>
                    <button
                      type="button"
                      className="font-semibold text-primary hover:underline"
                      onClick={() => setIntent("forgot")}
                    >
                      Forgot password?
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="font-semibold text-primary hover:underline"
                    onClick={() => setIntent("access")}
                  >
                    Back to login
                  </button>
                )}
                <button
                  type="button"
                  className="font-semibold text-primary hover:underline"
                  onClick={() => setIntent("reset")}
                >
                  I have a reset token
                </button>
              </div>
              {supportEmail ? <p className="text-muted-foreground">Support: {supportEmail}</p> : null}
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}

function Field({
  children,
  icon,
  label
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
  label: string;
}) {
  return (
    <label className="grid gap-2 text-sm font-semibold text-foreground">
      <span className="inline-flex items-center gap-2">
        {icon}
        {label}
      </span>
      {children}
    </label>
  );
}
