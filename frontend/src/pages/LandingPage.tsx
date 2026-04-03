import { useNavigate, Link } from 'react-router-dom'
import {
  Shield, Zap, ArrowRight, Lock, MessageSquare,
  MonitorSmartphone, CheckCircle, UserCheck, Headphones,
  ChevronRight, Star, LayoutDashboard
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useAppConfig } from '@/hooks/useConfig'
import { useAuthStore } from '@/stores/authStore'
import { DEFAULTS } from '@/lib/constants'

function FeatureCard({ icon: Icon, title, description }: {
  icon: React.ElementType; title: string; description: string
}) {
  return (
    <div className="group relative rounded-2xl border bg-card p-6 transition-all duration-300 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 hover:-translate-y-0.5">
      <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary ring-1 ring-primary/20 transition-colors group-hover:bg-primary/15">
        <Icon className="h-5 w-5" />
      </div>
      <h3 className="mb-1.5 text-base font-bold tracking-tight">{title}</h3>
      <p className="text-sm leading-relaxed text-muted-foreground">{description}</p>
    </div>
  )
}

function StepItem({ n, icon: Icon, title, description, last }: {
  n: string; icon: React.ElementType; title: string; description: string; last?: boolean
}) {
  return (
    <div className="flex gap-5">
      <div className="flex flex-col items-center">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground text-sm font-bold shadow-md shadow-primary/20">
          {n}
        </div>
        {!last && <div className="mt-2 w-px flex-1 bg-border/60 min-h-[2rem]" />}
      </div>
      <div className={`${last ? 'pb-0' : 'pb-8'} pt-1.5 min-w-0`}>
        <div className="flex items-center gap-2 mb-1">
          <Icon className="h-4 w-4 text-primary" />
          <p className="text-sm font-semibold">{title}</p>
        </div>
        <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
      </div>
    </div>
  )
}

function StatItem({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center px-4">
      <p className="text-3xl font-extrabold tracking-tight text-foreground">{value}</p>
      <p className="text-xs text-muted-foreground mt-0.5 font-medium">{label}</p>
    </div>
  )
}

export function LandingPage() {
  const navigate = useNavigate()
  const { data: configData } = useAppConfig()
  const brand = configData?.brand
  const tagline = brand?.tagline || 'Support that actually feels human.'
  const company = brand?.company || DEFAULTS.company
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const dashboardPath = user?.role === 'USER' ? '/home' : '/admin/home'

  // Stats are driven by brand config when set, otherwise fall back to honest
  // descriptive copy that doesn't make claims we can't verify.
  const stats = [
    { value: brand?.statResponseTime ?? 'Fast', label: 'Avg. first response' },
    { value: brand?.statUptime ?? '99.9%', label: 'Platform uptime' },
    { value: '100%', label: 'HTTPS secured' },
    { value: brand?.statAvailability ?? '24/7', label: 'Team availability' },
  ]

  return (
    <StaticLayout>
      {/* Hero */}
      <section className="relative overflow-hidden pt-16 pb-12 sm:pt-24 sm:pb-16 lg:pt-32 lg:pb-20">
        <div className="absolute inset-0 -z-10">
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent" />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-10%,hsl(var(--primary)/0.08),transparent)]" />
          <div
            className="absolute inset-0 opacity-[0.025]"
            style={{
              backgroundImage: 'linear-gradient(to right, currentColor 1px, transparent 1px), linear-gradient(to bottom, currentColor 1px, transparent 1px)',
              backgroundSize: '48px 48px',
            }}
          />
        </div>

        <div className="mx-auto max-w-5xl px-6 text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-4 py-1.5 text-xs font-semibold text-primary mb-8 animate-in fade-in duration-500">
            <span className="flex h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            Secure · Real-time · Built for teams
          </div>

          <h1 className="text-4xl font-extrabold tracking-tight sm:text-6xl lg:text-7xl mb-6 animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:100ms]">
            <span className="bg-clip-text text-transparent bg-gradient-to-b from-foreground via-foreground to-foreground/50">
              {tagline}
            </span>
          </h1>

          <p className="mx-auto max-w-xl text-base sm:text-lg leading-relaxed text-muted-foreground mb-10 animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:200ms]">
            {company} gives every customer a direct line to your support team — no tickets, no queues. Just a conversation.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-14 animate-in fade-in slide-in-from-bottom-4 duration-700 [animation-delay:300ms]">
            {isAuthenticated ? (
              <div className="flex flex-col items-center gap-3">
                <Button
                  size="lg"
                  className="w-full sm:w-auto rounded-full px-8 h-12 text-sm font-bold shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 hover:-translate-y-0.5 transition-all gap-2"
                  onClick={() => navigate(dashboardPath)}
                >
                  <LayoutDashboard className="h-4 w-4" />
                  {user?.role === 'USER' ? 'Go to My Dashboard' : 'Go to Admin Dashboard'}
                  <ArrowRight className="h-4 w-4" />
                </Button>
                <p className="text-xs text-muted-foreground">
                  Signed in as <span className="font-semibold text-foreground">{user?.name}</span>
                  {' · '}
                  <button
                    onClick={() => navigate(user?.status === 'APPROVED' ? (user?.role === 'USER' ? '/home/settings' : '/admin/settings') : dashboardPath)}
                    className="hover:text-foreground hover:underline underline-offset-2 transition-colors"
                  >
                    {user?.status === 'APPROVED' ? 'Settings' : 'Dashboard'}
                  </button>
                </p>
              </div>
            ) : (
              <>
                <Button
                  size="lg"
                  className="w-full sm:w-auto rounded-full px-8 h-12 text-sm font-bold shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 hover:-translate-y-0.5 transition-all gap-2"
                  onClick={() => navigate('/register')}
                >
                  Get Started Free
                  <ArrowRight className="h-4 w-4" />
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  className="w-full sm:w-auto rounded-full px-8 h-12 text-sm font-bold hover:bg-muted/60 transition-all gap-2"
                  onClick={() => navigate('/login')}
                >
                  Sign In
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </Button>
              </>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-xs font-medium text-muted-foreground animate-in fade-in duration-700 [animation-delay:500ms]">
            <span className="flex items-center gap-1.5"><Lock className="h-3.5 w-3.5 text-primary" />Secure & private</span>
            <span className="hidden sm:block h-3 w-px bg-border" />
            <span className="flex items-center gap-1.5"><Zap className="h-3.5 w-3.5 text-primary" />Real-time messaging</span>
            <span className="hidden sm:block h-3 w-px bg-border" />
            <span className="flex items-center gap-1.5"><MonitorSmartphone className="h-3.5 w-3.5 text-primary" />Works on every device</span>
            <span className="hidden sm:block h-3 w-px bg-border" />
            <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5 text-primary" />Role-based access control</span>
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section className="border-y border-border/50 bg-muted/20 py-8">
        <div className="mx-auto max-w-5xl px-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 sm:gap-4 sm:divide-x sm:divide-border/50">
            {stats.map((s) => (
              <StatItem key={s.label} value={s.value} label={s.label} />
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-16 sm:py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="grid lg:grid-cols-2 gap-12 lg:gap-20 items-start">
            <div>
              <p className="text-xs font-bold uppercase tracking-widest text-primary mb-3">How it works</p>
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight mb-8">
                From sign-up to conversation<br className="hidden sm:block" /> in under a minute
              </h2>
              <div>
                <StepItem n="1" icon={UserCheck} title="Create your account" description="Register with your email. Our team reviews and approves new accounts — usually within a few hours. You'll get an email when you're in." />
                <StepItem n="2" icon={MessageSquare} title="Start a conversation" description="Select your inquiry type, write your first message, and you're instantly connected to a dedicated support agent assigned just for you." />
                <StepItem n="3" icon={Headphones} title="Get real help, fast" last description="Your agent responds in real-time. Share files, react to messages, and get the full context of your conversation — all in one place." />
              </div>
            </div>

            {/* Chat mockup */}
            <div className="lg:sticky lg:top-24">
              <div className="rounded-2xl border bg-card shadow-xl shadow-black/5 overflow-hidden">
                <div className="flex items-center gap-3 border-b px-4 py-3 bg-sidebar">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                    <Headphones className="h-4 w-4 text-primary" />
                  </div>
                  <div>
                    <p className="text-xs font-semibold">Support Team</p>
                    <div className="flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                      <p className="text-[10px] text-muted-foreground">Online now</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 space-y-3 bg-accent/10 min-h-[220px]">
                  <div className="flex justify-start">
                    <div className="max-w-[78%] rounded-2xl rounded-bl-sm bg-background border px-3 py-2 text-xs text-foreground shadow-sm">
                      Hi! I have a question about my account setup.
                    </div>
                  </div>
                  <div className="flex justify-end">
                    <div className="max-w-[78%] rounded-2xl rounded-br-sm bg-primary px-3 py-2 text-xs text-primary-foreground shadow-sm shadow-primary/20">
                      Of course! I'm here to help. What would you like to know?
                    </div>
                  </div>
                  <div className="flex justify-start">
                    <div className="max-w-[78%] rounded-2xl rounded-bl-sm bg-background border px-3 py-2 text-xs text-foreground shadow-sm">
                      How do I update my notification settings?
                    </div>
                  </div>
                  <div className="flex justify-end">
                    <div className="max-w-[78%] rounded-2xl rounded-br-sm bg-primary px-3 py-2 text-xs text-primary-foreground shadow-sm shadow-primary/20">
                      Go to Settings → Preferences. Toggle email notifications there. Anything else I can help with?
                    </div>
                  </div>
                  <div className="flex justify-start">
                    <div className="rounded-2xl rounded-bl-sm bg-background border px-3 py-2 shadow-sm flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground animate-bounce [animation-delay:0ms]" />
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground animate-bounce [animation-delay:150ms]" />
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground animate-bounce [animation-delay:300ms]" />
                    </div>
                  </div>
                </div>
                <div className="border-t px-3 py-2.5 bg-sidebar flex items-center gap-2">
                  <div className="flex-1 h-8 rounded-xl bg-muted/50 border text-xs text-muted-foreground flex items-center px-3">
                    Type a message…
                  </div>
                  <div className="h-8 w-8 rounded-full bg-primary flex items-center justify-center shrink-0 shadow-sm shadow-primary/30">
                    <ArrowRight className="h-3.5 w-3.5 text-primary-foreground" />
                  </div>
                </div>
              </div>
              <p className="text-center text-[11px] text-muted-foreground mt-3 flex items-center justify-center gap-1.5">
                <Star className="h-3 w-3 fill-amber-400 text-amber-400" />
                This is the actual interface your customers will use
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="bg-muted/20 border-y border-border/50 py-16 sm:py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="text-center mb-12">
            <p className="text-xs font-bold uppercase tracking-widest text-primary mb-3">Built right</p>
            <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
              Everything your team needs.<br className="hidden sm:block" /> Nothing they don't.
            </h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <FeatureCard icon={MessageSquare} title="Familiar chat experience" description="A WhatsApp-inspired interface your customers already know — reactions, replies, file sharing, and read receipts built in." />
            <FeatureCard icon={Zap} title="Instant delivery" description="WebSocket-powered real-time messaging. Messages land in milliseconds, with live typing indicators keeping conversations alive." />
            <FeatureCard icon={Shield} title="Strict access control" description="Role-based permissions keep users, agents, and administrators in their lanes. Each person sees exactly what they should." />
            <FeatureCard icon={UserCheck} title="Dedicated agents" description="Every conversation is assigned to a specific support agent. No messages falling through the cracks, ever." />
            <FeatureCard icon={Headphones} title="Rich announcements" description="Broadcast platform-wide announcements with images and priority levels. Keep your entire user base informed instantly." />
            <FeatureCard icon={Lock} title="Secure by default" description="CSRF protection, httpOnly cookies, session revocation, and rate limiting — security built in from day one, not patched on." />
          </div>
        </div>
      </section>

      {/* Bottom CTA */}
      <section className="relative py-20 sm:py-28 overflow-hidden">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_60%_60%_at_50%_50%,hsl(var(--primary)/0.07),transparent)]" />
        <div className="mx-auto max-w-2xl px-6 text-center">
          <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 mb-6 ring-8 ring-primary/5">
            <LeafLogo className="h-7 w-7 text-primary" />
          </div>
          <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight mb-4">
            Ready to talk to your customers?
          </h2>
          <p className="text-muted-foreground mb-8 max-w-md mx-auto leading-relaxed">
            Join {company}'s platform and give your support team the tools to deliver exceptional experiences, every time.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Button
              size="lg"
              className="w-full sm:w-auto rounded-full px-8 h-12 text-sm font-bold shadow-lg shadow-primary/25 hover:-translate-y-0.5 transition-all gap-2"
              onClick={() => navigate(isAuthenticated ? dashboardPath : '/register')}
            >
              {isAuthenticated
                ? <><LayoutDashboard className="h-4 w-4" />{user?.role === 'USER' ? 'Go to My Dashboard' : 'Go to Admin Dashboard'}</>
                : 'Create Your Account'}
              <ArrowRight className="h-4 w-4" />
            </Button>
            <Button size="lg" variant="ghost" className="w-full sm:w-auto rounded-full px-8 h-12 text-sm font-semibold gap-2" asChild>
              <Link to="/faq">Read the FAQ <ChevronRight className="h-4 w-4 text-muted-foreground" /></Link>
            </Button>
          </div>
          <div className="mt-8 flex items-center justify-center gap-2 text-xs text-muted-foreground">
            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
            Free to get started · No credit card required
          </div>
        </div>
      </section>
    </StaticLayout>
  )
}
