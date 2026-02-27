import { useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Shield, Zap, ArrowRight,
  Lock, Mail, MessageSquare, MonitorSmartphone
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useAppConfig } from '@/hooks/useConfig'

function Feature({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <div className="group relative overflow-hidden rounded-3xl border bg-card/40 p-8 transition-all hover:bg-card hover:shadow-lg dark:hover:shadow-primary/5">
      <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-primary/10 transition-transform group-hover:scale-150 blur-2xl" />
      <div className="relative z-10">
        <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-primary/20 to-primary/5 text-primary ring-1 ring-primary/20">
          <Icon className="h-6 w-6" />
        </div>
        <h3 className="mb-2 text-xl font-bold tracking-tight">{title}</h3>
        <p className="text-sm leading-relaxed text-muted-foreground">{description}</p>
      </div>
    </div>
  )
}

export function LandingPage() {
  const navigate = useNavigate()
  const { data: configData } = useAppConfig()
  const brand = configData?.brand
  const tagline = brand?.tagline || 'Connect instantly, collaborate seamlessly.'
  const company = brand?.company || 'Acme Corporation'
  const supportEmail = brand?.supportEmail

  // The root div and body are overflow-hidden for the chat app layout.
  // Temporarily allow scrolling while this page is mounted.
  useEffect(() => {
    const body = document.body
    const root = document.getElementById('root')
    body.classList.remove('overflow-hidden')
    root?.classList.remove('overflow-hidden')
    root?.style.setProperty('height', 'auto')
    return () => {
      body.classList.add('overflow-hidden')
      root?.classList.add('overflow-hidden')
      root?.style.removeProperty('height')
    }
  }, [])

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col selection:bg-primary/20">
      <StaticPageHeader />

      <main className="flex-1 flex flex-col">
        {/* Hero Section */}
        <section className="relative overflow-hidden pt-16 pb-12 lg:pt-24 lg:pb-16">
          {/* Decorative background blobs */}
          <div className="absolute top-0 left-1/2 -z-10 -translate-x-1/2 transform-gpu blur-3xl sm:top-[-20rem] sm:ml-16 sm:translate-x-0 sm:transform-gpu" aria-hidden="true">
            <div className="aspect-[1097/845] w-[68.5625rem] bg-gradient-to-tr from-[#ff4694] to-[#77b198] opacity-20" style={{ clipPath: 'polygon(74.1% 44.1%, 100% 61.6%, 97.5% 26.9%, 85.5% 0.1%, 80.7% 2%, 72.5% 32.5%, 60.2% 62.4%, 52.4% 68.1%, 47.5% 58.3%, 45.2% 34.5%, 27.5% 76.7%, 0.1% 64.9%, 17.9% 100%, 27.6% 76.8%, 76.1% 97.7%, 74.1% 44.1%)' }}></div>
          </div>

          <div className="mx-auto max-w-6xl px-6 text-center">
            <div className="animate-fade-in-up">
              <a href="#" className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-4 py-1.5 text-sm font-medium text-primary transition-colors hover:bg-primary/10">
                <span className="flex h-2 w-2 rounded-full bg-primary animate-pulse"></span>
                Now with Real-time Chat
              </a>
            </div>

            <h1 className="mt-6 text-4xl font-extrabold tracking-tight sm:text-6xl lg:text-7xl bg-clip-text text-transparent bg-gradient-to-b from-foreground to-muted-foreground animate-fade-in-up [animation-delay:100ms]">
              {tagline}
            </h1>

            <p className="mx-auto mt-6 max-w-2xl text-base sm:text-lg leading-relaxed text-muted-foreground animate-fade-in-up [animation-delay:200ms]">
              Connect directly with {company}'s team through a beautifully fast, secure, and intuitive messaging platform designed for the modern web.
            </p>

            <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3 animate-fade-in-up [animation-delay:300ms]">
              <Button size="lg" className="w-full sm:w-auto rounded-full px-6 py-5 text-sm font-bold shadow-xl shadow-primary/20 hover:scale-105 transition-all gap-2" onClick={() => navigate('/register')}>
                Start Messaging Free
                <ArrowRight className="h-4 w-4" />
              </Button>
              <Button size="lg" variant="outline" className="w-full sm:w-auto rounded-full px-6 py-5 text-sm font-bold bg-background/50 backdrop-blur-md hover:bg-muted transition-all" onClick={() => navigate('/login')}>
                Sign In to Account
              </Button>
            </div>

            <div className="mt-12 flex flex-wrap items-center justify-center gap-6 text-sm font-medium text-muted-foreground animate-fade-in-up [animation-delay:400ms]">
              <span className="flex items-center gap-2"><Lock className="h-4 w-4 text-primary" /> End-to-end encrypted</span>
              <span className="flex items-center gap-2"><Zap className="h-4 w-4 text-primary" /> Lightning fast</span>
              <span className="flex items-center gap-2"><MonitorSmartphone className="h-4 w-4 text-primary" /> Mobile optimized</span>
            </div>
          </div>
        </section>

        {/* Feature Highlights */}
        <section className="relative bg-muted/30 py-16">
          <div className="mx-auto max-w-6xl px-6">
            <div className="text-center mb-12">
              <h2 className="text-primary font-bold tracking-wide uppercase text-xs mb-2">Enterprise Grade</h2>
              <h3 className="text-2xl sm:text-3xl font-extrabold tracking-tight">Everything you need to connect</h3>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Feature
                icon={MessageSquare}
                title="Fluid Conversations"
                description="Experience a WhatsApp-inspired chat interface that feels instantly familiar and incredibly fast."
              />
              <Feature
                icon={Zap}
                title="Real-time Presence"
                description="See when the team is online and typing, ensuring your communication is always in sync."
              />
              <Feature
                icon={Shield}
                title="Strict Privacy"
                description="Your data is protected by strict role-based access controls and robust backend security."
              />
            </div>
          </div>
        </section>

        {/* Bottom CTA */}
        <section className="relative overflow-hidden py-16">
          <div className="absolute inset-0 bg-primary/5" />
          <div className="relative mx-auto max-w-4xl px-6 text-center">
            <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight mb-4">Ready to upgrade your support experience?</h2>
            <p className="text-base text-muted-foreground mb-8 max-w-2xl mx-auto">
              Join {company} today and discover how effortless communication can be.
            </p>
            <Button size="lg" className="rounded-full px-6 py-5 text-sm font-bold shadow-xl shadow-primary/20 hover:scale-105 transition-transform gap-2" onClick={() => navigate('/register')}>
              Create Your Free Account
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        </section>
      </main>

      <footer className="border-t border-border/40 bg-background py-8">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-muted-foreground">
              <LeafLogo className="h-4 w-4" />
              <span className="text-sm font-medium">&copy; {new Date().getFullYear()} {company}. All rights reserved.</span>
            </div>
            <div className="flex flex-wrap items-center gap-6 text-sm font-medium text-muted-foreground">
              <Link to="/terms" className="hover:text-primary transition-colors">Terms</Link>
              <Link to="/privacy" className="hover:text-primary transition-colors">Privacy</Link>
              <Link to="/contact" className="hover:text-primary transition-colors">Contact</Link>
              {supportEmail && (
                <a href={`mailto:${supportEmail}`} className="flex items-center gap-1.5 hover:text-primary transition-colors">
                  <Mail className="h-4 w-4" />
                  Support
                </a>
              )}
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
