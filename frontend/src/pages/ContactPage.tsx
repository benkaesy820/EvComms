import { useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Mail, MessageSquare, HelpCircle, Clock } from 'lucide-react'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAuthStore } from '@/stores/authStore'
import { useAppConfig } from '@/hooks/useConfig'

export function ContactPage() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const { data } = useAppConfig()
  const brand = data?.brand
  const company = brand?.company || 'Acme Corporation'
  const supportEmail = brand?.supportEmail

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
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <StaticPageHeader />

      <main className="flex-1">
        <div className="mx-auto max-w-3xl px-6 py-12">
          <div className="flex items-center gap-3 mb-8">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <Mail className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight">Contact Us</h1>
              <p className="text-sm text-muted-foreground">We're here to help</p>
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-4 mb-8">
            {supportEmail && (
              <a
                href={`mailto:${supportEmail}`}
                className="flex items-start gap-4 rounded-xl border p-5 hover:bg-accent/50 transition-colors group"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 group-hover:bg-primary/15 transition-colors">
                  <Mail className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-semibold">Email Support</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{supportEmail}</p>
                  <p className="text-xs text-muted-foreground mt-2">Send us an email and we'll respond within 24 hours.</p>
                </div>
              </a>
            )}

            <div
              className="flex items-start gap-4 rounded-xl border p-5 hover:bg-accent/50 transition-colors cursor-pointer group"
              onClick={() => user ? navigate(user.role === 'USER' ? '/home/chat' : '/admin') : navigate('/login')}
            >
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 group-hover:bg-primary/15 transition-colors">
                <MessageSquare className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-semibold">Live Chat</p>
                <p className="text-xs text-muted-foreground mt-0.5">Real-time messaging</p>
                <p className="text-xs text-muted-foreground mt-2">
                  {user ? 'Go to your chat' : 'Sign in to start a conversation'} with our support team.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">Before reaching out</h2>
            <div className="grid sm:grid-cols-2 gap-3">
              <Link to="/faq" className="flex items-center gap-3 rounded-xl border p-4 hover:bg-accent/50 transition-colors">
                <HelpCircle className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-sm font-medium">Check our FAQ</p>
                  <p className="text-xs text-muted-foreground">Answers to common questions</p>
                </div>
              </Link>
              <div className="flex items-center gap-3 rounded-xl border p-4 bg-muted/20">
                <Clock className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-sm font-medium">Response Time</p>
                  <p className="text-xs text-muted-foreground">Typically within 1–24 hours</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-border/40 bg-background py-8">
        <div className="mx-auto max-w-6xl px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">© {new Date().getFullYear()} {company}. All rights reserved.</p>
          <div className="flex flex-wrap items-center gap-6 text-sm font-medium text-muted-foreground">
            <Link to="/terms" className="hover:text-primary transition-colors">Terms</Link>
            <Link to="/privacy" className="hover:text-primary transition-colors">Privacy</Link>
            <Link to="/contact" className="text-primary">Contact</Link>
            {supportEmail && (
              <a href={`mailto:${supportEmail}`} className="flex items-center gap-1.5 hover:text-primary transition-colors">
                <Mail className="h-4 w-4" />
                Support
              </a>
            )}
          </div>
        </div>
      </footer>
    </div>
  )
}
