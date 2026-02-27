import { Lock, Zap, Headphones } from 'lucide-react'
import { Link } from 'react-router-dom'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAppConfig } from '@/hooks/useConfig'
import { LeafLogo } from '@/components/ui/LeafLogo'

export function AuthLayout({
  children,
  title,
  subtitle,
}: {
  children: React.ReactNode
  title?: string
  subtitle?: string
}) {
  const { data: configData } = useAppConfig()
  const brand = configData?.brand
  const siteName = brand?.siteName || 'Customer Hub'
  const tagline = brand?.tagline || 'Your direct line to our team'
  const company = brand?.company || 'Acme Corporation'

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Shared branded header (guest) or full AppHeader (logged in) */}
      <StaticPageHeader />

      <div className="flex flex-1 overflow-hidden">
        {/* Left — Brand Panel (desktop only) */}
        <div className="relative hidden w-[42%] lg:flex flex-col justify-between overflow-hidden bg-primary p-10 text-primary-foreground shrink-0">
          <div className="absolute inset-0 bg-[linear-gradient(135deg,hsl(var(--primary))_0%,hsl(var(--primary)/0.85)_50%,hsl(var(--primary)/0.7)_100%)]" />
          <div className="absolute -bottom-24 -right-24 h-80 w-80 rounded-full bg-white/5" />
          <div className="absolute -top-16 -left-16 h-60 w-60 rounded-full bg-white/5" />
          <div className="absolute top-1/2 right-12 h-40 w-40 rounded-full bg-white/5" />

          <div className="relative z-10 flex items-center gap-3">
            <Link to="/" className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/15 backdrop-blur-sm hover:scale-105 transition-transform">
              <LeafLogo className="h-6 w-6" />
            </Link>
            <span className="text-lg font-bold tracking-tight">{siteName}</span>
          </div>

          <div className="relative z-10 space-y-8">
            <div>
              <h2 className="text-3xl font-bold leading-tight tracking-tight">
                {tagline}
              </h2>
              <p className="mt-3 text-sm leading-relaxed text-primary-foreground/70 max-w-xs">
                Connect directly with {company}'s support team — instant messaging, file sharing, and real-time assistance.
              </p>
            </div>

            <div className="space-y-4">
              {[
                { icon: Zap, text: 'Real-time messaging with read receipts' },
                { icon: Lock, text: 'End-to-end secure conversations' },
                { icon: Headphones, text: 'Dedicated admin support team' },
              ].map(({ icon: Icon, text }) => (
                <div key={text} className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/10">
                    <Icon className="h-4 w-4" />
                  </div>
                  <span className="text-sm text-primary-foreground/80">{text}</span>
                </div>
              ))}
            </div>
          </div>

          <p className="relative z-10 text-xs text-primary-foreground/40">
            &copy; {new Date().getFullYear()} {company}
          </p>
        </div>

        {/* Right — Form panel (scrollable on mobile) */}
        <div className="flex flex-1 flex-col overflow-y-auto">
          <div className="flex flex-1 items-center justify-center px-5 py-10 sm:px-8">
            <div className="w-full max-w-[420px] space-y-7">
              {(title || subtitle) && (
                <div className="space-y-1.5 text-center lg:text-left">
                  {title && <h1 className="text-2xl font-bold tracking-tight">{title}</h1>}
                  {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
                </div>
              )}

              {children}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
