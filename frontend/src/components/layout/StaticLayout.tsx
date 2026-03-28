/**
 * StaticLayout
 * Shared wrapper for all public/static pages.
 * Handles the overflow fix (needed because the app root locks scroll),
 * renders the header, and a consistent footer.
 */

import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Mail } from 'lucide-react'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAppConfig } from '@/hooks/useConfig'
import { useAuthStore } from '@/stores/authStore'
import { DEFAULTS } from '@/lib/constants'

// ── Footer ────────────────────────────────────────────────────────────────────

function StaticFooter() {
  const { data } = useAppConfig()
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const company = data?.brand?.company || DEFAULTS.company
  const supportEmail = data?.brand?.supportEmail
  // Authenticated users go to their in-app announcements; guests see the public page
  const announcementsHref = isAuthenticated
    ? (user?.role === 'USER' ? '/home/announcements' : '/admin/announcements')
    : '/announcements'

  return (
    <footer className="border-t border-border/40 bg-background">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-8 sm:py-10">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 sm:gap-6">
          {/* Brand */}
          <div className="flex items-center gap-2.5 text-muted-foreground">
            <LeafLogo className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">{company}</span>
            <span className="text-xs text-muted-foreground/60">·</span>
            <span className="text-xs">© {new Date().getFullYear()}</span>
          </div>

          {/* Links */}
          <nav className="flex flex-wrap items-center justify-center gap-x-4 sm:gap-x-6 gap-y-2 text-sm text-muted-foreground">
            <Link to={announcementsHref} className="hover:text-primary transition-colors">Announcements</Link>
            <Link to="/faq" className="hover:text-primary transition-colors">FAQ</Link>
            <Link to="/contact" className="hover:text-primary transition-colors">Contact</Link>
            <Link to="/terms" className="hover:text-primary transition-colors">Terms</Link>
            <Link to="/privacy" className="hover:text-primary transition-colors">Privacy</Link>
            {supportEmail && (
              <a
                href={`mailto:${supportEmail}`}
                className="flex items-center gap-1.5 hover:text-primary transition-colors"
              >
                <Mail className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">{supportEmail}</span>
                <span className="sm:hidden">Email</span>
              </a>
            )}
          </nav>
        </div>
      </div>
    </footer>
  )
}

// ── Layout ────────────────────────────────────────────────────────────────────

interface StaticLayoutProps {
  children: React.ReactNode
  /** Extra classes on the <main> element */
  className?: string
}

export function StaticLayout({ children, className }: StaticLayoutProps) {
  // The root div and body are overflow-hidden for the chat app layout.
  // Temporarily allow scrolling while any static page is mounted.
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
      <main className={`flex-1 flex flex-col ${className ?? ''}`}>
        {children}
      </main>
      <StaticFooter />
    </div>
  )
}
