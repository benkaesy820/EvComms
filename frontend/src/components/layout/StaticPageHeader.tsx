/**
 * StaticPageHeader
 *
 * Shows the LandingPage branded header (logo · theme-toggle · Sign In · Get Started)
 * when the visitor is a guest.  Once the user is logged in the full AppHeader is
 * displayed instead so they keep access to nav, global search, and the user menu.
 */
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { AppHeader } from '@/components/layout/AppHeader'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useAuthStore } from '@/stores/authStore'
import { useAppConfig } from '@/hooks/useConfig'

export function StaticPageHeader() {
    const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
    const navigate = useNavigate()
    const { data } = useAppConfig()
    const siteName = data?.brand?.siteName || 'Customer Hub'

    // Logged-in users get the full app header
    if (isAuthenticated) return <AppHeader />

    // Guests get the same branded header as the landing page
    return (
        <header className="sticky top-0 z-50 border-b border-border/40 bg-background/60 backdrop-blur-xl">
            <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
                {/* Logo + name */}
                <button
                    onClick={() => navigate('/')}
                    className="flex items-center gap-2.5"
                >
                    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-primary/80 text-primary-foreground shadow-sm hover:scale-105 transition-transform">
                        <LeafLogo className="h-5 w-5" />
                    </span>
                    <span className="font-extrabold text-xl tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-foreground to-foreground/70">
                        {siteName}
                    </span>
                </button>

                {/* Actions */}
                <div className="flex items-center gap-3">
                    <ThemeToggle />
                    <Button
                        variant="ghost"
                        className="hidden sm:flex rounded-full px-5 font-semibold hover:bg-muted"
                        onClick={() => navigate('/login')}
                    >
                        Sign In
                    </Button>
                    <Button
                        className="rounded-full px-6 font-semibold shadow-md shadow-primary/20 hover:shadow-lg hover:shadow-primary/30 transition-shadow"
                        onClick={() => navigate('/register')}
                    >
                        Get Started
                    </Button>
                </div>
            </div>
        </header>
    )
}
