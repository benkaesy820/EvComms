import { Link, useNavigate } from 'react-router-dom'
import { Home, ArrowLeft, SearchX } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { useAuthStore } from '@/stores/authStore'

export function NotFoundPage() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const homePath = isAuthenticated
    ? (user?.role === 'USER' ? '/home' : '/admin/home')
    : '/'

  return (
    <StaticLayout>
      <div className="flex flex-1 flex-col items-center justify-center px-4 py-20 sm:px-6 text-center">
        {/* Visual */}
        <div className="relative mb-8 select-none">
          <p className="text-[120px] sm:text-[160px] font-black leading-none text-muted-foreground/10 tabular-nums">
            404
          </p>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="flex h-20 w-20 items-center justify-center rounded-3xl bg-muted ring-8 ring-muted/30">
              <SearchX className="h-9 w-9 text-muted-foreground" aria-hidden="true" />
            </div>
          </div>
        </div>

        {/* Text */}
        <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight mb-3">
          Page not found
        </h1>
        <p className="text-muted-foreground max-w-md mx-auto leading-relaxed mb-8">
          Sorry, we couldn&apos;t find the page you&apos;re looking for. It may have been moved,
          deleted, or the URL might be incorrect.
        </p>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <Button
            size="lg"
            variant="outline"
            className="w-full sm:w-auto rounded-full px-8 h-11 font-semibold gap-2"
            onClick={() => window.history.length > 1 ? navigate(-1) : navigate(homePath)}
          >
            <ArrowLeft className="h-4 w-4" />
            Go Back
          </Button>
          <Button
            size="lg"
            asChild
            className="w-full sm:w-auto rounded-full px-8 h-11 font-semibold gap-2"
          >
            <Link to={homePath}>
              <Home className="h-4 w-4" />
              {isAuthenticated ? 'Go to Dashboard' : 'Return Home'}
            </Link>
          </Button>
        </div>

        {/* Help links */}
        <div className="mt-12 pt-8 border-t border-border/50 w-full max-w-sm">
          <p className="text-sm text-muted-foreground mb-4">Need help? Try these:</p>
          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm">
            <Link to="/faq" className="text-primary hover:underline underline-offset-4 font-medium">FAQ</Link>
            <Link to="/contact" className="text-primary hover:underline underline-offset-4 font-medium">Contact Support</Link>
            <Link to="/announcements" className="text-primary hover:underline underline-offset-4 font-medium">Announcements</Link>
          </div>
        </div>
      </div>
    </StaticLayout>
  )
}
