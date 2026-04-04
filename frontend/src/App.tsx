import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { broadcastQueryClient } from '@tanstack/query-broadcast-client-experimental'
import { Toaster } from '@/components/ui/sonner'
import { toast } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { NetworkBanner } from '@/components/NetworkBanner'
import { useAuthStore } from '@/stores/authStore'
import { useSocketConnection } from '@/hooks/useSocket'
import { ApiError, notifications } from '@/lib/api'
import type { Role, Status } from '@/lib/schemas'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { isPushSupported, getNotificationPermission, subscribeToPush, registerServiceWorker, getActiveSubscription } from '@/lib/webPush'

const LoginPage = lazy(() => import('@/pages/LoginPage').then((m) => ({ default: m.LoginPage })))
const RegisterPage = lazy(() => import('@/pages/RegisterPage').then((m) => ({ default: m.RegisterPage })))
const ForgotPasswordPage = lazy(() => import('@/pages/ForgotPasswordPage').then((m) => ({ default: m.ForgotPasswordPage })))
const ResetPasswordPage = lazy(() => import('@/pages/ResetPasswordPage').then((m) => ({ default: m.ResetPasswordPage })))
const StatusPage = lazy(() => import('@/pages/StatusPage').then((m) => ({ default: m.StatusPage })))
const ChatPage = lazy(() => import('@/pages/ChatPage').then((m) => ({ default: m.ChatPage })))
const HomePage = lazy(() => import('@/pages/HomePage').then((m) => ({ default: m.HomePage })))
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })))
const UserLayout = lazy(() => import('@/pages/UserLayout').then((m) => ({ default: m.UserLayout })))
const UserAnnouncementsPage = lazy(() => import('@/pages/UserAnnouncementsPage').then((m) => ({ default: m.UserAnnouncementsPage })))
const AdminLayout = lazy(() => import('@/pages/admin/AdminLayout').then((m) => ({ default: m.AdminLayout })))
const ConversationsPage = lazy(() => import('@/pages/admin/ConversationsPage').then((m) => ({ default: m.ConversationsPage })))
const UsersPage = lazy(() => import('@/pages/admin/UsersPage').then((m) => ({ default: m.UsersPage })))
const AdminsPage = lazy(() => import('@/pages/admin/AdminsPage').then((m) => ({ default: m.AdminsPage })))
const AuditPage = lazy(() => import('@/pages/admin/AuditPage').then((m) => ({ default: m.AuditPage })))
const AnnouncementsPage = lazy(() => import('@/pages/admin/AnnouncementsPage').then((m) => ({ default: m.AnnouncementsPage })))
const AnnouncementEditorPage = lazy(() => import('@/pages/admin/AnnouncementEditorPage').then((m) => ({ default: m.AnnouncementEditorPage })))
const InternalChatPage = lazy(() => import('@/pages/admin/InternalChatPage').then((m) => ({ default: m.InternalChatPage })))
const UserDetailPage = lazy(() => import('@/pages/admin/UserDetailPage').then((m) => ({ default: m.UserDetailPage })))
const AnnouncementViewPage = lazy(() => import('@/pages/AnnouncementViewPage').then((m) => ({ default: m.AnnouncementViewPage })))
const ReportViewPage = lazy(() => import('@/pages/ReportViewPage').then((m) => ({ default: m.ReportViewPage })))
const BrandPage = lazy(() => import('@/pages/admin/BrandPage').then((m) => ({ default: m.BrandPage })))
const DMPage = lazy(() => import('@/pages/admin/DMPage').then((m) => ({ default: m.DMPage })))
const LandingPage = lazy(() => import('@/pages/LandingPage').then((m) => ({ default: m.LandingPage })))
const TermsPage = lazy(() => import('@/pages/TermsPage').then((m) => ({ default: m.TermsPage })))
const PrivacyPage = lazy(() => import('@/pages/PrivacyPage').then((m) => ({ default: m.PrivacyPage })))
const FAQPage = lazy(() => import('@/pages/FAQPage').then((m) => ({ default: m.FAQPage })))
const ContactPage = lazy(() => import('@/pages/ContactPage').then((m) => ({ default: m.ContactPage })))
const ReportsPage = lazy(() => import('@/pages/admin/ReportsPage').then((m) => ({ default: m.ReportsPage })))
const PublicAnnouncementsPage = lazy(() => import('@/pages/PublicAnnouncementsPage').then((m) => ({ default: m.PublicAnnouncementsPage })))
const UserReportsPage = lazy(() => import('@/pages/UserReportsPage').then((m) => ({ default: m.UserReportsPage })))
const AdminUserReportsPage = lazy(() => import('@/pages/admin/AdminUserReportsPage').then((m) => ({ default: m.AdminUserReportsPage })))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage').then((m) => ({ default: m.NotFoundPage })))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (count, error) => {
        if (error instanceof ApiError && (error.status === 401 || error.status === 404)) return false
        return count < 3
      },
      staleTime: 0,   // always refetch on remount; socket keeps cache fresh
      refetchOnWindowFocus: true,
    },
  },
})

// Native Cross-Tab React Query Cache Sync
// This globally mirrors TanStack HTTP caches across all of the device's idle tabs over a BroadcastChannel.
broadcastQueryClient({
  queryClient,
  broadcastChannel: 'evcomms-query-cache',
})

function PageLoader() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <LeafLogo className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  )
}

type RouteGuardConfig = {
  requireAuth?: boolean
  requireStatus?: Status
  requireRole?: Role | Role[]
  guestOnly?: boolean
}

function RouteGuard({ children, config }: { children: React.ReactNode; config: RouteGuardConfig }) {
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  const isGuest = !isAuthenticated || !user

  if (config.guestOnly && !isGuest) {
    if (user.status !== 'APPROVED') return <Navigate to="/status" replace />
    return <Navigate to="/" replace />
  }

  if (config.requireAuth && isGuest) {
    return <Navigate to="/login" replace />
  }

  if (user && user.status !== 'APPROVED' && config.requireStatus === 'APPROVED') {
    return <Navigate to="/status" replace />
  }

  if (config.requireRole && user) {
    const roles = Array.isArray(config.requireRole) ? config.requireRole : [config.requireRole]
    if (!roles.includes(user.role)) {
      return <Navigate to={user.role === 'USER' ? '/' : '/admin'} replace />
    }
  }

  return <>{children}</>
}

function RootRoute() {
  const user = useAuthStore((s) => s.user)
  const isHydrated = useAuthStore((s) => s.isHydrated)

  // Wait for localStorage rehydration so the landing page renders with
  // the correct auth state (authenticated CTAs vs guest CTAs) without flash.
  if (!isHydrated) return <PageLoader />

  // Pending/suspended users go to the status page — they can't use the platform.
  if (user && user.status !== 'APPROVED') return <Navigate to="/status" replace />

  // Everyone else — guest or logged-in — sees the landing page.
  // LandingPage reads isAuthenticated and shows "Go to Dashboard" for logged-in users
  // instead of the sign-up CTAs, so no separate redirect needed.
  return <LandingPage />
}

function SocketProvider({ children }: { children: React.ReactNode }) {
  useSocketConnection()
  return <>{children}</>
}

function AppInit({ children }: { children: React.ReactNode }) {
  const refreshUser = useAuthStore((s) => s.refreshUser)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const user = useAuthStore((s) => s.user)
  const reset = useAuthStore((s) => s.reset)

  useEffect(() => {
    if (isAuthenticated) refreshUser()
  }, [isAuthenticated, refreshUser])

  // Admins/super-admins are always active — no approval gate needed for push.
  const isEligibleForPush = isAuthenticated && (
    user?.status === 'APPROVED' ||
    user?.role === 'ADMIN' ||
    user?.role === 'SUPER_ADMIN'
  )

  // Register the service worker as early as possible so the push subscription
  // is ready before the permission prompt fires (3 s delay below).
  useEffect(() => {
    if (isEligibleForPush && isPushSupported()) {
      registerServiceWorker().catch(() => { /* SW registration is best-effort — push notifications will still work via polling */ })
    }
  }, [isEligibleForPush])

  // Prompt for notification permission after a short delay (only if not yet decided)
  useEffect(() => {
    if (!isEligibleForPush) return
    if (!isPushSupported()) return

    // If already granted — check if subscription exists and sync to server
    if (getNotificationPermission() === 'granted') {
      getActiveSubscription().then((sub) => {
        if (sub) {
          // Subscription exists — ensure server has it (in case of device change)
          const raw = sub.toJSON()
          notifications.subscribe({
            endpoint: raw.endpoint!,
            keys: { p256dh: raw.keys?.p256dh!, auth: raw.keys?.auth! },
          }).catch(() => { /* best-effort sync */ })
        }
      })
      return
    }

    // If permission is 'default' (not yet asked) and user hasn't dismissed the prompt
    if (getNotificationPermission() === 'default' && !localStorage.getItem('push-prompt-dismissed')) {
      const timer = setTimeout(() => {
        toast.info('Enable Notifications', {
          description: 'Stay updated on messages and announcements even when the app is closed.',
          duration: 15000,
          action: {
            label: 'Enable',
            onClick: async () => {
              const ok = await subscribeToPush()
              if (ok) toast.success('Notifications enabled!')
            }
          },
          onDismiss: () => localStorage.setItem('push-prompt-dismissed', 'true'),
        })
      }, 3000)
      return () => clearTimeout(timer)
    }
  }, [isEligibleForPush, user?.id])

  useEffect(() => {
    const handleAuthExpired = () => {
      toast.error('Session expired. Please log in again.')
      reset()
    }
    window.addEventListener('auth:expired', handleAuthExpired)
    return () => window.removeEventListener('auth:expired', handleAuthExpired)
  }, [reset])

  return <>{children}</>
}

export function App() {
  return (
    <ErrorBoundary>
      <NetworkBanner />
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <AppInit>
              <SocketProvider>
                <Suspense fallback={<PageLoader />}>
                  <Routes>
                    <Route path="/login" element={<RouteGuard config={{ guestOnly: true }}><LoginPage /></RouteGuard>} />
                    <Route path="/register" element={<RouteGuard config={{ guestOnly: true }}><RegisterPage /></RouteGuard>} />
                    <Route path="/forgot-password" element={<RouteGuard config={{ guestOnly: true }}><ForgotPasswordPage /></RouteGuard>} />
                    <Route path="/reset-password" element={<RouteGuard config={{ guestOnly: true }}><ResetPasswordPage /></RouteGuard>} />
                    <Route path="/status" element={<RouteGuard config={{ requireAuth: true }}><StatusPage /></RouteGuard>} />

                    {/* Admin Routes */}
                    <Route path="/admin" element={<RouteGuard config={{ requireAuth: true, requireStatus: 'APPROVED', requireRole: ['ADMIN', 'SUPER_ADMIN'] }}><AdminLayout /></RouteGuard>}>
                      <Route index element={<ConversationsPage />} />
                      <Route path="home" element={<HomePage />} />
                      <Route path="users" element={<UsersPage />} />
                      <Route path="users/:userId" element={<UserDetailPage />} />
                      <Route path="admins" element={<RouteGuard config={{ requireRole: 'SUPER_ADMIN' }}><AdminsPage /></RouteGuard>} />
                      <Route path="announcements" element={<AnnouncementsPage />} />
                      <Route path="announcements/new" element={<AnnouncementEditorPage />} />
                      <Route path="announcements/:id" element={<AnnouncementViewPage />} />
                      <Route path="announcements/:id/edit" element={<AnnouncementEditorPage />} />
                      <Route path="dm" element={<DMPage />} />
                      <Route path="internal" element={<InternalChatPage />} />
                      <Route path="audit" element={<RouteGuard config={{ requireRole: 'SUPER_ADMIN' }}><AuditPage /></RouteGuard>} />
                      <Route path="reports" element={<RouteGuard config={{ requireRole: 'SUPER_ADMIN' }}><ReportsPage /></RouteGuard>} />
                      <Route path="reports/:id" element={<RouteGuard config={{ requireRole: 'SUPER_ADMIN' }}><ReportViewPage /></RouteGuard>} />
                      <Route path="brand" element={<RouteGuard config={{ requireRole: 'SUPER_ADMIN' }}><BrandPage /></RouteGuard>} />
                      <Route path="user-reports/:id" element={<ReportViewPage />} />
                      <Route path="user-reports" element={<AdminUserReportsPage />} />
                      <Route path="settings" element={<SettingsPage />} />
                    </Route>

                    {/* User Routes */}
                    <Route path="/home" element={<RouteGuard config={{ requireAuth: true, requireStatus: 'APPROVED', requireRole: 'USER' }}><UserLayout /></RouteGuard>}>
                      <Route index element={<HomePage />} />
                      <Route path="chat" element={<ChatPage />} />
                      <Route path="announcements" element={<UserAnnouncementsPage />} />
                      <Route path="announcements/:id" element={<AnnouncementViewPage />} />
                      <Route path="reports" element={<UserReportsPage />} />
                      <Route path="reports/:id" element={<ReportViewPage />} />
                      <Route path="settings" element={<SettingsPage />} />
                    </Route>

                    {/* Legacy redirects for backward compatibility */}
                    <Route path="/chat" element={<Navigate to="/home/chat" replace />} />

                    <Route path="/terms" element={<TermsPage />} />
                    <Route path="/privacy" element={<PrivacyPage />} />
                    <Route path="/faq" element={<FAQPage />} />
                    <Route path="/contact" element={<ContactPage />} />
                    <Route path="/announcements" element={<PublicAnnouncementsPage />} />
                    <Route path="/announcements/:id" element={<AnnouncementViewPage />} />
                    <Route path="/" element={<RootRoute />} />
                    <Route path="*" element={<NotFoundPage />} />
                  </Routes>
                </Suspense>
              </SocketProvider>
            </AppInit>
          </BrowserRouter>
          <Toaster
            richColors
            position="bottom-right"
            toastOptions={{
              className: 'sm:mb-0 mb-[calc(72px+env(safe-area-inset-bottom))]',
            }}
          />
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
