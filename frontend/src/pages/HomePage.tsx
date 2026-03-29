import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  MessageSquare, Settings, ArrowRight, Headphones,
  Users, ScrollText, Zap, Megaphone, CheckSquare,
  Clock, Monitor, Sun, Moon, UserCheck, UserX, Activity, Building2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { AppHeader } from '@/components/layout/AppHeader'
import { useAuthStore } from '@/stores/authStore'
import { useAnnouncements } from '@/hooks/useAnnouncements'
import { useConversation, useAdminConversations } from '@/hooks/useMessages'
import { adminStats, adminUsers } from '@/lib/api'
import { cn, formatRelativeTime, getInitials } from '@/lib/utils'
import { LeafLogo } from '@/components/ui/LeafLogo'
import type { Announcement, Status } from '@/lib/schemas'
import { useAppConfig } from '@/hooks/useConfig'
import { ANNOUNCEMENT_TYPE_CONFIG } from '@/lib/constants'
import { toast } from '@/components/ui/sonner'

function AnnouncementCard({ announcement, onView }: { announcement: Announcement; onView: (id: string) => void }) {
  const cfg = ANNOUNCEMENT_TYPE_CONFIG[announcement.type]
  const Icon = cfg.icon
  return (
    <button onClick={() => onView(announcement.id)} className={cn(
      'w-full text-left rounded-xl border p-3.5 transition-all hover:shadow-md hover:-translate-y-0.5 group cursor-pointer',
      cfg.bg, cfg.border,
    )}>
      <div className="flex items-start gap-3">
        <div className={cn('flex h-9 w-9 items-center justify-center rounded-xl shrink-0', cfg.bg)}>
          <Icon className={cn('h-4 w-4', cfg.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold group-hover:text-primary transition-colors">{announcement.title}</span>
            <Badge variant="outline" className={cn('text-[10px] py-0 px-1.5', cfg.color, cfg.border)}>
              {announcement.type}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{announcement.content}</p>
          <p className="text-[10px] text-muted-foreground mt-1.5">
            {formatRelativeTime(announcement.createdAt)}
          </p>
        </div>
        <ArrowRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-all group-hover:translate-x-0.5 mt-2 shrink-0" />
      </div>
    </button>
  )
}

function PendingUserCard({ user, onApprove, onReject, isLoading }: {
  user: { id: string; name: string; email: string; createdAt: number }
  onApprove: () => void
  onReject: () => void
  isLoading: boolean
}) {
  // FIX #23: Show inline confirm step before rejecting — prevents accidental one-click rejection
  const [confirmingReject, setConfirmingReject] = useState(false)

  return (
    <div className="flex items-center gap-3 p-3 rounded-xl border bg-card hover:bg-muted/30 transition-colors">
      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-amber-400 to-orange-500 text-white text-xs font-bold shadow-sm">
        {getInitials(user.name)}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{user.name}</p>
        <p className="text-[11px] text-muted-foreground truncate">{user.email}</p>
      </div>
      <div className="flex items-center gap-1.5">
        {confirmingReject ? (
          <>
            <span className="text-[10px] text-destructive font-medium">Reject?</span>
            <Button size="icon" variant="ghost" className="h-7 w-7 rounded-lg text-destructive hover:text-destructive hover:bg-red-100 dark:hover:bg-red-900/30" onClick={() => { setConfirmingReject(false); onReject() }} disabled={isLoading}>
              <UserX className="h-3.5 w-3.5" />
            </Button>
            <Button size="icon" variant="ghost" className="h-7 w-7 rounded-lg text-muted-foreground" onClick={() => setConfirmingReject(false)}>
              <span className="text-xs">✕</span>
            </Button>
          </>
        ) : (
          <>
            <Button size="icon" variant="ghost" className="h-8 w-8 rounded-lg text-green-600 hover:text-green-700 hover:bg-green-100 dark:hover:bg-green-900/30" onClick={onApprove} disabled={isLoading}>
              {isLoading ? <LeafLogo className="h-4 w-4 animate-spin" /> : <UserCheck className="h-4 w-4" />}
            </Button>
            <Button size="icon" variant="ghost" className="h-8 w-8 rounded-lg text-red-600 hover:text-red-700 hover:bg-red-100 dark:hover:bg-red-900/30" onClick={() => setConfirmingReject(true)} disabled={isLoading}>
              <UserX className="h-4 w-4" />
            </Button>
          </>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color }: {
  label: string
  value: string | number
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border bg-card/40 p-4 hover:bg-card hover:shadow-lg transition-all">
      <div className="absolute -right-4 -top-4 h-16 w-16 rounded-full opacity-20 blur-xl transition-transform group-hover:scale-150" />
      <div className="relative z-10 flex items-center justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-2xl font-extrabold tracking-tight tabular-nums">{value}</p>
          <p className="text-[10px] font-semibold text-muted-foreground mt-0.5 tracking-wider uppercase truncate">{label}</p>
        </div>
        <div className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ring-1', color)}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </div>
  )
}

function QuickAction({ icon: Icon, label, desc, path, onClick }: {
  icon: React.ElementType; label: string; desc: string; path: string; onClick: (p: string) => void
}) {
  return (
    <button
      onClick={() => onClick(path)}
      className="w-full group flex items-center justify-between p-2.5 rounded-xl hover:bg-accent/50 transition-colors"
    >
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </div>
        <div className="text-left">
          <p className="text-sm font-semibold">{label}</p>
          <p className="text-[10px] text-muted-foreground">{desc}</p>
        </div>
      </div>
      <ArrowRight className="h-4 w-4 text-muted-foreground opacity-50 transition-transform group-hover:translate-x-1 group-hover:opacity-100" />
    </button>
  )
}

export function HomePage() {
  const user = useAuthStore((s) => s.user)
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const isInsideLayout = location.pathname.startsWith('/home') || location.pathname.startsWith('/admin')
  const { data: announcementsData } = useAnnouncements()
  const activeAnnouncements = announcementsData?.announcements ?? []
  const { data: conversationData } = useConversation()
  const unreadCount = conversationData?.conversation?.unreadCount ?? 0

  const { data: configData } = useAppConfig()
  const brand = configData?.brand
  const subsidiaries = configData?.subsidiaries ?? []

  const { data: statsData } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: () => adminStats.get(),
    enabled: isAdmin,
    staleTime: 0,
  })
  const stats = statsData?.stats
  const pendingCount = stats?.users?.pending ?? 0

  // For regular admins, compute stats from their own assigned conversations
  // instead of showing platform-wide numbers which are meaningless to them.
  const { data: adminConvData } = useAdminConversations(false)
  const { data: adminArchivedData } = useAdminConversations(true)
  const myConversations = adminConvData?.pages.flatMap(p => p?.conversations ?? []) ?? []
  const myAssignedCount = myConversations.length
  const myUnreadCount = myConversations.filter(c => c && (c.adminUnreadCount ?? 0) > 0).length
  const myWaitingCount = myConversations.filter(c => c && c.waitingSince).length
  const myResolvedCount = adminArchivedData?.pages.flatMap(p => p?.conversations ?? []).length ?? 0

  const { data: pendingUsers } = useQuery({
    queryKey: ['admin', 'users', 'pending'],
    queryFn: () => adminUsers.list({ status: 'PENDING' as Status, limit: 5 }),
    enabled: isAdmin && (stats?.users?.pending ?? 0) > 0,
    staleTime: 0,
  })

  const updateStatus = useMutation({
    mutationFn: ({ userId, status, reason }: { userId: string; status: Status; reason?: string }) =>
      adminUsers.updateStatus(userId, { status, reason }),
    onSuccess: (_data, variables) => {
      queryClient.setQueriesData<{ success: boolean; users: Array<{ id: string; status: string;[key: string]: unknown }>; hasMore: boolean }>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old) return old
          return { ...old, users: old.users.map((u) => u.id === variables.userId ? { ...u, status: variables.status } : u) }
        }
      )
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'pending'] })
    },
  })

  const handleApprove = (userId: string) => {
    updateStatus.mutate({ userId, status: 'APPROVED' }, {
      onSuccess: () => toast.success('User approved'),
      onError: () => toast.error('Failed to approve'),
    })
  }

  const handleReject = (userId: string) => {
    updateStatus.mutate({ userId, status: 'REJECTED', reason: 'Not approved' }, {
      onSuccess: () => toast.success('User rejected'),
      onError: () => toast.error('Failed to reject'),
    })
  }

  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'

  return (
    <div className={cn('flex flex-col', isInsideLayout ? 'h-full' : 'h-screen bg-background')}>
      {!isInsideLayout && <AppHeader />}
      <div className="flex-1 overflow-y-auto overflow-x-hidden">
        <div className="max-w-5xl mx-auto p-3 sm:p-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Main column */}
            <div className="lg:col-span-2 space-y-4 order-2 lg:order-1">
              {/* Greeting */}
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight">
                    {greeting}, {user?.name?.split(' ')[0]}
                  </h1>
                  <p className="text-sm text-muted-foreground mt-0.5">
                    {isAdmin ? 'Here\'s your dashboard overview' : 'How can we help you today?'}
                  </p>
                </div>
                <div className="hidden sm:flex items-center gap-1.5 text-xs text-muted-foreground bg-muted/50 px-3 py-1.5 rounded-full">
                  {hour >= 6 && hour < 18 ? (
                    <><Sun className="h-3.5 w-3.5 text-amber-500" /> Daytime</>
                  ) : (
                    <><Moon className="h-3.5 w-3.5 text-indigo-400" /> Evening</>
                  )}
                </div>
              </div>

              {/* Hero CTA */}
              <button
                onClick={() => navigate(isAdmin ? '/admin' : '/home/chat')}
                className="w-full group relative overflow-hidden rounded-3xl bg-gradient-to-br from-primary via-primary/95 to-primary/80 p-6 text-primary-foreground transition-all hover:shadow-2xl hover:shadow-primary/30 hover:-translate-y-1"
              >
                {/* Decorative background blobs */}
                <div className="absolute -right-8 -top-8 h-40 w-40 rounded-full bg-white/10 blur-2xl transition-transform group-hover:scale-150" />
                <div className="absolute -left-8 -bottom-8 h-32 w-32 rounded-full bg-black/10 blur-xl transition-transform group-hover:scale-150" />

                <div className="relative flex flex-col sm:flex-row items-start sm:items-center justify-between z-10 gap-3 sm:gap-4">
                  <div className="flex items-center gap-4 sm:gap-5">
                    <div className="flex h-14 w-14 sm:h-16 sm:w-16 shrink-0 items-center justify-center rounded-2xl bg-white/20 backdrop-blur-md relative ring-1 ring-white/30 shadow-inner">
                      <LeafLogo className="h-7 w-7 sm:h-8 sm:w-8 drop-shadow-md text-white" />
                      {!isAdmin && unreadCount > 0 && (
                        <span className="absolute -top-2 -right-2 flex h-6 w-6 items-center justify-center rounded-full bg-destructive text-destructive-foreground text-[11px] font-bold ring-4 ring-primary shadow-lg animate-bounce">
                          {unreadCount > 9 ? '9+' : unreadCount}
                        </span>
                      )}
                    </div>
                    <div className="text-left min-w-0">
                      <h2 className="text-xl sm:text-2xl font-extrabold tracking-tight drop-shadow-sm text-white leading-tight">
                        {isAdmin
                          ? isSuperAdmin ? 'View User Conversations' : 'View My Assigned Conversations'
                          : unreadCount > 0 ? `You have ${unreadCount} new message${unreadCount > 1 ? 's' : ''}` : 'Start a Conversation'}
                      </h2>
                      <p className="text-sm text-white/80 font-medium mt-1">
                        {isAdmin
                          ? isSuperAdmin
                            ? 'Respond to user inquiries and support requests'
                            : `${myAssignedCount} conversation${myAssignedCount !== 1 ? 's' : ''} assigned to you`
                          : brand?.tagline || 'Connect instantly with our support team'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 rounded-full bg-white/10 px-4 py-2 text-sm font-semibold backdrop-blur-md opacity-90 transition-all group-hover:bg-white/20 group-hover:opacity-100 ring-1 ring-white/20 shrink-0">
                    <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
                  </div>
                </div>
              </button>

              {/* Pending Registrations — super admin action only */}
              {isSuperAdmin && pendingCount > 0 && pendingUsers?.users && pendingUsers.users.length > 0 && (
                <div className="rounded-2xl border bg-card overflow-hidden">
                  <div className="p-3 border-b flex items-center justify-between bg-gradient-to-r from-amber-50 to-transparent dark:from-amber-950/20">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-amber-400 to-orange-500 shadow-sm">
                        <UserCheck className="h-4 w-4 text-white" />
                      </div>
                      <div>
                        <h2 className="text-sm font-bold">Pending Registrations</h2>
                        <p className="text-[11px] text-muted-foreground">{pendingCount} awaiting approval</p>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" className="text-xs rounded-lg" onClick={() => navigate('/admin/users')}>
                      View all
                    </Button>
                  </div>
                  <div className="p-3 space-y-2">
                    {pendingUsers.users.slice(0, 3).map((u) => (
                      <PendingUserCard
                        key={u.id}
                        user={u}
                        onApprove={() => handleApprove(u.id)}
                        onReject={() => handleReject(u.id)}
                        isLoading={updateStatus.isPending}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* Admin Stats — super admin sees platform-wide; regular admin sees their own workload */}
              {isAdmin && (isSuperAdmin ? stats : true) && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {isSuperAdmin ? (
                    <>
                      <StatCard icon={Users} label="Total Users" value={stats?.users?.total ?? 0} color="text-primary bg-primary/10 ring-primary/20" />
                      <StatCard icon={Clock} label="Pending" value={stats?.users?.pending ?? 0} color="text-amber-500 bg-amber-500/10 ring-amber-500/20" />
                      <StatCard icon={MessageSquare} label="Messages" value={stats?.messages ?? 0} color="text-blue-500 bg-blue-500/10 ring-blue-500/20" />
                      <StatCard icon={Monitor} label="Online" value={stats?.activeSessions ?? 0} color="text-green-500 bg-green-500/10 ring-green-500/20" />
                    </>
                  ) : (
                    <>
                      <StatCard icon={MessageSquare} label="Assigned" value={myAssignedCount} color="text-primary bg-primary/10 ring-primary/20" />
                      <StatCard icon={Clock} label="Waiting" value={myWaitingCount} color="text-amber-500 bg-amber-500/10 ring-amber-500/20" />
                      <StatCard icon={UserCheck} label="Unread" value={myUnreadCount} color="text-blue-500 bg-blue-500/10 ring-blue-500/20" />
                      <StatCard icon={CheckSquare} label="Resolved" value={myResolvedCount} color="text-green-500 bg-green-500/10 ring-green-500/20" />
                    </>
                  )}
                </div>
              )}

              {/* Announcements */}
              {activeAnnouncements.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Megaphone className="h-4 w-4 text-primary" />
                      <h2 className="text-sm font-bold">Latest Announcements</h2>
                    </div>
                    <Button variant="ghost" size="sm" className="text-xs rounded-lg" onClick={() => navigate(isAdmin ? '/admin/announcements' : '/home/announcements')}>
                      View all
                    </Button>
                  </div>
                  <div className="space-y-2">
                    {activeAnnouncements.slice(0, 3).map((ann) => (
                      <AnnouncementCard
                        key={ann.id}
                        announcement={ann}
                        onView={(id) => navigate(isAdmin ? `/admin/announcements/${id}` : `/home/announcements/${id}`)}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Sidebar column */}
            <div className="space-y-4 order-1 lg:order-2">
              {/* Quick Actions */}
              <div className="rounded-2xl border bg-card overflow-hidden">
                <div className="p-3 border-b">
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-primary" />
                    <h2 className="text-sm font-bold">Quick Actions</h2>
                  </div>
                </div>
                <div className="p-2">
                  {isAdmin ? (
                    <>
                      {[
                        { icon: Users, label: 'Users', desc: 'Manage accounts', path: '/admin/users', show: true },
                        { icon: Megaphone, label: 'Announce', desc: 'Create post', path: '/admin/announcements', show: true },
                        { icon: ScrollText, label: 'Audit', desc: 'View logs', path: '/admin/audit', show: isSuperAdmin },
                        { icon: Settings, label: 'Site Settings', desc: 'Brand & config', path: '/admin/settings', show: isSuperAdmin },
                      ].filter(a => a.show).map(({ icon, label, desc, path }) => (
                        <QuickAction key={path} icon={icon} label={label} desc={desc} path={path} onClick={navigate} />
                      ))}
                    </>
                  ) : (
                    <>
                      {[
                        { icon: Settings, label: 'Settings', desc: 'Account & sessions', path: '/home/settings' },
                        { icon: Headphones, label: 'Support', desc: 'Get help', path: '/home/chat' },
                      ].map(({ icon, label, desc, path }) => (
                        <QuickAction key={path} icon={icon} label={label} desc={desc} path={path} onClick={navigate} />
                      ))}
                    </>
                  )}
                </div>
              </div>

              {/* User Status Breakdown — platform-wide numbers, super admin only */}
              {isSuperAdmin && stats && (
                <div className="rounded-2xl border bg-card p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <Activity className="h-4 w-4 text-primary" />
                    <h3 className="text-sm font-bold">User Breakdown</h3>
                  </div>
                  <div className="space-y-3">
                    {[
                      { label: 'Approved', value: stats?.users?.approved ?? 0, total: stats?.users?.total ?? 0, color: 'bg-green-500' },
                      { label: 'Suspended', value: stats?.users?.suspended ?? 0, total: stats?.users?.total ?? 0, color: 'bg-red-500' },
                      { label: 'Rejected', value: stats?.users?.rejected ?? 0, total: stats?.users?.total ?? 0, color: 'bg-gray-400' },
                    ].map(({ label, value, total, color }) => (
                      <div key={label}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-muted-foreground">{label}</span>
                          <span className="text-xs font-medium tabular-nums">{value}</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn('h-full rounded-full transition-all', color)}
                            style={{ width: `${total > 0 ? (value / total) * 100 : 0}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* My Workload — regular admins get a summary of their own queue instead of platform-wide breakdown */}
              {isAdmin && !isSuperAdmin && (
                <div className="rounded-2xl border bg-card p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <Activity className="h-4 w-4 text-primary" />
                    <h3 className="text-sm font-bold">My Workload</h3>
                  </div>
                  <div className="space-y-3">
                    {[
                      { label: 'Assigned', value: myAssignedCount, color: 'bg-primary' },
                      { label: 'Waiting for reply', value: myWaitingCount, color: 'bg-amber-500' },
                      { label: 'Unread messages', value: myUnreadCount, color: 'bg-blue-500' },
                    ].map(({ label, value, color }) => (
                      <div key={label}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-muted-foreground">{label}</span>
                          <span className="text-xs font-medium tabular-nums">{value}</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn('h-full rounded-full transition-all', color)}
                            style={{ width: myAssignedCount > 0 ? `${Math.min(100, (value / myAssignedCount) * 100)}%` : '0%' }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Conversation status for users */}
              {!isAdmin && (
                <div className="rounded-2xl border bg-card overflow-hidden">
                  <div className="p-3 border-b flex items-center gap-2">
                    <MessageSquare className="h-4 w-4 text-primary" />
                    <h3 className="text-sm font-bold">Your Conversation</h3>
                  </div>
                  <div className="p-3 space-y-2">
                    {conversationData?.conversation ? (
                      <>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Status</span>
                          <span className={cn(
                            'font-medium text-xs px-2 py-0.5 rounded-full',
                            conversationData.conversation.archivedAt
                              ? 'bg-muted text-muted-foreground'
                              : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                          )}>
                            {conversationData.conversation.archivedAt ? 'Closed' : 'Active'}
                          </span>
                        </div>
                        {unreadCount > 0 && (
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Unread</span>
                            <span className="font-bold text-destructive">{unreadCount} new</span>
                          </div>
                        )}
                        <button
                          onClick={() => navigate('/home/chat')}
                          className="w-full mt-1 text-xs font-semibold text-primary hover:underline underline-offset-4 text-left"
                        >
                          Open conversation →
                        </button>
                      </>
                    ) : (
                      <div className="text-center py-2">
                        <p className="text-xs text-muted-foreground mb-2">No conversation yet</p>
                        <button
                          onClick={() => navigate('/home/chat')}
                          className="text-xs font-semibold text-primary hover:underline underline-offset-4"
                        >
                          Start your first conversation →
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Subsidiaries — only useful for super admins (can navigate to filtered conversations) and end users */}
              {subsidiaries.length > 0 && (isSuperAdmin || !isAdmin) && (
                <div className="rounded-2xl border bg-card overflow-hidden">
                  <div className="p-3 border-b flex items-center gap-2">
                    <Building2 className="h-4 w-4 text-primary" />
                    <h3 className="text-sm font-bold">Our Subsidiaries</h3>
                  </div>
                  <div className="divide-y">
                    {subsidiaries.map(sub => (
                      <button
                        key={sub.id}
                        onClick={() => navigate(isAdmin ? '/admin' : '/home/chat', { state: { subsidiaryId: sub.id } })}
                        className="w-full text-left flex items-center gap-3 px-3 py-2.5 hover:bg-muted/40 transition-colors group"
                      >
                        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                          <Building2 className="h-3.5 w-3.5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold truncate">{sub.name}</p>
                          {sub.description && <p className="text-[10px] text-muted-foreground truncate">{sub.description}</p>}
                        </div>
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}