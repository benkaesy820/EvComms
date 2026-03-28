import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  Users, MessageSquare, Shield, ScrollText, Megaphone, Crown,
  LayoutDashboard, ChevronLeft, ChevronRight, MessageSquareLock, MessageCircle,
  UserCheck, Sparkles, Settings, Home, FileWarning, ClipboardList, MoreHorizontal, Palette,
} from 'lucide-react'
import { AppHeader } from '@/components/layout/AppHeader'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import {
  Tooltip, TooltipContent, TooltipTrigger, TooltipProvider,
} from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { useAdminConversations } from '@/hooks/useMessages'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { adminStats } from '@/lib/api'
import type { Role } from '@/lib/schemas'
import { useState, useEffect, useMemo } from 'react'
import { getSocket } from '@/lib/socket'
import { useAppConfig } from '@/hooks/useConfig'
import { useDMUnreadCount, CONVOS_KEY as DM_CONVOS_KEY } from '@/hooks/useDM'
import { useInternalUnreadCount, INTERNAL_UNREAD_KEY, useMarkInternalRead } from '@/hooks/useInternalChat'
import { useReportStatusListener, useReports } from '@/hooks/useReports'
import { useAdminUserReports } from '@/hooks/useUserReports'

interface NavItem {
  path: string
  icon: typeof MessageSquare
  label: string
  exact: boolean
  minRole?: Role
  showBadge?: 'users' | 'conversations' | 'team' | 'dm' | 'reports' | 'user-reports'
  group: 'main' | 'manage'
}

const NAV_ITEMS: NavItem[] = [
  { path: '/admin/home', icon: Home, label: 'Dashboard', exact: true, group: 'main' },
  { path: '/admin', icon: MessageSquare, label: 'Conversations', exact: true, showBadge: 'conversations', group: 'main' },
  { path: '/admin/users', icon: Users, label: 'Users', exact: false, showBadge: 'users', group: 'main' },
  { path: '/admin/internal', icon: MessageSquareLock, label: 'Team Chat', exact: false, showBadge: 'team', group: 'main' },
  { path: '/admin/dm', icon: MessageCircle, label: 'Direct Messages', exact: false, showBadge: 'dm', group: 'manage' },
  { path: '/admin/announcements', icon: Megaphone, label: 'Announcements', exact: false, group: 'manage' },
  { path: '/admin/user-reports', icon: FileWarning, label: 'User Reports', exact: false, showBadge: 'user-reports', group: 'manage' },
  { path: '/admin/reports', icon: ClipboardList, label: 'Registration Reports', exact: false, minRole: 'SUPER_ADMIN', showBadge: 'reports', group: 'manage' },
  { path: '/admin/admins', icon: Shield, label: 'Admins', exact: false, minRole: 'SUPER_ADMIN', group: 'manage' },
  { path: '/admin/audit', icon: ScrollText, label: 'Audit Logs', exact: false, minRole: 'SUPER_ADMIN', group: 'manage' },
  { path: '/admin/settings', icon: Settings, label: 'Settings', exact: true, group: 'manage' },
  { path: '/admin/brand', icon: Palette, label: 'Brand & Storefront', exact: false, minRole: 'SUPER_ADMIN', group: 'manage' },
]

function NavButton({
  item,
  isActive,
  badgeCount,
  collapsed,
  onClick,
}: {
  item: NavItem
  isActive: boolean
  badgeCount: number
  collapsed: boolean
  onClick: () => void
}) {
  const btn = (
    <button
      onClick={onClick}
      className={cn(
        'relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all',
        isActive
          ? 'bg-sidebar-accent text-sidebar-accent-foreground font-semibold shadow-sm'
          : 'text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent/50',
        collapsed && 'justify-center px-2',
      )}
    >
      {/* Active indicator */}
      {isActive && (
        <div className="absolute left-0 top-1/2 -translate-y-1/2 h-6 w-1 rounded-r-full bg-sidebar-primary" />
      )}
      <div className="relative shrink-0">
        <item.icon className={cn('h-[18px] w-[18px]', isActive && 'text-sidebar-primary')} />
        {collapsed && badgeCount > 0 && (
          <span className="absolute -top-1 -right-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-sidebar-primary text-[8px] font-bold text-sidebar-primary-foreground">
            {badgeCount > 9 ? '9+' : badgeCount}
          </span>
        )}
      </div>
      {!collapsed && (
        <>
          <span className="flex-1 text-left truncate">{item.label}</span>
          {badgeCount > 0 && (
            <Badge variant="default" className="h-5 min-w-5 px-1.5 text-[10px] rounded-full tabular-nums">
              {badgeCount > 99 ? '99+' : badgeCount}
            </Badge>
          )}
        </>
      )}
    </button>
  )

  if (collapsed) {
    return (
      <Tooltip delayDuration={0}>
        <TooltipTrigger asChild>{btn}</TooltipTrigger>
        <TooltipContent side="right" className="text-xs">
          {item.label}
          {badgeCount > 0 && <span className="ml-1 text-primary font-bold">({badgeCount})</span>}
        </TooltipContent>
      </Tooltip>
    )
  }
  return btn
}

export function AdminLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const user = useAuthStore((s) => s.user)
  const userRole = user?.role
  const { data: configData } = useAppConfig()
  const siteName = configData?.brand?.siteName || 'Admin'
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem('admin-nav-collapsed') === 'true' } catch { return false }
  })
  // Read pending report count directly from React Query cache — useReportStatusListener
  // keeps this up-to-date in real time so the badge clears immediately on approval.
  const { data: pendingReportsData } = useReports('PENDING')
  const pendingReports = pendingReportsData?.pendingCount ?? 0
  // Derive pending user-reports count from live query instead of local state.
  const { data: adminUserReportsData } = useAdminUserReports()
  const pendingUserReports = adminUserReportsData?.pendingCount ?? 0
  const queryClient = useQueryClient()

  const { data: convData } = useAdminConversations()
  const { data: statsData } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: () => adminStats.get(),
    staleTime: 0,
  })

  // Single source of truth: server queries for unread counts.
  // Socket events simply invalidate these queries — no local counters to drift.
  const { data: dmUnreadData } = useDMUnreadCount()
  const { data: teamUnreadData } = useInternalUnreadCount()
  const markInternalRead = useMarkInternalRead()
  useReportStatusListener() // Listen for real-time report updates

  // When landing on /admin/internal, mark internal messages read
  useEffect(() => {
    if (location.pathname.startsWith('/admin/internal')) {
      markInternalRead.mutate()
    }
  }, [location.pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  // Socket → invalidate server counts (no local state, avoids double-counting)
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const currentUserId = useAuthStore.getState().user?.id

    const onInternal = (data: { message: { senderId: string } }) => {
      if (data.message.senderId === currentUserId) return
      if (!location.pathname.startsWith('/admin/internal')) {
        queryClient.invalidateQueries({ queryKey: INTERNAL_UNREAD_KEY })
      }
    }
    const onDM = (data: { message: { senderId: string } }) => {
      if (data.message.senderId === currentUserId) return
      if (!location.pathname.startsWith('/admin/dm')) {
        queryClient.invalidateQueries({ queryKey: ['dm', 'unread'] })
        queryClient.invalidateQueries({ queryKey: DM_CONVOS_KEY })
      }
    }

    socket.on('internal:message', onInternal)
    socket.on('dm:message', onDM)
    return () => {
      socket.off('internal:message', onInternal)
      socket.off('dm:message', onDM)
    }
  }, [location.pathname, queryClient])

  // Listen for new user registrations to update the reports & stats badge
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onRegistered = () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
    }
    socket.on('admin:user_registered', onRegistered)
    return () => { socket.off('admin:user_registered', onRegistered) }
  }, [queryClient])

  // Optimistically bump pendingCount when a new user report arrives, then sync from server
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onNewReport = () => {
      // Immediately increment the badge — no waiting for a network round-trip
      queryClient.setQueriesData<{ reports: unknown[]; hasMore: boolean; pendingCount: number }>(
        { queryKey: ['admin', 'user-reports'] },
        (old) => old ? { ...old, pendingCount: old.pendingCount + 1 } : old,
      )
      // Then refetch in the background to get the full updated list
      queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
    }
    socket.on('user_report:new', onNewReport)
    return () => { socket.off('user_report:new', onNewReport) }
  }, [queryClient])

  // Invalidate stats when a user status changes (approval/rejection/suspension)
  // so the pending-users sidebar badge clears immediately without waiting for TTL.
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onStatsInvalidate = () => queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
    socket.on('stats:invalidate', onStatsInvalidate)
    return () => { socket.off('stats:invalidate', onStatsInvalidate) }
  }, [queryClient])

  const pendingUsers = statsData?.stats?.scope === 'super_admin'
    ? (statsData.stats.users?.pending ?? 0)
    : 0
  const { unreadConversations, assignedCount } = useMemo(() => {
    const convs = convData?.pages?.flatMap(p => p.conversations) ?? []
    return {
      unreadConversations: convs.filter(c => (c.adminUnreadCount ?? 0) > 0).length,
      assignedCount: convs.length,
    }
  }, [convData])

  const visibleItems = NAV_ITEMS.filter((item) => {
    if (!item.minRole) return true
    if (item.minRole === 'SUPER_ADMIN') return userRole === 'SUPER_ADMIN'
    return true
  })

  const mainItems = visibleItems.filter(i => i.group === 'main')
  const manageItems = visibleItems.filter(i => i.group === 'manage')

  // Single source of truth from server queries (invalidated by socket events above)
  const totalDmUnread = dmUnreadData?.unreadCount ?? 0
  const totalTeamUnread = teamUnreadData?.unreadCount ?? 0

  // Suppress the conversations nav badge when the admin is already on the conversations
  // page — they are actively reading, so flashing a count is misleading noise.
  const isOnConversationsPage = location.pathname === '/admin' || location.pathname === '/admin/'
  const isOnTeamChatPage = location.pathname.startsWith('/admin/internal')
  const isOnDMPage = location.pathname.startsWith('/admin/dm')

  const getBadgeCount = (item: NavItem) => {
    if (item.showBadge === 'users') return pendingUsers
    if (item.showBadge === 'conversations') return isOnConversationsPage ? 0 : unreadConversations
    if (item.showBadge === 'team') return isOnTeamChatPage ? 0 : totalTeamUnread
    if (item.showBadge === 'dm') return isOnDMPage ? 0 : totalDmUnread
    if (item.showBadge === 'reports') return pendingReports
    if (item.showBadge === 'user-reports') return pendingUserReports
    return 0
  }

  const toggleCollapsed = () => {
    const next = !collapsed
    setCollapsed(next)
    try { localStorage.setItem('admin-nav-collapsed', String(next)) } catch { return }
  }

  const renderNavGroup = (items: NavItem[], label?: string) => (
    <div className="space-y-0.5">
      {label && !collapsed && (
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 px-3 mb-1.5">
          {label}
        </p>
      )}
      {collapsed && label && <div className="mx-3 border-t my-2" />}
      {items.map((item) => {
        const isActive = item.exact
          ? location.pathname === item.path
          : location.pathname.startsWith(item.path)
        return (
          <NavButton
            key={item.path}
            item={item}
            isActive={isActive}
            badgeCount={getBadgeCount(item)}
            collapsed={collapsed}
            onClick={() => navigate(item.path)}
          />
        )
      })}
    </div>
  )

  return (
    <TooltipProvider>
      <div className="fixed inset-0 flex flex-col bg-background">
        <AppHeader />
        <div className="flex flex-col sm:flex-row flex-1 overflow-hidden relative">
          {/* Desktop Sidebar */}
          <aside className={cn(
            'hidden sm:flex flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-all duration-300 relative z-20',
            collapsed ? 'w-[68px]' : 'w-[280px]'
          )}>
            {/* Header */}
            <div className={cn(
              'flex items-center h-[60px] px-3 border-b border-sidebar-border',
              collapsed ? 'justify-center' : 'justify-between'
            )}>
              {!collapsed && (
                <div className="flex items-center gap-2">
                  <div className="h-7 w-7 rounded-lg bg-gradient-to-br from-primary to-primary/70 flex items-center justify-center shadow-sm">
                    <LayoutDashboard className="h-3.5 w-3.5 text-primary-foreground" />
                  </div>
                  <div>
                    <span className="text-sm font-bold">{siteName}</span>
                    <Sparkles className="inline h-3 w-3 ml-1 text-amber-500" />
                  </div>
                </div>
              )}
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 rounded-lg"
                onClick={toggleCollapsed}
                aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
              </Button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-2 space-y-3 overflow-y-auto">
              {renderNavGroup(mainItems, 'Messaging')}
              {renderNavGroup(manageItems, 'Manage')}
            </nav>

            {/* Stats Footer */}
            <div className="p-3 border-t border-sidebar-border space-y-3">
              {/* Role identity badge — always visible, adapts to collapsed state */}
              {collapsed ? (
                <Tooltip delayDuration={0}>
                  <TooltipTrigger asChild>
                    <div className={cn(
                      'flex items-center justify-center w-full py-2 rounded-lg border cursor-default',
                      userRole === 'SUPER_ADMIN'
                        ? 'bg-primary/10 border-primary/20 text-primary'
                        : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400'
                    )}>
                      {userRole === 'SUPER_ADMIN'
                        ? <Crown className="h-3.5 w-3.5" />
                        : <Shield className="h-3.5 w-3.5" />}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="right" className="text-xs">
                    {userRole === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin (Limited)'}
                  </TooltipContent>
                </Tooltip>
              ) : (
                <div className={cn(
                  'flex items-center gap-2 px-3 py-2 rounded-lg border text-[11px] font-medium',
                  userRole === 'SUPER_ADMIN'
                    ? 'bg-primary/10 border-primary/20 text-primary'
                    : 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400'
                )}>
                  {userRole === 'SUPER_ADMIN'
                    ? <Crown className="h-3.5 w-3.5 shrink-0" />
                    : <Shield className="h-3.5 w-3.5 shrink-0" />}
                  <span>{userRole === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'}</span>
                  {userRole !== 'SUPER_ADMIN' && (
                    <span className="ml-auto text-[10px] text-amber-600/60 dark:text-amber-400/60 font-normal">Limited</span>
                  )}
                </div>
              )}
              {!collapsed && (userRole === 'ADMIN' ? (
                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                      <div className="flex items-center justify-center gap-1 text-sidebar-foreground/70 mb-0.5">
                        <UserCheck className="h-3 w-3" />
                        <span>Assigned</span>
                      </div>
                      <p className="font-bold text-sm tabular-nums">{assignedCount}</p>
                    </div>
                    <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                      <p className="text-sidebar-foreground/70 mb-0.5">Unread</p>
                      <p className={cn('font-bold text-sm tabular-nums', unreadConversations > 0 && 'text-sidebar-primary')}>{unreadConversations}</p>
                    </div>
                  </div>
                ) : statsData?.stats ? (
                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    {statsData.stats.users ? (
                      <>
                        <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                          <p className="text-sidebar-foreground/70 mb-0.5">Users</p>
                          <p className="font-bold text-sm tabular-nums">{statsData.stats.users.total}</p>
                        </div>
                        <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                          <p className="text-sidebar-foreground/70 mb-0.5">Messages</p>
                          <p className="font-bold text-sm tabular-nums">{statsData.stats.messages}</p>
                        </div>
                      </>
                    ) : statsData.stats.conversations && typeof statsData.stats.conversations === 'object' ? (
                      <>
                        <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                          <p className="text-sidebar-foreground/70 mb-0.5">Assigned</p>
                          <p className="font-bold text-sm tabular-nums">{(statsData.stats.conversations as { assigned: number; waiting: number }).assigned}</p>
                        </div>
                        <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                          <p className="text-sidebar-foreground/70 mb-0.5">Waiting</p>
                          <p className={cn('font-bold text-sm tabular-nums', (statsData.stats.conversations as { assigned: number; waiting: number }).waiting > 0 && 'text-destructive')}>{(statsData.stats.conversations as { assigned: number; waiting: number }).waiting}</p>
                        </div>
                      </>
                    ) : null}
                  </div>
                ) : null)}
            </div>
          </aside>

          {/* Main Content */}
          <main className="flex-1 min-h-0 overflow-hidden flex flex-col pb-[calc(60px+env(safe-area-inset-bottom))] sm:pb-0">
            <Outlet />
          </main>

          {/* Mobile Bottom Nav - FIX #15: active route always visible, swapped into first 4 slots */}
          <div className="sm:hidden fixed bottom-0 left-0 w-full border-t border-sidebar-border bg-background/95 backdrop-blur z-50 flex items-center justify-around h-[calc(60px+env(safe-area-inset-bottom))] px-1 pb-[env(safe-area-inset-bottom)] shadow-[0_-4px_24px_-8px_rgba(0,0,0,0.1)]">
            {(() => {
              // Find the currently active item
              const activeItem = visibleItems.find(item =>
                item.exact ? location.pathname === item.path : location.pathname.startsWith(item.path)
              )
              // Build the 4 visible slots: if active item is beyond slot 4, swap it into slot 3
              let mobileSlots = visibleItems.slice(0, 4)
              if (activeItem && !mobileSlots.includes(activeItem)) {
                mobileSlots = [...visibleItems.slice(0, 3), activeItem]
              }
              const overflowItems = visibleItems.filter(item => !mobileSlots.includes(item))

              return (
                <>
                  {mobileSlots.map((item) => {
                    const isActive = item.exact
                      ? location.pathname === item.path
                      : location.pathname.startsWith(item.path)
                    const badgeCount = getBadgeCount(item)
                    return (
                      <button
                        key={item.path}
                        className={cn(
                          'flex flex-col items-center justify-center gap-0.5 shrink-0 flex-1 h-full transition-colors relative py-1 min-w-0',
                          isActive
                            ? 'text-primary'
                            : 'text-muted-foreground hover:text-foreground',
                        )}
                        onClick={() => navigate(item.path)}
                      >
                        {isActive && (
                          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-8 h-0.5 rounded-full bg-primary" />
                        )}
                        <div className="relative">
                          <item.icon className={cn('h-[22px] w-[22px]', isActive && 'fill-primary/20')} />
                          {badgeCount > 0 && (
                            <span className="absolute -top-1 -right-2 flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[9px] font-bold text-destructive-foreground shadow-sm">
                              {badgeCount > 9 ? '9+' : badgeCount}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] font-medium truncate w-full text-center leading-none">{item.label.split(' ')[0]}</span>
                      </button>
                    )
                  })}

                  {overflowItems.length > 0 && (() => {
                    const overflowHasActive = overflowItems.some(item =>
                      item.exact ? location.pathname === item.path : location.pathname.startsWith(item.path)
                    )
                    const totalOverflowBadge = overflowItems.reduce((sum, item) => sum + getBadgeCount(item), 0)
                    return (
                      <Sheet>
                        <SheetTrigger asChild>
                          <button className={cn(
                            'flex flex-col items-center justify-center gap-0.5 shrink-0 flex-1 h-full transition-colors relative py-1 min-w-0',
                            overflowHasActive ? 'text-primary' : 'text-muted-foreground hover:text-foreground'
                          )}>
                            {overflowHasActive && (
                              <div className="absolute top-0 left-1/2 -translate-x-1/2 w-8 h-0.5 rounded-full bg-primary" />
                            )}
                            <div className="relative">
                              <MoreHorizontal className="h-[22px] w-[22px]" />
                              {totalOverflowBadge > 0 && (
                                <span className="absolute -top-1 -right-2 flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[9px] font-bold text-destructive-foreground shadow-sm">
                                  {totalOverflowBadge > 9 ? '9+' : totalOverflowBadge}
                                </span>
                              )}
                            </div>
                            <span className="text-[10px] font-medium text-center leading-none">More</span>
                          </button>
                        </SheetTrigger>
                        <SheetContent side="bottom" className="h-[75vh] p-0 flex flex-col rounded-t-2xl">
                          <SheetHeader className="p-4 border-b text-left shrink-0">
                            <SheetTitle>Menu</SheetTitle>
                          </SheetHeader>
                          <nav className="flex-1 overflow-y-auto p-4 space-y-1">
                            {overflowItems.map(item => {
                              const isActive = item.exact ? location.pathname === item.path : location.pathname.startsWith(item.path)
                              const badgeCount = getBadgeCount(item)
                              return (
                                <button
                                  key={item.path}
                                  onClick={() => navigate(item.path)}
                                  className={cn(
                                    'flex w-full items-center gap-3 rounded-xl px-4 py-3.5 text-sm font-medium transition-all min-h-[52px]',
                                    isActive ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted'
                                  )}
                                >
                                  <item.icon className="h-5 w-5 shrink-0" />
                                  <span className="flex-1 text-left">{item.label}</span>
                                  {badgeCount > 0 && (
                                    <Badge variant="destructive" className="h-5 px-2 rounded-full tabular-nums">
                                      {badgeCount}
                                    </Badge>
                                  )}
                                </button>
                              )
                            })}
                          </nav>
                        </SheetContent>
                      </Sheet>
                    )
                  })()}
                </>
              )
            })()}
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}
