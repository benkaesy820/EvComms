import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  Users, MessageSquare, Shield, ScrollText, Megaphone,
  LayoutDashboard, ChevronLeft, ChevronRight, MessageSquareLock, MessageCircle,
  UserCheck, Sparkles, Settings, Home,
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
import { useQuery } from '@tanstack/react-query'
import { adminStats } from '@/lib/api'
import type { Role } from '@/lib/schemas'
import { useState, useEffect, useMemo } from 'react'
import { getSocket } from '@/lib/socket'
import { useAppConfig } from '@/hooks/useConfig'

interface NavItem {
  path: string
  icon: typeof MessageSquare
  label: string
  exact: boolean
  minRole?: Role
  showBadge?: 'users' | 'conversations' | 'team' | 'dm'
  group: 'main' | 'manage'
}

const NAV_ITEMS: NavItem[] = [
  { path: '/admin/home', icon: Home, label: 'Dashboard', exact: true, group: 'main' },
  { path: '/admin', icon: MessageSquare, label: 'Conversations', exact: true, showBadge: 'conversations', group: 'main' },
  { path: '/admin/internal', icon: MessageSquareLock, label: 'Team Chat', exact: false, showBadge: 'team', group: 'main' },
  { path: '/admin/dm', icon: MessageCircle, label: 'Direct Messages', exact: false, showBadge: 'dm', group: 'main' },
  { path: '/admin/users', icon: Users, label: 'Users', exact: false, showBadge: 'users', group: 'manage' },
  { path: '/admin/announcements', icon: Megaphone, label: 'Announcements', exact: false, group: 'manage' },
  { path: '/admin/admins', icon: Shield, label: 'Admins', exact: false, minRole: 'SUPER_ADMIN', group: 'manage' },
  { path: '/admin/audit', icon: ScrollText, label: 'Audit Logs', exact: false, group: 'manage' },
  { path: '/admin/settings', icon: Settings, label: 'Settings', exact: true, group: 'manage' },
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
  const [teamUnread, setTeamUnread] = useState(0)
  const [dmUnread, setDmUnread] = useState(0)

  const { data: convData } = useAdminConversations()
  const { data: statsData } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: () => adminStats.get(),
    staleTime: 60_000,
  })

  useEffect(() => {
    if (location.pathname.startsWith('/admin/internal')) {
      setTeamUnread(0); return
    }
    const socket = getSocket()
    if (!socket) return
    const currentUserId = useAuthStore.getState().user?.id
    const onInternal = (data: { message: { senderId: string } }) => {
      if (data.message.senderId === currentUserId) return
      setTeamUnread((n) => n + 1)
    }
    socket.on('internal:message', onInternal)
    return () => { socket.off('internal:message', onInternal) }
  }, [location.pathname])

  useEffect(() => {
    if (location.pathname.startsWith('/admin/dm')) {
      setDmUnread(0); return
    }
    const socket = getSocket()
    if (!socket) return
    const currentUserId = useAuthStore.getState().user?.id
    const onDM = (data: { message: { senderId: string } }) => {
      if (data.message.senderId === currentUserId) return
      setDmUnread((n) => n + 1)
    }
    socket.on('dm:message', onDM)
    return () => { socket.off('dm:message', onDM) }
  }, [location.pathname])

  const pendingUsers = statsData?.stats?.users?.pending ?? 0
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

  const getBadgeCount = (item: NavItem) => {
    if (item.showBadge === 'users') return pendingUsers
    if (item.showBadge === 'conversations') return unreadConversations
    if (item.showBadge === 'team') return teamUnread
    if (item.showBadge === 'dm') return dmUnread
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
            {!collapsed && (
              <div className="p-3 border-t border-sidebar-border">
                {userRole === 'ADMIN' ? (
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
                    <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                      <p className="text-sidebar-foreground/70 mb-0.5">Users</p>
                      <p className="font-bold text-sm tabular-nums">{statsData.stats.users.total}</p>
                    </div>
                    <div className="rounded-lg bg-background/50 p-2 text-center border border-sidebar-border">
                      <p className="text-sidebar-foreground/70 mb-0.5">Messages</p>
                      <p className="font-bold text-sm tabular-nums">{statsData.stats.messages}</p>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </aside>

          {/* Main Content */}
          <main className="flex-1 min-h-0 overflow-hidden flex flex-col pb-[calc(60px+env(safe-area-inset-bottom))] sm:pb-0">
            <Outlet />
          </main>

          {/* Mobile Bottom Nav */}
          <div className="sm:hidden fixed bottom-0 left-0 w-full border-t border-sidebar-border bg-background/95 backdrop-blur z-50 flex items-center justify-around h-[calc(60px+env(safe-area-inset-bottom))] px-2 pb-[env(safe-area-inset-bottom)] shadow-[0_-4px_24px_-8px_rgba(0,0,0,0.1)]">
            {visibleItems.slice(0, 4).map((item) => {
              const isActive = item.exact
                ? location.pathname === item.path
                : location.pathname.startsWith(item.path)
              const badgeCount = getBadgeCount(item)
              return (
                <button
                  key={item.path}
                  className={cn(
                    'flex flex-col items-center justify-center gap-1 shrink-0 w-16 h-full transition-colors relative',
                    isActive
                      ? 'text-primary'
                      : 'text-muted-foreground hover:text-foreground',
                  )}
                  onClick={() => navigate(item.path)}
                >
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

            {/* Menu Drawer for leftover items */}
            {visibleItems.length > 4 && (
              <Sheet>
                <SheetTrigger asChild>
                  <button className="flex flex-col items-center justify-center gap-1 shrink-0 w-16 h-full transition-colors relative text-muted-foreground hover:text-foreground">
                    <LayoutDashboard className="h-[22px] w-[22px]" />
                    <span className="text-[10px] font-medium truncate w-full text-center leading-none">Menu</span>
                  </button>
                </SheetTrigger>
                <SheetContent side="bottom" className="h-[75vh] p-0 flex flex-col rounded-t-2xl">
                  <SheetHeader className="p-4 border-b text-left shrink-0">
                    <SheetTitle>Menu</SheetTitle>
                  </SheetHeader>
                  <nav className="flex-1 overflow-y-auto p-4 space-y-2">
                    {visibleItems.slice(4).map(item => {
                      const isActive = item.exact ? location.pathname === item.path : location.pathname.startsWith(item.path)
                      const badgeCount = getBadgeCount(item)
                      return (
                        <button
                          key={item.path}
                          onClick={() => navigate(item.path)}
                          className={cn(
                            'flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm font-medium transition-all',
                            isActive ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted'
                          )}
                        >
                          <item.icon className="h-5 w-5" />
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
            )}
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}
