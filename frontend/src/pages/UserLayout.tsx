import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  Home, MessageSquare, Megaphone, Settings,
  ChevronLeft, ChevronRight, Sparkles,
} from 'lucide-react'
import { AppHeader } from '@/components/layout/AppHeader'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Tooltip, TooltipContent, TooltipTrigger, TooltipProvider,
} from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useConversation } from '@/hooks/useMessages'
import { useAnnouncements } from '@/hooks/useAnnouncements'
import { useState } from 'react'

interface NavItem {
  path: string
  icon: typeof MessageSquare
  label: string
  exact: boolean
  badge?: 'unread' | 'announcements'
}

const NAV_ITEMS: NavItem[] = [
  { path: '/home', icon: Home, label: 'Home', exact: true },
  { path: '/home/chat', icon: MessageSquare, label: 'Messages', exact: true, badge: 'unread' },
  { path: '/home/announcements', icon: Megaphone, label: 'Announcements', exact: true, badge: 'announcements' },
  { path: '/home/settings', icon: Settings, label: 'Settings', exact: false },
]

export function UserLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem('user-nav-collapsed') === 'true' } catch { return false }
  })

  const { data: conversationData } = useConversation()
  const unreadCount = conversationData?.conversation?.unreadCount ?? 0
  const { data: announcementsData } = useAnnouncements()
  const activeAnnouncements = announcementsData?.announcements ?? []

  const toggleCollapsed = () => {
    const next = !collapsed
    setCollapsed(next)
    try { localStorage.setItem('user-nav-collapsed', String(next)) } catch { return }
  }

  const importantCount = activeAnnouncements.filter(a => a.type === 'IMPORTANT').length

  const getBadge = (item: NavItem) => {
    if (item.badge === 'unread') return unreadCount
    if (item.badge === 'announcements') return importantCount
    return 0
  }

  return (
    <TooltipProvider>
      <div className="fixed inset-0 flex flex-col bg-background">
        <AppHeader />
        <div className="flex flex-col sm:flex-row flex-1 overflow-hidden">
          {/* Desktop Sidebar */}
          <aside className={cn(
            'hidden sm:flex flex-col border-r bg-muted/20 transition-all duration-300',
            collapsed ? 'w-[60px]' : 'w-56'
          )}>
            {/* Header */}
            <div className={cn(
              'flex items-center h-12 px-3 border-b',
              collapsed ? 'justify-center' : 'justify-between'
            )}>
              {!collapsed && (
                <div className="flex items-center gap-2">
                  <div className="h-7 w-7 rounded-lg bg-gradient-to-br from-primary to-primary/70 flex items-center justify-center shadow-sm">
                    <Sparkles className="h-3.5 w-3.5 text-primary-foreground" />
                  </div>
                  <span className="text-sm font-bold">Menu</span>
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
            <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
              {NAV_ITEMS.map((item) => {
                const isActive = item.exact
                  ? location.pathname === item.path
                  : location.pathname.startsWith(item.path)
                const badgeCount = getBadge(item)

                const btn = (
                  <button
                    onClick={() => navigate(item.path)}
                    className={cn(
                      'relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all',
                      isActive
                        ? 'bg-primary/10 text-primary shadow-sm'
                        : 'text-muted-foreground hover:text-foreground hover:bg-accent/50',
                      collapsed && 'justify-center px-2',
                    )}
                  >
                    {isActive && (
                      <div className="absolute left-0 top-1/2 -translate-y-1/2 h-6 w-1 rounded-r-full bg-primary" />
                    )}
                    <div className="relative shrink-0">
                      <item.icon className={cn('h-[18px] w-[18px]', isActive && 'text-primary')} />
                      {collapsed && badgeCount > 0 && (
                        <span className={cn(
                          'absolute -top-1 -right-1.5 flex h-4 w-4 items-center justify-center rounded-full text-[8px] font-bold text-primary-foreground',
                          item.badge === 'unread' ? 'bg-destructive' : 'bg-primary',
                        )}>
                          {badgeCount > 9 ? '9+' : badgeCount}
                        </span>
                      )}
                    </div>
                    {!collapsed && (
                      <>
                        <span className="flex-1 text-left truncate">{item.label}</span>
                        {badgeCount > 0 && item.badge === 'unread' && (
                          <Badge variant="default" className="h-5 min-w-5 px-1.5 text-[10px] rounded-full bg-destructive tabular-nums">
                            {badgeCount > 9 ? '9+' : badgeCount}
                          </Badge>
                        )}
                        {badgeCount > 0 && item.badge === 'announcements' && (
                          <Badge variant="secondary" className="h-5 min-w-5 px-1.5 text-[10px] rounded-full tabular-nums">
                            {badgeCount > 9 ? '9+' : badgeCount}
                          </Badge>
                        )}
                      </>
                    )}
                  </button>
                )

                if (collapsed) {
                  return (
                    <Tooltip key={item.path} delayDuration={0}>
                      <TooltipTrigger asChild>{btn}</TooltipTrigger>
                      <TooltipContent side="right" className="text-xs">
                        {item.label}
                        {badgeCount > 0 && (
                          <span className={cn('ml-1 font-bold', item.badge === 'unread' ? 'text-destructive' : 'text-primary')}>
                            ({badgeCount})
                          </span>
                        )}
                      </TooltipContent>
                    </Tooltip>
                  )
                }
                return <div key={item.path}>{btn}</div>
              })}
            </nav>
          </aside>

          {/* Main Content */}
          <main className="flex-1 min-h-0 overflow-hidden flex flex-col pb-[calc(60px+env(safe-area-inset-bottom))] sm:pb-0">
            <Outlet />
          </main>

          {/* Mobile Bottom Nav */}
          <div className="sm:hidden fixed bottom-0 left-0 w-full border-t border-sidebar-border bg-background/95 backdrop-blur z-50 flex items-center justify-around h-[calc(60px+env(safe-area-inset-bottom))] px-2 pb-[env(safe-area-inset-bottom)] shadow-[0_-4px_24px_-8px_rgba(0,0,0,0.1)]">
            {NAV_ITEMS.map((item) => {
              const isActive = item.exact
                ? location.pathname === item.path
                : location.pathname.startsWith(item.path)
              const badgeCount = getBadge(item)

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
                      <span className={cn(
                        'absolute -top-1 -right-2 flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold text-white shadow-sm',
                        item.badge === 'unread' ? 'bg-destructive' : 'bg-primary'
                      )}>
                        {badgeCount > 9 ? '9+' : badgeCount}
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] font-medium truncate w-full text-center leading-none">{item.label}</span>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}
