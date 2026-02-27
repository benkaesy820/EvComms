import {
  MessageSquare, LogOut, Settings, Shield, Home, ChevronDown, Users,
} from 'lucide-react'
import { GlobalSearch } from '@/components/admin/GlobalSearch'
import { useNavigate, useLocation } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { useAuthStore } from '@/stores/authStore'
import { useConversation } from '@/hooks/useMessages'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { cn, getInitials } from '@/lib/utils'
import { useAppConfig } from '@/hooks/useConfig'

function NavLink({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'relative flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg transition-colors',
        active
          ? 'text-primary bg-primary/8'
          : 'text-muted-foreground hover:text-foreground hover:bg-accent',
      )}
    >
      {children}
    </button>
  )
}

export function AppHeader() {
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const navigate = useNavigate()
  const location = useLocation()
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const { data: conversationData } = useConversation()
  const unreadCount = !isAdmin ? (conversationData?.conversation?.unreadCount ?? 0) : 0

  const { data: configData } = useAppConfig()
  const siteName = configData?.brand?.siteName || 'Customer Hub'

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const initials = user?.name ? getInitials(user.name) : '?'

  return (
    <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex h-14 items-center gap-4 px-4 lg:px-6">
        {/* Logo */}
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2.5 shrink-0 group"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground transition-transform group-hover:scale-105">
            <LeafLogo className="h-4.5 w-4.5" />
          </div>
          <span className="hidden sm:inline text-sm font-bold tracking-tight">
            {siteName}
          </span>
        </button>

        <Separator orientation="vertical" className="hidden sm:block h-6" />

        {/* Navigation */}
        <nav className="flex items-center gap-0 sm:gap-1">
          <NavLink
            active={isAdmin ? location.pathname.startsWith('/admin') || location.pathname === '/' : location.pathname.startsWith('/home')}
            onClick={() => navigate(isAdmin ? '/admin/home' : '/home')}
          >
            <Home className="h-4 w-4 shrink-0" />
            <span className="hidden lg:inline">Home</span>
          </NavLink>
          {!isAdmin && (
            <NavLink
              active={location.pathname === '/home/chat' || location.pathname === '/chat'}
              onClick={() => navigate('/home/chat')}
            >
              <MessageSquare className="h-4 w-4 shrink-0" />
              <span className="hidden lg:inline">Messages</span>
              {unreadCount > 0 && (
                <Badge className="ml-1 h-3 min-w-3 px-1 text-[9px] bg-destructive text-destructive-foreground">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </Badge>
              )}
            </NavLink>
          )}
          {isAdmin && (
            <NavLink active={location.pathname.startsWith('/admin/users')} onClick={() => navigate('/admin/users')}>
              <Users className="h-4 w-4 shrink-0" />
              <span className="hidden lg:inline">Users</span>
            </NavLink>
          )}
        </nav>

        {/* Admin search */}
        {isAdmin && (
          <div className="flex-1 flex justify-center px-2 sm:px-4 min-w-0">
            <GlobalSearch />
          </div>
        )}
        {!isAdmin && <div className="flex-1 min-w-0" />}

        {/* Right section */}
        <div className="flex items-center gap-1 sm:gap-2 shrink-0">
          <ThemeToggle />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2 pl-2 pr-2.5 h-9 rounded-lg shrink-0">
                <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">
                  {initials}
                </div>
                <span className="hidden md:inline text-sm font-medium truncate max-w-[120px]">
                  {user?.name}
                </span>
                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <div className="px-3 py-2.5">
                <p className="text-sm font-semibold truncate">{user?.name}</p>
                <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => navigate(isAdmin ? '/admin/settings' : '/home/settings')} className="gap-2 cursor-pointer">
                <Settings className="h-4 w-4" />
                Settings
              </DropdownMenuItem>
              {isAdmin && (
                <DropdownMenuItem onClick={() => navigate('/admin')} className="gap-2 cursor-pointer">
                  <Shield className="h-4 w-4" />
                  Admin Panel
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={handleLogout}
                className="gap-2 cursor-pointer text-destructive focus:text-destructive"
              >
                <LogOut className="h-4 w-4" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
