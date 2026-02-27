import { useState, useEffect, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Search, Users, MessageSquare, Megaphone, X, CheckCircle, UserCog, ArrowRight } from 'lucide-react'
import { cn, getInitials } from '@/lib/utils'
import { adminSearch, adminUsers, type SearchResults } from '@/lib/api'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { useAuthStore } from '@/stores/authStore'
import type { InfiniteData } from '@tanstack/react-query'

type SearchType = 'all' | 'users' | 'conversations' | 'announcements' | 'messages'

const TYPE_TABS: { id: SearchType; label: string; icon: typeof Search }[] = [
  { id: 'all', label: 'All', icon: Search },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'conversations', label: 'Chats', icon: MessageSquare },
  { id: 'announcements', label: 'Posts', icon: Megaphone },
]

const STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  APPROVED: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  REJECTED: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  SUSPENDED: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
}

function highlight(text: string, q: string): React.ReactNode {
  if (!q.trim()) return text
  const idx = text.toLowerCase().indexOf(q.toLowerCase())
  if (idx === -1) return text
  return (
    <>
      {text.slice(0, idx)}
      <mark className="bg-primary/25 text-foreground rounded-sm not-italic">{text.slice(idx, idx + q.length)}</mark>
      {text.slice(idx + q.length)}
    </>
  )
}

export function GlobalSearch() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [debouncedQ, setDebouncedQ] = useState('')
  const [activeType, setActiveType] = useState<SearchType>('all')
  const [approvingId, setApprovingId] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'

  // Debounce query
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(query.trim()), 300)
    return () => clearTimeout(t)
  }, [query])

  // Keyboard shortcut Ctrl+K / Cmd+K + Escape to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  // Focus input when opened
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 30)
  }, [open])

  // Lock body scroll while open (the body already has overflow-hidden for chat, this is a safety net)
  useEffect(() => {
    if (!open) return
    return () => { /* noop */ }
  }, [open])

  const { data, isFetching } = useQuery({
    queryKey: ['admin', 'search', debouncedQ, activeType],
    queryFn: () => adminSearch.search(debouncedQ, activeType, 8),
    enabled: debouncedQ.length >= 1,
    staleTime: 15_000,
  })

  const results: SearchResults = {
    users: data?.users ?? [],
    conversations: data?.conversations ?? [],
    announcements: data?.announcements ?? [],
    messages: data?.messages ?? [],
  }

  const hasResults =
    results.users.length + results.conversations.length +
    results.announcements.length + results.messages.length > 0

  const handleApprove = useCallback(async (userId: string, userName: string) => {
    setApprovingId(userId)
    try {
      await adminUsers.updateStatus(userId, { status: 'APPROVED' })
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: Array<{ id: string; status: string;[key: string]: unknown }>; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              users: page.users.map((u) => u.id === userId ? { ...u, status: 'APPROVED' } : u),
            })),
          }
        },
      )
      queryClient.invalidateQueries({ queryKey: ['admin', 'search'] })
      toast.success(`${userName} approved`)
    } catch {
      toast.error('Failed to approve user')
    } finally {
      setApprovingId(null)
    }
  }, [queryClient])

  const go = (path: string) => {
    navigate(path)
    setOpen(false)
    setQuery('')
    setDebouncedQ('')
  }

  const close = () => {
    setOpen(false)
    setQuery('')
    setDebouncedQ('')
  }

  // ─── Trigger button (always visible in header) ────────────────────────
  const trigger = (
    <button
      onClick={() => setOpen(true)}
      className="flex items-center gap-2 h-9 px-3 rounded-xl border border-border/40 bg-accent/20 text-muted-foreground text-[13px] hover:bg-accent/40 shadow-sm transition-all w-full max-w-[200px] md:max-w-[260px]"
      aria-label="Open search"
    >
      <Search className="h-3.5 w-3.5 shrink-0" />
      <span className="flex-1 text-left truncate">Search...</span>
      <kbd className="hidden md:inline-flex h-5 select-none items-center gap-0.5 rounded border bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground opacity-70">
        ⌘K
      </kbd>
    </button>
  )

  // ─── Command palette (portalled to body so it's never clipped) ────────
  const palette = open ? createPortal(
    <div
      className="fixed inset-0 z-[9999] flex items-start justify-center pt-[10vh] px-4 sm:pt-[8vh]"
      onClick={close}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in duration-150" />

      {/* Panel */}
      <div
        className="relative w-full max-w-[600px] rounded-2xl border border-border/40 bg-popover shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 ring-1 ring-black/10 dark:ring-white/10"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input row */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border/40 bg-background/80">
          <Search className="h-5 w-5 text-muted-foreground shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search users, conversations, announcements…"
            className="flex-1 bg-transparent text-[15px] outline-none placeholder:text-muted-foreground text-foreground"
            autoComplete="off"
          />
          {query && (
            <button
              onClick={() => { setQuery(''); setDebouncedQ(''); inputRef.current?.focus() }}
              className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded-lg hover:bg-accent"
            >
              <X className="h-4 w-4" />
            </button>
          )}
          {isFetching && (
            <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin shrink-0" />
          )}
          <button
            onClick={close}
            className="hidden sm:flex text-[11px] items-center gap-1 text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded-lg border hover:bg-accent ml-1"
          >
            <kbd className="font-mono">Esc</kbd>
          </button>
        </div>

        {/* Type filter tabs */}
        <div className="flex border-b border-border/40 bg-muted/20 overflow-x-auto scrollbar-hide">
          {TYPE_TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveType(id)}
              className={cn(
                'flex-1 min-w-[72px] flex items-center justify-center gap-1.5 py-2.5 text-xs font-semibold border-b-2 transition-all whitespace-nowrap px-2',
                activeType === id
                  ? 'border-primary text-primary bg-primary/5'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-accent/50',
              )}
            >
              <Icon className="h-3.5 w-3.5 shrink-0" />
              {label}
            </button>
          ))}
        </div>

        {/* Results area */}
        <div className="max-h-[50vh] overflow-y-auto overscroll-contain">
          {!debouncedQ ? (
            <div className="py-10 text-center">
              <Search className="h-8 w-8 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Type to search across the platform</p>
              <p className="text-xs text-muted-foreground/60 mt-1">Users · Conversations · Announcements · Messages</p>
            </div>
          ) : isFetching && !hasResults ? (
            <div className="py-10 text-center">
              <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Searching…</p>
            </div>
          ) : !hasResults ? (
            <div className="py-10 text-center">
              <p className="text-sm text-muted-foreground">No results for &ldquo;{debouncedQ}&rdquo;</p>
              <p className="text-xs text-muted-foreground/60 mt-1">Try a different search term</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {/* Users */}
              {results.users.length > 0 && (
                <div>
                  <p className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground bg-muted/30 sticky top-0">
                    Users
                  </p>
                  {results.users.map((u) => (
                    <button
                      key={u.id}
                      className="flex items-center gap-3 px-4 py-3 hover:bg-accent w-full text-left group transition-colors"
                      onClick={() => go(u.role === 'USER' ? `/admin/users/${u.id}` : `/admin/admins`)}
                    >
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold">
                        {getInitials(u.name)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{highlight(u.name, debouncedQ)}</p>
                        <p className="text-xs text-muted-foreground truncate">{highlight(u.email, debouncedQ)}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={cn('text-[10px] font-medium px-1.5 py-0.5 rounded-full', STATUS_COLORS[u.status] ?? 'bg-muted text-muted-foreground')}>
                          {u.status}
                        </span>
                        {u.status === 'PENDING' && (isSuperAdmin || user?.role === 'ADMIN') && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleApprove(u.id, u.name) }}
                            disabled={approvingId === u.id}
                            className="flex items-center gap-1 h-6 px-2 rounded-lg bg-green-600 text-white text-[10px] font-semibold hover:bg-green-700 transition-colors disabled:opacity-60"
                          >
                            {approvingId === u.id ? (
                              <div className="h-3 w-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            ) : (
                              <CheckCircle className="h-3 w-3" />
                            )}
                            Approve
                          </button>
                        )}
                        {u.role !== 'USER' && <UserCog className="h-3.5 w-3.5 text-muted-foreground" />}
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {/* Conversations */}
              {results.conversations.length > 0 && (
                <div>
                  <p className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground bg-muted/30 sticky top-0">
                    Conversations
                  </p>
                  {results.conversations.map((c) => (
                    <button
                      key={c.id}
                      className="flex items-center gap-3 px-4 py-3 hover:bg-accent w-full text-left group transition-colors"
                      onClick={() => go(`/admin?conversationId=${c.id}`)}
                    >
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs font-bold">
                        {getInitials(c.user.name)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{highlight(c.user.name, debouncedQ)}</p>
                        <p className="text-xs text-muted-foreground truncate">{highlight(c.user.email, debouncedQ)}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {(c.adminUnreadCount ?? 0) > 0 && (
                          <Badge variant="destructive" className="text-[10px] h-5 min-w-5 px-1.5 rounded-full">
                            {c.adminUnreadCount}
                          </Badge>
                        )}
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {/* Announcements */}
              {results.announcements.length > 0 && (
                <div>
                  <p className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground bg-muted/30 sticky top-0">
                    Announcements
                  </p>
                  {results.announcements.map((a) => (
                    <button
                      key={a.id}
                      className="flex items-center gap-3 px-4 py-3 hover:bg-accent w-full text-left group transition-colors"
                      onClick={() => go(`/admin/announcements/${a.id}/edit`)}
                    >
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        <Megaphone className="h-4 w-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{highlight(a.title, debouncedQ)}</p>
                        <p className="text-xs text-muted-foreground">{a.type}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {!a.isActive && <Badge variant="outline" className="text-[10px]">Inactive</Badge>}
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {/* Messages */}
              {results.messages.length > 0 && (
                <div>
                  <p className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground bg-muted/30 sticky top-0">
                    Messages
                  </p>
                  {results.messages.map((m) => (
                    <button
                      key={m.id}
                      className="flex items-center gap-3 px-4 py-3 hover:bg-accent w-full text-left group transition-colors"
                      onClick={() => go(`/admin?conversationId=${m.conversationId}`)}
                    >
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground text-xs font-bold">
                        {getInitials(m.sender.name)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-muted-foreground mb-0.5">{m.sender.name}</p>
                        <p className="text-sm truncate">{highlight(m.content ?? '', debouncedQ)}</p>
                      </div>
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer hint */}
        <div className="flex items-center justify-between px-4 py-2 border-t bg-muted/20 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <kbd className="px-1 py-0.5 rounded border bg-background font-mono">↵</kbd>
            to open
          </span>
          <span className="flex items-center gap-1.5">
            <kbd className="px-1 py-0.5 rounded border bg-background font-mono">Esc</kbd>
            to close
          </span>
        </div>
      </div>
    </div>,
    document.body,
  ) : null

  return (
    <>
      {trigger}
      {palette}
    </>
  )
}
