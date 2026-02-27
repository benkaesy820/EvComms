import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { format } from 'date-fns'
import { cn, parseTimestamp } from '@/lib/utils'
import {
  ScrollText, Filter, User, MessageSquare, Shield, FileText,
  Clock, RefreshCw, Settings, Image, Megaphone, Wrench, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useAuditLogs } from '@/hooks/useUsers'
import { EmptyState } from '@/components/ui/empty-state'
import { LeafLogo } from '@/components/ui/LeafLogo'

const SCROLL_NEAR_BOTTOM_PX = 200

const ACTION_CONFIG: Record<string, { color: string; bg: string; icon: typeof User }> = {
  'user.status_change': { color: 'text-amber-700 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/15', icon: Shield },
  'user.media_permission_change': { color: 'text-blue-700 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/15', icon: Image },
  'user.sessions_revoke': { color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-900/15', icon: User },
  'user.preferences_change': { color: 'text-sky-700 dark:text-sky-400', bg: 'bg-sky-50 dark:bg-sky-900/15', icon: User },
  'admin.create': { color: 'text-green-700 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/15', icon: Shield },
  'admin.role_change': { color: 'text-purple-700 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-900/15', icon: Shield },
  'admin.media_cleanup': { color: 'text-slate-700 dark:text-slate-400', bg: 'bg-slate-50 dark:bg-slate-900/15', icon: Wrench },
  'message.send': { color: 'text-teal-700 dark:text-teal-400', bg: 'bg-teal-50 dark:bg-teal-900/15', icon: MessageSquare },
  'message.delete': { color: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/15', icon: MessageSquare },
  'announcement.create': { color: 'text-green-700 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/15', icon: Megaphone },
  'announcement.update': { color: 'text-amber-700 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/15', icon: Megaphone },
  'announcement.delete': { color: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/15', icon: Megaphone },
  'config.brand_update': { color: 'text-violet-700 dark:text-violet-400', bg: 'bg-violet-50 dark:bg-violet-900/15', icon: Settings },
  'config.features_update': { color: 'text-violet-700 dark:text-violet-400', bg: 'bg-violet-50 dark:bg-violet-900/15', icon: Settings },
  'config.limits_update': { color: 'text-violet-700 dark:text-violet-400', bg: 'bg-violet-50 dark:bg-violet-900/15', icon: Settings },
  'config.subsidiaries_update': { color: 'text-violet-700 dark:text-violet-400', bg: 'bg-violet-50 dark:bg-violet-900/15', icon: Settings },
  'media.upload': { color: 'text-indigo-700 dark:text-indigo-400', bg: 'bg-indigo-50 dark:bg-indigo-900/15', icon: Image },
  'media.delete': { color: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/15', icon: Image },
}

const ENTITY_ICONS: Record<string, typeof User> = {
  user: User,
  message: MessageSquare,
  conversation: MessageSquare,
  session: User,
  announcement: Megaphone,
  config: Settings,
  media: Image,
  system: Wrench,
}

function formatAction(action: string): string {
  return action
    .replace(/\./g, ' › ')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (l) => l.toUpperCase())
}

function parseDetails(raw: string | null | undefined): Record<string, unknown> | null {
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) return parsed
    return null
  } catch {
    return null
  }
}

function DetailRow({ label, value }: { label: string; value: unknown }) {
  const display = typeof value === 'boolean'
    ? (value ? 'Yes' : 'No')
    : typeof value === 'number'
      ? String(value)
      : String(value ?? '')
  return (
    <div className="flex items-baseline gap-2 text-[11px]">
      <span className="text-muted-foreground shrink-0 capitalize">{label.replace(/_/g, ' ')}:</span>
      <span className="font-medium truncate">{display}</span>
    </div>
  )
}

function LogSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="rounded-xl border p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-20 rounded" />
              <Skeleton className="h-5 w-16 rounded" />
            </div>
            <Skeleton className="h-3 w-28" />
          </div>
          <Skeleton className="h-3 w-40 mt-3" />
          <Skeleton className="h-8 w-full mt-2 rounded" />
        </div>
      ))}
    </div>
  )
}

export function AuditPage() {
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [entityFilter, setEntityFilter] = useState<string>('all')
  const [userSearch, setUserSearch] = useState('')
  const scrollContainerRef = useRef<HTMLDivElement>(null)

  const [debouncedSearch, setDebouncedSearch] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(userSearch.trim().toLowerCase()), 300)
    return () => clearTimeout(t)
  }, [userSearch])

  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage, refetch } = useAuditLogs({
    action: actionFilter === 'all' ? undefined : actionFilter,
    entityType: entityFilter === 'all' ? undefined : entityFilter,
  })

  const allLogs = useMemo(() => {
    const raw = data?.pages.flatMap((p) => p.logs) ?? []
    if (!debouncedSearch) return raw
    return raw.filter((l) =>
      l.user?.name?.toLowerCase().includes(debouncedSearch) ||
      l.user?.email?.toLowerCase().includes(debouncedSearch)
    )
  }, [data, debouncedSearch])

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget
    if (el.scrollHeight - el.scrollTop - el.clientHeight < SCROLL_NEAR_BOTTOM_PX && hasNextPage && !isFetchingNextPage) {
      fetchNextPage()
    }
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])

  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = 0
    }
  }, [actionFilter, entityFilter, userSearch])

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 p-4 border-b bg-background space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <ScrollText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">Audit Logs</h2>
              <p className="text-[11px] text-muted-foreground">
                {allLogs.length} entries &middot; System activity
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 rounded-full"
            onClick={() => refetch()}
            disabled={isFetchingNextPage}
          >
            <RefreshCw className={cn('h-3.5 w-3.5', isFetchingNextPage && 'animate-spin')} />
            Refresh
          </Button>
        </div>

        <div className="flex flex-wrap gap-2">
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search by user name or email..."
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              className="pl-9 h-9 rounded-xl w-56"
            />
          </div>
          <Select value={actionFilter} onValueChange={setActionFilter}>
            <SelectTrigger className="w-[180px] h-9 rounded-xl">
              <Filter className="h-3.5 w-3.5 mr-1.5" />
              <SelectValue placeholder="All actions" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Actions</SelectItem>
              <SelectItem value="user.status_change">User › Status Change</SelectItem>
              <SelectItem value="user.media_permission_change">User › Media Permission</SelectItem>
              <SelectItem value="user.sessions_revoke">User › Sessions Revoke</SelectItem>
              <SelectItem value="admin.create">Admin › Create</SelectItem>
              <SelectItem value="admin.role_change">Admin › Role Change</SelectItem>
              <SelectItem value="message.send">Message › Send</SelectItem>
              <SelectItem value="message.delete">Message › Delete</SelectItem>
              <SelectItem value="announcement.create">Announcement › Create</SelectItem>
              <SelectItem value="announcement.update">Announcement › Update</SelectItem>
              <SelectItem value="announcement.delete">Announcement › Delete</SelectItem>
              <SelectItem value="config.brand_update">Config › Brand</SelectItem>
              <SelectItem value="config.features_update">Config › Features</SelectItem>
              <SelectItem value="config.limits_update">Config › Limits</SelectItem>
              <SelectItem value="media.upload">Media › Upload</SelectItem>
              <SelectItem value="media.delete">Media › Delete</SelectItem>
            </SelectContent>
          </Select>
          <Select value={entityFilter} onValueChange={setEntityFilter}>
            <SelectTrigger className="w-[160px] h-9 rounded-xl">
              <SelectValue placeholder="All entities" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Entities</SelectItem>
              <SelectItem value="user">User</SelectItem>
              <SelectItem value="message">Message</SelectItem>
              <SelectItem value="announcement">Announcement</SelectItem>
              <SelectItem value="config">Config</SelectItem>
              <SelectItem value="media">Media</SelectItem>
              <SelectItem value="system">System</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div
        ref={scrollContainerRef}
        className="flex-1 min-h-0 overflow-y-auto bg-background"
        onScroll={handleScroll}
      >
        <div className="flex flex-col pb-4">
          {isLoading ? (
            <LogSkeleton />
          ) : allLogs.length === 0 ? (
            <EmptyState icon={ScrollText} title="No audit logs found" subtitle="Activity will appear here as it happens" />
          ) : (
            <>
              {allLogs.map((log) => {
                const config = ACTION_CONFIG[log.action] || { color: 'text-muted-foreground', bg: 'bg-muted', icon: FileText }
                const EntityIcon = ENTITY_ICONS[log.entityType] || FileText

                return (
                  <div
                    key={log.id}
                    className="border-b border-border/40 bg-transparent p-4 hover:bg-accent/30 transition-all flex flex-col"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={cn('text-[10px] font-medium border', config.color, config.bg)}>
                          {formatAction(log.action)}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] gap-1">
                          <EntityIcon className="h-3 w-3" />
                          {log.entityType}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        <span>{format(parseTimestamp(log.createdAt), 'MMM d, yyyy HH:mm')}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 mt-3 text-xs">
                      <div className="flex items-center gap-1">
                        <span className="text-muted-foreground">By:</span>
                        <span className="font-medium">{log.user?.name ?? 'System'}</span>
                      </div>
                      {log.user?.email && (
                        <span className="text-muted-foreground">&lt;{log.user.email}&gt;</span>
                      )}
                    </div>

                    {log.details && (() => {
                      const parsed = parseDetails(log.details)
                      return parsed ? (
                        <div className="mt-3 rounded-lg bg-muted/50 px-3 py-2 border-l-2 border-primary/40 space-y-0.5">
                          {Object.entries(parsed).map(([k, v]) => (
                            <DetailRow key={k} label={k} value={v} />
                          ))}
                        </div>
                      ) : (
                        <div className="mt-3 rounded-lg bg-muted/50 p-3 text-xs font-mono text-muted-foreground border-l-2 border-primary/40 break-all">
                          {log.details}
                        </div>
                      )
                    })()}

                    <div className="flex items-center gap-1 mt-3 text-[10px] text-muted-foreground">
                      <span className="font-mono bg-muted px-1.5 py-0.5 rounded">{log.entityId}</span>
                      <ChevronRight className="h-3 w-3" />
                      <span className="text-muted-foreground/70">Entity ID</span>
                    </div>
                  </div>
                )
              })}

              {hasNextPage && (
                <div className="flex justify-center pt-4 pb-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="rounded-xl gap-2"
                    onClick={() => fetchNextPage()}
                    disabled={isFetchingNextPage}
                  >
                    {isFetchingNextPage && <LeafLogo className="h-4 w-4 animate-spin" />}
                    Load More
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
