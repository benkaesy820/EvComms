import { useState } from 'react'
import {
  Megaphone, Info, AlertTriangle, AlertCircle, ChevronDown, ChevronUp,
  ThumbsUp, ThumbsDown, X, Users,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn, formatRelativeTime } from '@/lib/utils'
import { useAnnouncements, useVoteAnnouncement } from '@/hooks/useAnnouncements'
import { useAuthStore } from '@/stores/authStore'
import type { Announcement, AnnouncementType } from '@/lib/schemas'

const TYPE_STYLE: Record<AnnouncementType, {
  icon: typeof Info
  color: string
  bg: string
  border: string
  accent: string
}> = {
  INFO: {
    icon: Info,
    color: 'text-blue-700 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-950/40',
    border: 'border-blue-200 dark:border-blue-800/60',
    accent: 'bg-blue-500',
  },
  WARNING: {
    icon: AlertTriangle,
    color: 'text-amber-700 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-950/40',
    border: 'border-amber-200 dark:border-amber-800/60',
    accent: 'bg-amber-500',
  },
  IMPORTANT: {
    icon: AlertCircle,
    color: 'text-red-700 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-950/40',
    border: 'border-red-200 dark:border-red-800/60',
    accent: 'bg-red-500',
  },
}

function BannerTemplate({ announcement, onVote }: { announcement: Announcement; onVote: (id: string, vote: 'UP' | 'DOWN') => void }) {
  const style = TYPE_STYLE[announcement.type]
  const Icon = style.icon

  return (
    <div className={cn('relative overflow-hidden rounded-lg border', style.bg, style.border)}>
      <div className={cn('absolute left-0 top-0 bottom-0 w-1', style.accent)} />
      <div className="flex items-start gap-3 px-4 py-3 pl-5">
        <Icon className={cn('h-4 w-4 shrink-0 mt-0.5', style.color)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">{announcement.title}</span>
            <Badge variant="outline" className={cn('text-[9px] px-1.5 py-0', style.color, style.border)}>
              {announcement.type}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2 leading-relaxed">
            {announcement.content}
          </p>
          {announcement.mediaAttachment?.type === 'IMAGE' && (
            <img
              src={announcement.mediaAttachment.cdnUrl}
              alt=""
              className="mt-2 rounded-md max-h-24 object-cover"
            />
          )}
          <div className="flex items-center gap-3 mt-2">
            <div className="flex items-center gap-0.5">
              <button
                onClick={() => onVote(announcement.id, 'UP')}
                className={cn(
                  'flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] transition-colors',
                  announcement.userVote === 'UP'
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400'
                    : 'hover:bg-muted text-muted-foreground',
                )}
              >
                <ThumbsUp className="h-3 w-3" />
                <span className="tabular-nums">{announcement.upvoteCount}</span>
              </button>
              <button
                onClick={() => onVote(announcement.id, 'DOWN')}
                className={cn(
                  'flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] transition-colors',
                  announcement.userVote === 'DOWN'
                    ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400'
                    : 'hover:bg-muted text-muted-foreground',
                )}
              >
                <ThumbsDown className="h-3 w-3" />
                <span className="tabular-nums">{announcement.downvoteCount}</span>
              </button>
            </div>
            <span className="text-[10px] text-muted-foreground">
              {formatRelativeTime(announcement.createdAt)}
            </span>
            {announcement.targetRoles && announcement.targetRoles.length > 0 && (
              <span className="flex items-center gap-0.5 text-[10px] text-muted-foreground">
                <Users className="h-2.5 w-2.5" />
                {announcement.targetRoles.join(', ')}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function CardTemplate({ announcement, onVote }: { announcement: Announcement; onVote: (id: string, vote: 'UP' | 'DOWN') => void }) {
  const style = TYPE_STYLE[announcement.type]
  const Icon = style.icon

  return (
    <div className={cn('rounded-xl border p-4 shadow-sm', style.bg, style.border)}>
      <div className="flex items-start gap-3">
        <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg', style.bg, 'ring-1 ring-inset', style.border)}>
          <Icon className={cn('h-4 w-4', style.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold">{announcement.title}</h4>
          <p className="text-xs text-muted-foreground mt-1 whitespace-pre-wrap leading-relaxed">
            {announcement.content}
          </p>
          {announcement.mediaAttachment?.type === 'IMAGE' && (
            <img
              src={announcement.mediaAttachment.cdnUrl}
              alt=""
              className="mt-2 rounded-lg max-h-32 object-cover"
            />
          )}
          <div className="flex items-center justify-between mt-3">
            <div className="flex items-center gap-1">
              <button
                onClick={() => onVote(announcement.id, 'UP')}
                className={cn(
                  'flex items-center gap-1 rounded-md px-2 py-0.5 text-xs transition-colors',
                  announcement.userVote === 'UP'
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400'
                    : 'hover:bg-muted text-muted-foreground',
                )}
              >
                <ThumbsUp className="h-3 w-3" />
                <span className="tabular-nums">{announcement.upvoteCount}</span>
              </button>
              <button
                onClick={() => onVote(announcement.id, 'DOWN')}
                className={cn(
                  'flex items-center gap-1 rounded-md px-2 py-0.5 text-xs transition-colors',
                  announcement.userVote === 'DOWN'
                    ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400'
                    : 'hover:bg-muted text-muted-foreground',
                )}
              >
                <ThumbsDown className="h-3 w-3" />
                <span className="tabular-nums">{announcement.downvoteCount}</span>
              </button>
            </div>
            <span className="text-[10px] text-muted-foreground">
              {announcement.author?.name ?? 'Admin'} &middot; {formatRelativeTime(announcement.createdAt)}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function MinimalTemplate({ announcement, onVote }: { announcement: Announcement; onVote: (id: string, vote: 'UP' | 'DOWN') => void }) {
  const style = TYPE_STYLE[announcement.type]
  const Icon = style.icon

  return (
    <div className="flex items-center gap-2.5 rounded-lg border bg-muted/30 px-3 py-2">
      <Icon className={cn('h-3.5 w-3.5 shrink-0', style.color)} />
      <span className="text-xs font-medium truncate flex-1">{announcement.title}</span>
      <div className="flex items-center gap-0.5 shrink-0">
        <button
          onClick={() => onVote(announcement.id, 'UP')}
          className={cn(
            'p-0.5 rounded transition-colors',
            announcement.userVote === 'UP' ? 'text-green-600' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          <ThumbsUp className="h-3 w-3" />
        </button>
        <button
          onClick={() => onVote(announcement.id, 'DOWN')}
          className={cn(
            'p-0.5 rounded transition-colors',
            announcement.userVote === 'DOWN' ? 'text-red-600' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          <ThumbsDown className="h-3 w-3" />
        </button>
      </div>
      <span className="text-[10px] text-muted-foreground shrink-0">
        {formatRelativeTime(announcement.createdAt)}
      </span>
    </div>
  )
}

function AnnouncementItem({ announcement, onVote }: { announcement: Announcement; onVote: (id: string, vote: 'UP' | 'DOWN') => void }) {
  switch (announcement.template) {
    case 'CARD':
      return <CardTemplate announcement={announcement} onVote={onVote} />
    case 'MINIMAL':
      return <MinimalTemplate announcement={announcement} onVote={onVote} />
    case 'BANNER':
    case 'DEFAULT':
    default:
      return <BannerTemplate announcement={announcement} onVote={onVote} />
  }
}

export function AnnouncementsBanner() {
  const user = useAuthStore((s) => s.user)
  const { data } = useAnnouncements()
  const vote = useVoteAnnouncement()
  const [expanded, setExpanded] = useState(false)
  const [dismissed, setDismissed] = useState<Set<string>>(() => {
    try {
      const stored = sessionStorage.getItem('dismissed-announcements')
      return stored ? new Set(JSON.parse(stored) as string[]) : new Set()
    } catch { return new Set() }
  })

  const allAnnouncements = data?.announcements ?? []

  const visibleAnnouncements = allAnnouncements.filter((ann) => {
    if (dismissed.has(ann.id)) return false
    if (!ann.targetRoles || ann.targetRoles.length === 0) return true
    return user?.role && ann.targetRoles.includes(user.role)
  })

  const handleVote = (id: string, v: 'UP' | 'DOWN') => {
    vote.mutate({ id, vote: v })
  }

  const handleDismiss = (id: string) => {
    setDismissed((prev) => {
      const next = new Set(prev).add(id)
      try { sessionStorage.setItem('dismissed-announcements', JSON.stringify([...next])) } catch { }
      return next
    })
  }

  if (visibleAnnouncements.length === 0) return null

  const importantCount = visibleAnnouncements.filter((a) => a.type === 'IMPORTANT').length
  const warningCount = visibleAnnouncements.filter((a) => a.type === 'WARNING').length

  return (
    <div className="border-b">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-accent/30 transition-colors"
      >
        <Megaphone className="h-3.5 w-3.5 text-primary shrink-0" />
        <span className="text-xs font-semibold text-foreground">
          {visibleAnnouncements.length} Announcement{visibleAnnouncements.length !== 1 ? 's' : ''}
        </span>
        {importantCount > 0 && (
          <Badge variant="destructive" className="text-[9px] px-1.5 py-0 h-4">
            {importantCount} important
          </Badge>
        )}
        {warningCount > 0 && (
          <Badge className="text-[9px] px-1.5 py-0 h-4 bg-amber-500 hover:bg-amber-600">
            {warningCount} warning
          </Badge>
        )}
        <div className="flex-1" />
        {expanded ? (
          <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
        ) : (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-3 space-y-2 max-h-[280px] overflow-y-auto">
          {visibleAnnouncements.map((ann) => (
            <div key={ann.id} className="relative group">
              <AnnouncementItem announcement={ann} onVote={handleVote} />
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-1 right-1 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={() => handleDismiss(ann.id)}
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
