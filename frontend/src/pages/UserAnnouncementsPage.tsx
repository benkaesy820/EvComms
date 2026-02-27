import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Megaphone,
  ThumbsUp, ThumbsDown, Users, Clock, ChevronDown, ChevronUp, ExternalLink,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn, formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/empty-state'
import {
  useAnnouncements, useVoteAnnouncement,
} from '@/hooks/useAnnouncements'
import type { Announcement } from '@/lib/schemas'
import { ANNOUNCEMENT_TYPE_CONFIG as TYPE_CONFIG } from '@/lib/constants'

function getGradient(type: string) {
  switch (type) {
    case 'INFO': return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
    case 'WARNING': return 'hsl(38, 92%, 50%), hsl(45, 93%, 65%)'
    case 'IMPORTANT': return 'hsl(0, 72%, 51%), hsl(0, 84%, 65%)'
    default: return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
  }
}

function AuthorAvatar({ name }: { name: string }) {
  const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()
  return (
    <div className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/10 text-[9px] font-bold text-primary shrink-0">
      {initials}
    </div>
  )
}

function AnnouncementCard({
  announcement,
  onVote,
  onView,
}: {
  announcement: Announcement
  onVote: (id: string, vote: 'UP' | 'DOWN') => void
  onView: (id: string) => void
}) {
  const config = TYPE_CONFIG[announcement.type]
  const Icon = config.icon
  const hasMedia = !!announcement.mediaAttachment
  const [expanded, setExpanded] = useState(false)
  const isLong = announcement.content.length > 200
  const authorName = announcement.author?.name ?? 'Admin'

  return (
    <div className={cn(
      'rounded-xl border overflow-hidden transition-all hover:shadow-lg',
      !announcement.isActive && 'opacity-50',
    )}>
      <div className="flex">
        {/* Gradient accent */}
        <div className="w-1 shrink-0" style={{
          background: `linear-gradient(to bottom, ${getGradient(announcement.type)})`,
        }} />

        <div className="flex-1 min-w-0">
          {/* Hero media */}
          {hasMedia && announcement.mediaAttachment && announcement.mediaAttachment.type === 'IMAGE' && (
            <div className="relative">
              <img
                src={announcement.mediaAttachment.cdnUrl}
                alt={announcement.mediaAttachment.filename}
                className="w-full h-44 object-cover"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />
              <div className="absolute bottom-3 left-4">
                <Badge variant="outline" className="text-[10px] bg-black/30 backdrop-blur-sm border-white/20 text-white">
                  {config.label}
                </Badge>
              </div>
            </div>
          )}

          <div className="p-4">
            {/* Header — no hero media */}
            {!hasMedia && (
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg', config.bg)}>
                  <Icon className={cn('h-4 w-4', config.color)} />
                </div>
                <Badge variant="outline" className={cn('text-[10px]', config.color, config.border)}>
                  {config.label}
                </Badge>
                {announcement.targetRoles && announcement.targetRoles.length > 0 && (
                  <Badge variant="secondary" className="text-[10px] gap-1">
                    <Users className="h-3 w-3" />
                    {announcement.targetRoles.join(', ')}
                  </Badge>
                )}
              </div>
            )}

            {/* Title */}
            <button
              onClick={() => onView(announcement.id)}
              className="text-sm font-bold hover:text-primary transition-colors text-left leading-snug"
            >
              {announcement.title}
            </button>

            {/* Content */}
            <div className="mt-1.5">
              <p className={cn(
                'text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed',
                !expanded && isLong && 'line-clamp-3',
              )}>
                {announcement.content}
              </p>
              {isLong && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 mt-1 text-xs"
                  onClick={() => setExpanded(!expanded)}
                >
                  {expanded ? (
                    <><ChevronUp className="h-3 w-3 mr-1" /> Show less</>
                  ) : (
                    <><ChevronDown className="h-3 w-3 mr-1" /> Show more</>
                  )}
                </Button>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between mt-4 pt-3 border-t">
              {/* Votes */}
              <div className="flex items-center gap-1">
                <button
                  onClick={() => onVote(announcement.id, 'UP')}
                  className={cn(
                    'flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-all',
                    announcement.userVote === 'UP'
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 shadow-sm'
                      : 'hover:bg-muted text-muted-foreground',
                  )}
                >
                  <ThumbsUp className={cn('h-3.5 w-3.5', announcement.userVote === 'UP' && 'fill-current')} />
                  <span className="tabular-nums">{announcement.upvoteCount}</span>
                </button>
                <button
                  onClick={() => onVote(announcement.id, 'DOWN')}
                  className={cn(
                    'flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-all',
                    announcement.userVote === 'DOWN'
                      ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 shadow-sm'
                      : 'hover:bg-muted text-muted-foreground',
                  )}
                >
                  <ThumbsDown className={cn('h-3.5 w-3.5', announcement.userVote === 'DOWN' && 'fill-current')} />
                  <span className="tabular-nums">{announcement.downvoteCount}</span>
                </button>
              </div>

              {/* Meta + View */}
              <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1">
                  <AuthorAvatar name={authorName} />
                  {authorName}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatRelativeTime(announcement.createdAt)}
                </span>
                <button
                  onClick={() => onView(announcement.id)}
                  className="flex items-center gap-1 text-primary hover:underline font-medium"
                >
                  <ExternalLink className="h-3 w-3" />
                  Read
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="rounded-xl border overflow-hidden">
          <Skeleton className="h-44 w-full" />
          <div className="p-4 space-y-2">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-32" />
          </div>
        </div>
      ))}
    </div>
  )
}

export function UserAnnouncementsPage() {
  const navigate = useNavigate()
  const { data, isLoading } = useAnnouncements()
  const voteAnnouncement = useVoteAnnouncement()

  const items = data?.announcements ?? []
  const infoCount = items.filter(a => a.type === 'INFO').length
  const warningCount = items.filter(a => a.type === 'WARNING').length
  const importantCount = items.filter(a => a.type === 'IMPORTANT').length

  const handleVote = (id: string, vote: 'UP' | 'DOWN') => {
    voteAnnouncement.mutate({ id, vote })
  }
  const handleView = (id: string) => navigate(`/home/announcements/${id}`)

  if (isLoading) {
    return <CardSkeleton />
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-4 border-b space-y-4 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <Megaphone className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">Announcements</h2>
              <p className="text-[11px] text-muted-foreground">
                {items.length} total
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {importantCount > 0 && (
              <Badge variant="destructive" className="text-[10px]">
                {importantCount} important
              </Badge>
            )}
            {warningCount > 0 && (
              <Badge className="text-[10px] bg-amber-500 hover:bg-amber-600">
                {warningCount} warning
              </Badge>
            )}
            {infoCount > 0 && (
              <Badge variant="outline" className="text-[10px] text-blue-600 border-blue-300">
                {infoCount} info
              </Badge>
            )}
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4 space-y-3">
          {items.length === 0 ? (
            <EmptyState icon={Megaphone} title="No announcements" subtitle="New announcements will appear here" />
          ) : (
            items.map((ann) => (
              <AnnouncementCard
                key={ann.id}
                announcement={ann}
                onVote={handleVote}
                onView={handleView}
              />
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
