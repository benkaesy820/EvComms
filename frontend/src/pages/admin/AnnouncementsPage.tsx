import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Megaphone, Plus, Trash2,
  ThumbsUp, ThumbsDown, Users, LayoutTemplate, Eye, EyeOff,
  Calendar, Clock, MoreVertical, Pencil, ExternalLink,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Switch } from '@/components/ui/switch'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn, formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/empty-state'
import {
  useAnnouncements, useDeleteAnnouncement, useVoteAnnouncement,
} from '@/hooks/useAnnouncements'
import type { AnnouncementTemplate, Announcement } from '@/lib/schemas'
import { ANNOUNCEMENT_TYPE_CONFIG as TYPE_CONFIG } from '@/lib/constants'

const TEMPLATE_LABELS: Record<AnnouncementTemplate, string> = {
  DEFAULT: 'Default',
  BANNER: 'Banner',
  CARD: 'Card',
  MINIMAL: 'Minimal',
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
  onDelete,
  onVote,
  onEdit,
  onView,
}: {
  announcement: Announcement
  onDelete: (id: string) => void
  onVote: (id: string, vote: 'UP' | 'DOWN') => void
  onEdit: (id: string) => void
  onView: (id: string) => void
}) {
  const config = TYPE_CONFIG[announcement.type]
  const Icon = config.icon
  const hasMedia = !!announcement.mediaAttachment
  const authorName = announcement.author?.name ?? 'Admin'

  return (
    <div className={cn(
      'group border-b border-border/40 bg-transparent overflow-hidden transition-all hover:bg-accent/30',
      !announcement.isActive && 'opacity-50',
    )}>
      {/* Left accent gradient */}
      <div className="flex">
        <div className={cn('w-1 shrink-0', config.bg)} style={{
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
              <div className="absolute bottom-3 left-4 right-4">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={cn('text-[10px] bg-black/30 backdrop-blur-sm border-white/20 text-white')}>
                    {config.label}
                  </Badge>
                  <Badge variant="secondary" className="text-[10px] bg-black/30 backdrop-blur-sm border-white/20 text-white">
                    <LayoutTemplate className="h-3 w-3 mr-1" />
                    {TEMPLATE_LABELS[announcement.template]}
                  </Badge>
                </div>
              </div>
            </div>
          )}

          <div className="p-4">
            {/* Header row — no hero media */}
            {!hasMedia && (
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg', config.bg)}>
                  <Icon className={cn('h-4 w-4', config.color)} />
                </div>
                <Badge variant="outline" className={cn('text-[10px]', config.color, config.border)}>
                  {config.label}
                </Badge>
                <Badge variant="secondary" className="text-[10px]">
                  <LayoutTemplate className="h-3 w-3 mr-1" />
                  {TEMPLATE_LABELS[announcement.template]}
                </Badge>
                {!announcement.isActive && (
                  <Badge variant="secondary" className="text-[10px] text-muted-foreground">
                    <EyeOff className="h-3 w-3 mr-1" /> Inactive
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

            {/* Content preview */}
            <p className="text-sm text-muted-foreground mt-1.5 whitespace-pre-wrap leading-relaxed line-clamp-3">
              {announcement.content}
            </p>

            {/* Footer */}
            <div className="flex items-start sm:items-center justify-between mt-4 pt-3 border-t gap-2">
              <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 min-w-0 flex-1">
                {/* Votes */}
                <div className="flex items-center gap-1 shrink-0">
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

                {/* Meta */}
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground min-w-0">
                  <span className="flex items-center gap-1 truncate">
                    <AuthorAvatar name={authorName} />
                    <span className="truncate max-w-[100px]">{authorName}</span>
                  </span>
                  <span className="flex items-center gap-1 shrink-0">
                    <Calendar className="h-3 w-3" />
                    {formatRelativeTime(announcement.createdAt)}
                  </span>
                  {announcement.expiresAt && (
                    <span className="flex items-center gap-1 text-amber-600 shrink-0">
                      <Clock className="h-3 w-3" />
                      Expires {formatRelativeTime(announcement.expiresAt)}
                    </span>
                  )}
                </div>
              </div>

              {/* Actions */}
              <div className="shrink-0 self-start sm:self-auto ml-2">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-foreground shrink-0 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                      <MoreVertical className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => onView(announcement.id)}>
                      <ExternalLink className="h-4 w-4" /> View
                    </DropdownMenuItem>
                    <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => onEdit(announcement.id)}>
                      <Pencil className="h-4 w-4" /> Edit
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="gap-2 text-destructive focus:text-destructive cursor-pointer"
                      onClick={() => onDelete(announcement.id)}
                    >
                      <Trash2 className="h-4 w-4" /> Delete
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            {/* Target roles */}
            {announcement.targetRoles && announcement.targetRoles.length > 0 && (
              <div className="mt-2 flex items-center gap-1 text-[10px] text-muted-foreground">
                <Users className="h-3 w-3" />
                <span>{announcement.targetRoles.join(', ')}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function getGradient(type: string) {
  switch (type) {
    case 'INFO': return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
    case 'WARNING': return 'hsl(38, 92%, 50%), hsl(45, 93%, 65%)'
    case 'IMPORTANT': return 'hsl(0, 72%, 51%), hsl(0, 84%, 65%)'
    default: return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
  }
}

export function AnnouncementsPage() {
  const navigate = useNavigate()
  const [showInactive, setShowInactive] = useState(() => {
    try { return sessionStorage.getItem('announcements:showInactive') === 'true' } catch { return false }
  })

  const handleShowInactiveChange = (v: boolean) => {
    setShowInactive(v)
    try { sessionStorage.setItem('announcements:showInactive', String(v)) } catch { /* noop */ }
  }

  const { data, isLoading } = useAnnouncements(showInactive)

  const deleteAnnouncement = useDeleteAnnouncement()
  const voteAnnouncement = useVoteAnnouncement()

  const items = data?.announcements ?? []
  const activeCount = useMemo(() => items.filter(a => a.isActive).length, [items])

  const handleDelete = (id: string) => deleteAnnouncement.mutate(id)
  const handleVote = (id: string, vote: 'UP' | 'DOWN') => voteAnnouncement.mutate({ id, vote })
  const handleEdit = (id: string) => navigate(`/admin/announcements/${id}/edit`)
  const handleView = (id: string) => navigate(`/admin/announcements/${id}`)

  if (isLoading) {
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

  return (
    <div className="flex h-full flex-col">
      <div className="p-4 border-b shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <Megaphone className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">Announcements</h2>
              <p className="text-[11px] text-muted-foreground">
                {activeCount} active &middot; {items.length} total
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
              <Switch checked={showInactive} onCheckedChange={handleShowInactiveChange} className="scale-75" />
              <span className="flex items-center gap-1">
                {showInactive ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
                Show inactive
              </span>
            </label>
            <Button size="sm" className="gap-1.5 rounded-full px-4 shadow-sm" onClick={() => navigate('/admin/announcements/new')}>
              <Plus className="h-4 w-4" />
              New Announcement
            </Button>
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1 bg-background">
        <div className="flex flex-col pb-4">
          {items.length === 0 ? (
            <EmptyState icon={Megaphone} title="No announcements" subtitle="Create one to notify all users" />
          ) : (
            items.map((ann) => (
              <AnnouncementCard
                key={ann.id}
                announcement={ann}
                onDelete={handleDelete}
                onVote={handleVote}
                onEdit={handleEdit}
                onView={handleView}
              />
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
