import { useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, ThumbsUp, ThumbsDown, Calendar, Clock, Users,
  EyeOff, Pencil, FileText, AlertTriangle, Share2, Download,
  SmilePlus, Send, Trash2, MessageSquare,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'
import { cn, formatRelativeTime, parseTimestamp, getInitials } from '@/lib/utils'
import {
  useAnnouncement, useVoteAnnouncement,
  useAnnouncementReaction,
  useAnnouncementComments, useAddComment, useDeleteComment,
} from '@/hooks/useAnnouncements'
import { useAuthStore } from '@/stores/authStore'
import { ANNOUNCEMENT_TYPE_CONFIG as TYPE_CONFIG } from '@/lib/constants'
import type { AnnouncementType } from '@/lib/schemas'
import { format } from 'date-fns'
import { EmojiPicker } from '@/components/ui/EmojiPicker'

const TEMPLATE_LABELS: Record<string, string> = {
  DEFAULT: 'Default',
  BANNER: 'Banner',
  CARD: 'Card',
  MINIMAL: 'Minimal',
}

function getGradient(type: string) {
  switch (type) {
    case 'WARNING': return 'from-amber-500/15 via-amber-500/5 to-transparent'
    case 'IMPORTANT': return 'from-red-500/15 via-red-500/5 to-transparent'
    default: return 'from-primary/10 via-primary/5 to-transparent'
  }
}

function AuthorAvatar({ name, size = 'md' }: { name: string; size?: 'sm' | 'md' }) {
  return (
    <div className={cn(
      'flex items-center justify-center rounded-full bg-primary/10 text-primary font-bold shrink-0 ring-2 ring-background',
      size === 'sm' ? 'h-7 w-7 text-[10px]' : 'h-9 w-9 text-xs'
    )}>
      {getInitials(name)}
    </div>
  )
}

export function AnnouncementViewPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'

  const { data, isLoading, isError } = useAnnouncement(id)
  const vote = useVoteAnnouncement()
  const { react: reactMut, remove: removeReaction } = useAnnouncementReaction(id)

  const { data: commentsData, isLoading: commentsLoading } = useAnnouncementComments(id)
  const addComment = useAddComment(id)
  const deleteComment = useDeleteComment(id)

  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [commentInput, setCommentInput] = useState('')
  const commentRef = useRef<HTMLTextAreaElement>(null)

  const announcement = data?.announcement

  const handleBack = () => navigate(-1)
  const handleEdit = () => navigate(`/admin/announcements/${id}/edit`)
  const handleVote = (v: 'UP' | 'DOWN') => { if (!id) return; vote.mutate({ id, vote: v }) }

  const handleReact = (emoji: string) => {
    setShowEmojiPicker(false)
    reactMut.mutate(emoji)
  }

  const handleSubmitComment = () => {
    const trimmed = commentInput.trim()
    if (!trimmed || addComment.isPending) return
    addComment.mutate(trimmed, { onSuccess: () => setCommentInput('') })
  }

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0">
          <Skeleton className="h-8 w-8 rounded-lg" />
          <Skeleton className="h-5 w-48" />
        </div>
        <div className="flex-1 overflow-y-auto p-6 max-w-3xl mx-auto w-full space-y-4">
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-8 w-3/4" />
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-32 w-full" />
        </div>
      </div>
    )
  }

  if (isError || !announcement) {
    return (
      <div className="flex flex-col h-full items-center justify-center gap-4 text-muted-foreground p-8">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-8 w-8 text-destructive/60" />
        </div>
        <div className="text-center">
          <p className="font-semibold text-foreground">Announcement not found</p>
          <p className="text-sm mt-1">It may have been deleted or you may not have access.</p>
        </div>
        <Button variant="outline" className="gap-2 rounded-xl" onClick={handleBack}>
          <ArrowLeft className="h-4 w-4" />
          Go Back
        </Button>
      </div>
    )
  }

  const config = TYPE_CONFIG[announcement.type as AnnouncementType]
  const Icon = config.icon
  const createdAt = parseTimestamp(announcement.createdAt)
  const expiresAt = announcement.expiresAt ? parseTimestamp(announcement.expiresAt) : null
  const authorName = announcement.author?.name ?? 'Admin'
  const hasMedia = announcement.mediaAttachment?.type === 'IMAGE'
  const hasVideo = announcement.mediaAttachment?.type === 'VIDEO'
  const hasDoc = announcement.mediaAttachment?.type === 'DOCUMENT'
  const totalVotes = announcement.upvoteCount + announcement.downvoteCount
  const upPct = totalVotes > 0 ? Math.round((announcement.upvoteCount / totalVotes) * 100) : 0

  const comments = commentsData?.comments ?? []

  return (
    <div className="flex flex-col h-full">
      {/* Sticky header */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b shrink-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex items-center gap-3 min-w-0">
          <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0 rounded-lg" onClick={handleBack}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded-lg', config.bg)}>
            <Icon className={cn('h-3.5 w-3.5', config.color)} />
          </div>
          <span className="text-sm font-semibold truncate">{announcement.title}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg text-muted-foreground" onClick={() => navigator.clipboard.writeText(window.location.href)}>
            <Share2 className="h-4 w-4" />
          </Button>
          {isAdmin && (
            <Button variant="outline" size="sm" className="gap-1.5 rounded-lg text-xs" onClick={handleEdit}>
              <Pencil className="h-3.5 w-3.5" /> Edit
            </Button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {/* Hero media */}
        {hasMedia && announcement.mediaAttachment && (
          <div className="relative">
            <img
              src={announcement.mediaAttachment.cdnUrl}
              alt={announcement.mediaAttachment.filename}
              className="w-full h-56 sm:h-72 object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-transparent" />
          </div>
        )}

        {/* Gradient accent banner for non-media posts */}
        {!hasMedia && (
          <div className={cn('h-24 bg-gradient-to-b', getGradient(announcement.type))} />
        )}

        <div className="max-w-3xl mx-auto w-full px-6 -mt-8 relative pb-12">
          {/* Type + template badges */}
          <div className="flex flex-wrap gap-2 mb-4">
            <Badge className={cn('gap-1.5 rounded-lg', config.bg, config.color, 'border', config.border)}>
              <Icon className="h-3 w-3" />
              {config.label}
            </Badge>
            <Badge variant="secondary" className="rounded-lg text-[11px]">
              {TEMPLATE_LABELS[announcement.template] ?? announcement.template}
            </Badge>
            {!announcement.isActive && (
              <Badge variant="secondary" className="gap-1 text-muted-foreground rounded-lg text-[11px]">
                <EyeOff className="h-3 w-3" /> Inactive
              </Badge>
            )}
            {announcement.targetRoles && announcement.targetRoles.length > 0 && (
              <Badge variant="secondary" className="gap-1 rounded-lg text-[11px]">
                <Users className="h-3 w-3" />
                {announcement.targetRoles.join(', ')}
              </Badge>
            )}
          </div>

          {/* Title */}
          <h1 className="text-2xl sm:text-3xl font-bold leading-tight tracking-tight">
            {announcement.title}
          </h1>

          {/* Author + Date row */}
          <div className="flex items-center gap-3 mt-4">
            <AuthorAvatar name={authorName} />
            <div>
              <p className="text-sm font-medium">{authorName}</p>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  {format(createdAt, 'MMMM d, yyyy')}
                </span>
                <span>·</span>
                <span>{formatRelativeTime(announcement.createdAt)}</span>
              </div>
            </div>
          </div>

          {expiresAt && (
            <div className="mt-3 flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 rounded-lg px-3 py-1.5 w-fit">
              <Clock className="h-3.5 w-3.5" />
              Expires {format(expiresAt, 'MMM d, yyyy')}
            </div>
          )}

          <Separator className="my-6" />

          {/* Video */}
          {hasVideo && announcement.mediaAttachment && (
            <div className="rounded-xl border overflow-hidden mb-6">
              <video
                src={announcement.mediaAttachment.cdnUrl}
                controls
                className="w-full max-h-[400px]"
              />
            </div>
          )}

          {/* Document */}
          {hasDoc && announcement.mediaAttachment && (
            <a
              href={announcement.mediaAttachment.cdnUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-4 rounded-xl border bg-muted/30 hover:bg-muted/60 transition-colors mb-6"
            >
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-background border">
                <FileText className="h-6 w-6 text-muted-foreground" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{announcement.mediaAttachment.filename}</p>
                <p className="text-xs text-muted-foreground">Click to download</p>
              </div>
              <Download className="h-4 w-4 text-muted-foreground shrink-0" />
            </a>
          )}

          {/* Body content */}
          <article className="prose prose-sm dark:prose-invert max-w-none">
            <div className="text-[15px] leading-[1.8] whitespace-pre-wrap text-foreground">
              {announcement.content}
            </div>
          </article>

          <Separator className="my-6" />

          {/* Voting section */}
          <div className="rounded-xl border bg-muted/20 p-5">
            <p className="text-sm font-medium mb-3">Was this helpful?</p>
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleVote('UP')}
                disabled={vote.isPending}
                className={cn(
                  'flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium transition-all',
                  announcement.userVote === 'UP'
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 shadow-sm ring-1 ring-green-200 dark:ring-green-800'
                    : 'bg-background border hover:bg-muted text-muted-foreground hover:text-foreground',
                )}
              >
                <ThumbsUp className={cn('h-4 w-4', announcement.userVote === 'UP' && 'fill-current')} />
                <span className="tabular-nums">{announcement.upvoteCount}</span>
              </button>
              <button
                onClick={() => handleVote('DOWN')}
                disabled={vote.isPending}
                className={cn(
                  'flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium transition-all',
                  announcement.userVote === 'DOWN'
                    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 shadow-sm ring-1 ring-red-200 dark:ring-red-800'
                    : 'bg-background border hover:bg-muted text-muted-foreground hover:text-foreground',
                )}
              >
                <ThumbsDown className={cn('h-4 w-4', announcement.userVote === 'DOWN' && 'fill-current')} />
                <span className="tabular-nums">{announcement.downvoteCount}</span>
              </button>

              {totalVotes > 0 && (
                <div className="flex items-center gap-2 ml-auto text-xs text-muted-foreground">
                  <div className="w-20 h-1.5 rounded-full bg-muted overflow-hidden">
                    <div className="h-full rounded-full bg-green-500 transition-all" style={{ width: `${upPct}%` }} />
                  </div>
                  <span className="tabular-nums">{upPct}% helpful</span>
                </div>
              )}
            </div>
          </div>

          {/* ── Emoji Reactions ───────────────────────────────────────────── */}
          <div className="mt-5 rounded-xl border bg-muted/10 p-5 relative">
            <p className="text-sm font-medium mb-3">React to this</p>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Grouped reactions from server */}
              {(() => {
                const reactions = announcement.reactions ?? []
                const myEmoji = announcement.userReaction?.emoji
                const grouped = reactions.reduce<Record<string, { count: number; mine: boolean }>>((acc, r) => {
                  if (!acc[r.emoji]) acc[r.emoji] = { count: 0, mine: false }
                  acc[r.emoji].count++
                  if (myEmoji && r.emoji === myEmoji) acc[r.emoji].mine = true
                  return acc
                }, {})
                return Object.entries(grouped).map(([emoji, { count, mine }]) => (
                  <button
                    key={emoji}
                    onClick={() => mine ? removeReaction.mutate() : handleReact(emoji)}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-sm transition-all',
                      mine
                        ? 'bg-primary/10 border-primary/30 text-primary font-medium'
                        : 'bg-background text-muted-foreground hover:text-foreground hover:bg-accent'
                    )}
                  >
                    <span>{emoji}</span>
                    <span className="text-xs tabular-nums">{count}</span>
                  </button>
                ))
              })()}

              {/* Add reaction button */}
              <div className="relative">
                <button
                  onClick={() => setShowEmojiPicker((v) => !v)}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-sm transition-all',
                    showEmojiPicker
                      ? 'bg-primary/10 border-primary/30 text-primary'
                      : 'bg-background text-muted-foreground hover:text-foreground hover:bg-accent'
                  )}
                >
                  <SmilePlus className="h-4 w-4" />
                  <span className="text-xs">Add reaction</span>
                </button>

                {showEmojiPicker && (
                  <div className="absolute left-0 bottom-full mb-2 z-50">
                    <EmojiPicker
                      onSelect={handleReact}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── Comments ─────────────────────────────────────────────────── */}
          <div className="mt-5 rounded-xl border bg-card">
            {/* Header */}
            <div className="flex items-center gap-2 px-5 py-3.5 border-b">
              <MessageSquare className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">
                Comments {comments.length > 0 && <span className="text-muted-foreground font-normal">({comments.length})</span>}
              </span>
            </div>

            {/* Comment input */}
            <div className="flex items-start gap-3 p-4 border-b">
              {user && (
                <AuthorAvatar name={user.name} size="sm" />
              )}
              <div className="flex-1 relative">
                <textarea
                  ref={commentRef}
                  value={commentInput}
                  onChange={(e) => setCommentInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault()
                      handleSubmitComment()
                    }
                  }}
                  placeholder="Add a comment…"
                  rows={2}
                  className="w-full resize-none rounded-xl border bg-muted/30 px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                />
              </div>
              <Button
                size="icon"
                className="h-8 w-8 rounded-xl shrink-0 mt-0.5"
                disabled={!commentInput.trim() || addComment.isPending}
                onClick={handleSubmitComment}
              >
                <Send className="h-3.5 w-3.5" />
              </Button>
            </div>

            {/* Comments list */}
            <div className="divide-y">
              {commentsLoading ? (
                <div className="p-4 space-y-3">
                  {[...Array(2)].map((_, i) => (
                    <div key={i} className="flex gap-3">
                      <Skeleton className="h-7 w-7 rounded-full shrink-0" />
                      <div className="flex-1 space-y-1.5">
                        <Skeleton className="h-3 w-24" />
                        <Skeleton className="h-3 w-full" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : comments.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-8 text-muted-foreground">
                  <MessageSquare className="h-8 w-8 opacity-30" />
                  <p className="text-sm">No comments yet. Be the first!</p>
                </div>
              ) : (
                comments.map((comment) => {
                  const isOwn = comment.user.id === user?.id
                  const canDelete = isOwn || isAdmin
                  return (
                    <div key={comment.id} className="flex items-start gap-3 px-5 py-4 group hover:bg-muted/20 transition-colors">
                      <AuthorAvatar name={comment.user.name} size="sm" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-xs font-semibold">{comment.user.name}</span>
                          <span className="text-[10px] text-muted-foreground">{formatRelativeTime(comment.createdAt)}</span>
                          {comment.user.role !== 'USER' && (
                            <Badge variant="secondary" className="text-[9px] px-1.5 py-0 rounded-md h-4">
                              {comment.user.role === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'}
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm whitespace-pre-wrap break-words leading-relaxed">{comment.content}</p>
                      </div>
                      {canDelete && (
                        <button
                          onClick={() => deleteComment.mutate(comment.id)}
                          className="opacity-60 hover:opacity-100 transition-opacity h-6 w-6 flex items-center justify-center rounded-lg hover:bg-destructive/10 text-muted-foreground hover:text-destructive shrink-0 ml-auto"
                          title="Delete comment"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
