import { useState, useCallback, useEffect, useMemo, memo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Check, CheckCheck, Trash2, Smile, Reply, Copy, Megaphone, ExternalLink, MoreVertical } from 'lucide-react'
import { format } from 'date-fns'
import { cn, parseTimestamp, getInitials } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { EmojiPicker } from '@/components/ui/EmojiPicker'
import { MediaViewer } from './MediaViewer'
import { MediaGrid, DocumentPreview } from './MediaGrid'
import type { Message, InternalMessage, DirectMessage } from '@/lib/schemas'
import { DeleteMessageDialog } from './DeleteMessageDialog'
import { useAuthStore } from '@/stores/authStore'
import { LeafLogo } from '@/components/ui/LeafLogo'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

export interface ReactionGroup {
  emoji: string
  count: number
  users: string[]
  hasReacted: boolean
}

type GenericMessage = Message | InternalMessage | DirectMessage

export interface MessageBubbleProps {
  message: GenericMessage & {
    linkedAnnouncement?: { id: string; title: string; type: string } | null
    status?: string
  }
  hideAvatar?: boolean
  bubbleClassName?: string
  onReply?: (msg: GenericMessage) => void
  onReact?: (emoji: string) => void
  onDelete?: (scope: 'me' | 'all') => void
  canDeleteOverride?: boolean
  // Multi-select mode
  isSelectMode?: boolean
  isSelected?: boolean
  onSelect?: (id: string) => void
}

function StatusIcon({ status, isSending }: { status: string; isSending?: boolean }) {
  if (isSending) {
    return <LeafLogo className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
  }
  if (status === 'READ') {
    return <CheckCheck className="h-3.5 w-3.5 text-blue-500" />
  }
  return <Check className="h-3.5 w-3.5 text-muted-foreground" />
}

function MessageBubbleInner({
  message,
  hideAvatar,
  bubbleClassName,
  onReply,
  onReact,
  onDelete,
  canDeleteOverride,
  isSelectMode,
  isSelected,
  onSelect,
}: MessageBubbleProps) {
  const user = useAuthStore((s) => s.user)
  const navigate = useNavigate()
  const [viewerOpen, setViewerOpen] = useState(false)
  const [viewerIndex, setViewerIndex] = useState(0)
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [showMobileEmojiPicker, setShowMobileEmojiPicker] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const longPressTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [mobileActionsOpen, setMobileActionsOpen] = useState(false)

  const isMine = user?.id === message.senderId || (message.sender && user?.id === message.sender.id)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const isDeleted = 'deletedAt' in message ? !!message.deletedAt : false
  const isTemp = message.id.startsWith('temp-')

  const mediaList = message.media ? [message.media] : []
  const imagesAndVideos = mediaList.filter((m) => m.type === 'IMAGE' || m.type === 'VIDEO')
  const documentItems = mediaList.filter((m) => m.type === 'DOCUMENT')

  useEffect(() => {
    if (isAdmin || !isMine || isDeleted || isTemp) return
    const timer = window.setInterval(() => {
      setNowMs(Date.now())
    }, 30_000)
    return () => {
      window.clearInterval(timer)
    }
  }, [isAdmin, isMine, isDeleted, isTemp])

  const canDelete = canDeleteOverride ?? (!isDeleted && !isTemp && (
    isAdmin ||
    (isMine && (nowMs - parseTimestamp(message.createdAt).getTime()) < 300_000)
  ))

  const canReact = !isDeleted && !isTemp && !!onReact

  const handleContextMenu = useCallback(
    (e: React.MouseEvent) => {
      if (isSelectMode) { e.preventDefault(); onSelect?.(message.id); return }
      if (!canDelete || !onDelete) return
      e.preventDefault()
      setDeleteConfirmOpen(true)
    },
    [canDelete, onDelete, isSelectMode, onSelect, message.id],
  )

  const handleTouchStart = useCallback(() => {
    if (isSelectMode) return
    if (isDeleted || isTemp) return
    longPressTimer.current = setTimeout(() => {
      setMobileActionsOpen(true)
    }, 500)
  }, [isDeleted, isTemp, isSelectMode])

  const handleTouchEnd = useCallback(() => {
    if (longPressTimer.current) {
      clearTimeout(longPressTimer.current)
      longPressTimer.current = null
    }
  }, [])

  const handleCopy = useCallback(() => {
    if (message.content) {
      navigator.clipboard.writeText(message.content)
    }
  }, [message.content])

  const onAnnouncementClick = useCallback(() => {
    if (!message.linkedAnnouncement) return
    const annPath = isAdmin
      ? `/admin/announcements/${message.linkedAnnouncement.id}`
      : `/home/announcements/${message.linkedAnnouncement.id}`
    navigate(annPath)
  }, [message.linkedAnnouncement, isAdmin, navigate])

  const groupedReactions = useMemo(() => {
    const groups: Record<string, ReactionGroup> = {}
    for (const r of message.reactions ?? []) {
      if (!groups[r.emoji]) {
        groups[r.emoji] = { emoji: r.emoji, count: 0, users: [], hasReacted: false }
      }
      groups[r.emoji].count++
      if (r.userId === user?.id) {
        groups[r.emoji].hasReacted = true
      }
      if (r.user?.name) {
        groups[r.emoji].users.push(r.user.name)
      }
    }
    return Object.values(groups)
  }, [message.reactions, user?.id])

  const replyTo = message.replyTo
    ? {
      id: ('id' in message.replyTo) ? message.replyTo.id : ('id' in message ? message.replyToId : undefined),
      senderName: message.replyTo.sender?.name || 'User',
      content: message.replyTo.content,
      isDeleted: 'deletedAt' in message.replyTo ? !!message.replyTo.deletedAt : false,
      type: message.replyTo.type,
    }
    : undefined

  const onReplyPreviewClick = useCallback(() => {
    const targetId = replyTo?.id
    if (!targetId) return
    const el = document.getElementById(`msg-${targetId}`)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [replyTo?.id])

  const handleMediaClick = useCallback((index: number) => {
    setViewerIndex(index)
    setViewerOpen(true)
  }, [])

  if (isDeleted) {
    return (
      <div className={cn('flex mb-3', isMine ? 'justify-end' : 'justify-start')}>
        <div className="max-w-[75%] rounded-lg px-3 py-2 text-xs italic text-muted-foreground bg-muted/50">
          This message was deleted
        </div>
      </div>
    )
  }

  const senderName = message.sender?.name ?? 'User'
  const senderRole = message.sender?.role ?? 'USER'
  const senderLabel =
    senderRole && senderRole !== 'USER' ? `${senderName} (${senderRole === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'})` : senderName
  const initials = getInitials(senderName)

  return (
    <>
      <div
        id={`msg-${message.id}`}
        className={cn(
          'flex mb-3 group items-end gap-2 w-full',
          isMine ? 'justify-end' : 'justify-start',
          isSelectMode && 'cursor-pointer select-none',
          isSelectMode && isSelected && 'bg-primary/10 rounded-lg',
        )}
        onTouchStart={handleTouchStart}
        onTouchEnd={handleTouchEnd}
        onTouchMove={handleTouchEnd}
        onContextMenu={handleContextMenu}
        onClick={isSelectMode ? () => onSelect?.(message.id) : undefined}
      >
        {/* Select mode checkbox */}
        {isSelectMode && (
          <div className={cn(
            'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 mb-1 transition-all',
            isMine ? 'order-last ml-1' : 'order-first mr-1',
            isSelected
              ? 'bg-primary border-primary text-primary-foreground'
              : 'border-muted-foreground/40 bg-background',
          )}>
            {isSelected && (
              <svg viewBox="0 0 12 12" className="h-3 w-3 fill-current">
                <polyline points="2,6 5,9 10,3" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </div>
        )}
        {!isMine && (
          <div
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-[11px] font-bold text-muted-foreground mb-0.5 select-none',
              hideAvatar && 'invisible',
            )}
          >
            {initials}
          </div>
        )}

        <div className={cn('flex items-end gap-1.5 max-w-[75%]', isMine ? 'flex-row-reverse' : 'flex-row')}>
          {/* Main Bubble Content */}
          <div className={cn('flex flex-col', isMine ? 'items-end' : 'items-start min-w-0 flex-1')}>
            <div
              className={cn(
                'rounded-2xl px-2.5 py-1.5 shadow-sm relative break-words overflow-visible',
                isMine ? 'bg-[#d9fdd3] dark:bg-[#005c4b] text-foreground rounded-tr-none border border-black/5 dark:border-white/5' : 'bg-card text-card-foreground rounded-tl-none border border-black/5 dark:border-white/5',
                isTemp && 'opacity-70',
                bubbleClassName,
              )}
            >
              {!isMine && (
                <p className={cn('text-[10px] font-semibold uppercase tracking-wider mb-1 line-clamp-1', 'text-muted-foreground')}>
                  {senderLabel}
                </p>
              )}

              {/* Announcement Link */}
              {message.linkedAnnouncement && (
                <button
                  type="button"
                  onClick={onAnnouncementClick}
                  className={cn(
                    'mb-1 rounded-lg px-2.5 py-1.5 border flex items-start gap-2 text-xs w-full text-left transition-opacity hover:opacity-80',
                    isMine ? 'bg-black/5 dark:bg-white/5 border-black/10 dark:border-white/10' : 'bg-background/50 border-border',
                  )}
                >
                  <Megaphone className={cn('h-3.5 w-3.5 mt-0.5 shrink-0', isMine ? 'text-primary' : 'text-primary')} />
                  <div className="min-w-0 flex-1">
                    <p className={cn('text-[10px] font-semibold uppercase tracking-wider mb-0.5', 'text-muted-foreground')}>
                      Announcement
                    </p>
                    <p className={cn('font-medium truncate', 'text-foreground')}>
                      {message.linkedAnnouncement.title}
                    </p>
                  </div>
                  <ExternalLink className={cn('h-3 w-3 mt-0.5 shrink-0 opacity-60')} />
                </button>
              )}

              {/* Reply Preview */}
              {replyTo && (
                <div
                  className={cn(
                    'mb-1 rounded-lg px-2.5 py-1.5 border-l-4 text-xs cursor-pointer hover:opacity-80 transition-opacity',
                    isMine ? 'bg-black/5 dark:bg-black/20 border-primary/50' : 'bg-background/50 border-primary/40',
                  )}
                  onClick={onReplyPreviewClick}
                >
                  <p className={cn('font-semibold text-[10px] mb-0.5', 'text-primary')}>
                    {replyTo.senderName}
                  </p>
                  <p className={cn('truncate text-[11px]', 'text-foreground/80')}>
                    {replyTo.isDeleted
                      ? 'Message deleted'
                      : replyTo.content
                        ? replyTo.content.slice(0, 80) + (replyTo.content.length > 80 ? '…' : '')
                        : `[${(replyTo.type || 'Media').toLowerCase()}]`}
                  </p>
                </div>
              )}

              {/* Media Renderers */}
              {imagesAndVideos.length > 0 && (
                <div className="mb-1.5 -mx-1 -mt-0.5">
                  <MediaGrid
                    media={imagesAndVideos}
                    onMediaClick={handleMediaClick}
                  />
                </div>
              )}

              {documentItems.map((doc) => (
                <DocumentPreview key={doc.id} media={doc} isMine={isMine} />
              ))}

              {/* Text Content with Inline Timestamp hack */}
              {message.content && (
                <p className={cn('text-[14px] whitespace-pre-wrap leading-relaxed inline-block', mediaList.length > 0 && 'px-1 pb-1 pt-0.5')}>
                  {message.content}
                  <span className="inline-block w-12" /> {/* Spacer for inline timestamp */}
                </p>
              )}

              {/* Delivery Status & Timestamp */}
              <div className={cn('float-right flex items-center gap-1 mt-2 ml-2 opacity-70 relative top-[2px]')}>
                <span className={cn('text-[10px] text-foreground/80')}>
                  {format(parseTimestamp(message.createdAt), 'HH:mm')}
                </span>
                {isMine && message.status && <StatusIcon status={message.status} isSending={isTemp} />}
                {isMine && !message.status && isTemp && <span className="text-[10px] pr-1">Sending…</span>}
              </div>
            </div>

            {/* Reactions Below Bubble */}
            {groupedReactions.length > 0 && (
              <div className={cn('flex flex-wrap gap-1 mt-1.5 max-w-[90%]', isMine ? 'justify-end' : 'justify-start')}>
                {groupedReactions.map((group) => (
                  <button
                    key={group.emoji}
                    onClick={() => onReact?.(group.emoji)}
                    className={cn(
                      'text-[12px] px-2 py-0.5 rounded-full transition-all border shrink-0',
                      group.hasReacted
                        ? isMine
                          ? 'bg-black/10 dark:bg-white/10 border-black/20 dark:border-white/20 text-foreground'
                          : 'bg-primary/10 border-primary/20 text-primary'
                        : isMine
                          ? 'bg-black/5 dark:bg-black/20 border-transparent text-foreground/80 hover:bg-black/10 dark:hover:bg-black/40'
                          : 'bg-background/50 border-transparent text-muted-foreground hover:bg-muted',
                    )}
                    title={group.users.length > 0 ? group.users.join(', ') : group.emoji}
                  >
                    {group.emoji} {group.count > 1 && <span className="text-[10px] opacity-70 ml-1">{group.count}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Hover Actions — Desktop only (hidden in select mode) */}
          {!isTemp && !isSelectMode && (
            <div
              className={cn(
                'hidden sm:flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0 mb-1',
                isMine && 'flex-row-reverse',
              )}
            >
              {canReact && onReact && (
                <div className="relative">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-muted-foreground hover:text-foreground"
                    onClick={() => setShowEmojiPicker((v) => !v)}
                  >
                    <Smile className="h-4 w-4" />
                  </Button>
                  {showEmojiPicker && (
                    <div className={cn('absolute bottom-full pb-2 z-50', isMine ? 'right-0' : 'left-0')}>
                      <EmojiPicker
                        onSelect={(emoji) => {
                          onReact(emoji)
                          setShowEmojiPicker(false)
                        }}
                        selectedEmojis={groupedReactions.filter((r) => r.hasReacted).map((r) => r.emoji)}
                      />
                    </div>
                  )}
                </div>
              )}
              {onReply && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-foreground"
                  onClick={() => onReply(message)}
                  title="Reply"
                >
                  <Reply className="h-4 w-4" />
                </Button>
              )}
              {message.content && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-foreground"
                  onClick={handleCopy}
                  title="Copy Text"
                >
                  <Copy className="h-4 w-4" />
                </Button>
              )}
              {canDelete && onDelete && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                  onClick={() => setDeleteConfirmOpen(true)}
                  title="Delete"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </div>
          )}

          {/* Mobile Actions — long-press opens DropdownMenu (hidden in select mode) */}
          {!isTemp && !isSelectMode && (
            <div className={cn('flex sm:hidden items-center shrink-0 mb-1', isMine ? 'flex-row-reverse' : '')}>
              <DropdownMenu open={mobileActionsOpen} onOpenChange={setMobileActionsOpen}>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-muted-foreground opacity-0 group-hover:opacity-100 focus:opacity-100"
                    aria-label="Message actions"
                  >
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align={isMine ? 'end' : 'start'} side="top" className="min-w-[160px]">
                  {canReact && (
                    <DropdownMenuItem
                      onSelect={(e) => { e.preventDefault(); setShowMobileEmojiPicker(v => !v) }}
                      className="gap-2"
                    >
                      <Smile className="h-4 w-4" /> React
                    </DropdownMenuItem>
                  )}
                  {onReply && (
                    <DropdownMenuItem onSelect={() => { onReply(message); setMobileActionsOpen(false) }} className="gap-2">
                      <Reply className="h-4 w-4" /> Reply
                    </DropdownMenuItem>
                  )}
                  {message.content && (
                    <DropdownMenuItem onSelect={() => { handleCopy(); setMobileActionsOpen(false) }} className="gap-2">
                      <Copy className="h-4 w-4" /> Copy Text
                    </DropdownMenuItem>
                  )}
                  {canDelete && onDelete && (
                    <DropdownMenuItem
                      onSelect={() => { setDeleteConfirmOpen(true); setMobileActionsOpen(false) }}
                      className="gap-2 text-destructive focus:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" /> Delete
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
              {showMobileEmojiPicker && canReact && onReact && (
                <div className={cn('absolute bottom-full pb-2 z-50', isMine ? 'right-0' : 'left-0')}>
                  <EmojiPicker
                    onSelect={(emoji) => {
                      onReact(emoji)
                      setShowMobileEmojiPicker(false)
                      setMobileActionsOpen(false)
                    }}
                    selectedEmojis={groupedReactions.filter((r) => r.hasReacted).map((r) => r.emoji)}
                  />
                </div>
              )}
            </div>
          )}
        </div>

        {isMine && (
          <div
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[11px] font-bold text-primary mb-0.5 select-none',
              hideAvatar && 'invisible',
            )}
          >
            {initials}
          </div>
        )}
      </div>

      {viewerOpen && imagesAndVideos.length > 0 && (
        <MediaViewer
          src={imagesAndVideos[viewerIndex]?.cdnUrl || ''}
          type={imagesAndVideos[viewerIndex]?.type as 'IMAGE' | 'VIDEO'}
          filename={imagesAndVideos[viewerIndex]?.filename || ''}
          onClose={() => setViewerOpen(false)}
        />
      )}

      {onDelete && (
        <DeleteMessageDialog
          open={deleteConfirmOpen}
          onOpenChange={setDeleteConfirmOpen}
          message={message}
          onDelete={onDelete}
        />
      )}
    </>
  )
}

export const MessageBubble = memo(MessageBubbleInner, (prev, next) =>
  prev.message === next.message &&
  prev.hideAvatar === next.hideAvatar &&
  prev.bubbleClassName === next.bubbleClassName &&
  prev.canDeleteOverride === next.canDeleteOverride &&
  prev.isSelectMode === next.isSelectMode &&
  prev.isSelected === next.isSelected &&
  prev.onSelect === next.onSelect
)

export const TypingIndicator = memo(function TypingIndicator({ userName }: { userName: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-1 mb-2">
      <span className="text-xs text-muted-foreground italic">{userName} is typing</span>
      <span className="flex gap-0.5">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50 animate-bounce"
            style={{ animationDelay: `${i * 150}ms` }}
          />
        ))}
      </span>
    </div>
  )
})
