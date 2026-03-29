import { useState, useCallback, useMemo, memo, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { Check, CheckCheck, Reply, Copy, Megaphone, ExternalLink, MessageCircle, Plus, Trash2, AlertTriangle, RotateCcw } from 'lucide-react'
import { format } from 'date-fns'
import { cn, parseTimestamp, getInitials } from '@/lib/utils'
import { EmojiPicker } from '@/components/ui/EmojiPicker'
import { MediaGrid, DocumentPreview } from './MediaGrid'
import type { Message, InternalMessage, DirectMessage } from '@/lib/schemas'
import { useAuthStore } from '@/stores/authStore'
import { LeafLogo } from '@/components/ui/LeafLogo'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

const QUICK_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏']

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
  isNextSame?: boolean
  bubbleClassName?: string
  onReply?: (msg: GenericMessage) => void
  onReact?: (emoji: string) => void
  onDelete?: (scope: 'me' | 'all') => void
  onRetry?: () => void
  canDeleteOverride?: boolean
  onAvatarClick?: (senderId: string, senderName: string) => void
  groupMode?: boolean
  groupSize?: number
  readCount?: number
  isSelectMode?: boolean
  isSelected?: boolean
  onSelect?: (id: string) => void
}

function StatusIcon({ status, isSending, groupMode, groupSize, readCount }: {
  status: string; isSending?: boolean; groupMode?: boolean; groupSize?: number; readCount?: number
}) {
  if (isSending) return <LeafLogo className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
  if (status === 'FAILED') return <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
  if (groupMode) {
    const allRead = typeof readCount === 'number' && typeof groupSize === 'number' && groupSize > 0 && readCount >= groupSize
    if (status === 'READ' || allRead) return <CheckCheck className="h-3.5 w-3.5 text-blue-500 dark:text-sky-400" />
    return <Check className="h-3.5 w-3.5 text-muted-foreground/70" />
  }
  // 1:1: single grey = sent, double blue = read
  if (status === 'READ') return <CheckCheck className="h-3.5 w-3.5 text-blue-500 dark:text-sky-400" />
  return <Check className="h-3.5 w-3.5 text-muted-foreground/70" />
}

// ─── Cursor-positioned context menu ──────────────────────────────────────────
function ContextMenu({ x, y, isMine: _isMine, isAdmin, canDelete, hasText, canReact, hasReply,
  onClose, onReply, onCopy, onDelete, onOpenFullPicker, onQuickReact, reactedEmojis }: {
  x: number; y: number; isMine: boolean; isAdmin: boolean; canDelete: boolean
  hasText: boolean; canReact: boolean; hasReply: boolean
  onClose: () => void; onReply: () => void; onCopy: () => void
  onDelete: (s: 'me' | 'all') => void; onOpenFullPicker: () => void
  onQuickReact: (e: string) => void; reactedEmojis: string[]
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })

  useEffect(() => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    setPos({
      x: x + r.width > window.innerWidth - 8 ? window.innerWidth - r.width - 8 : x,
      y: y + r.height > window.innerHeight - 8 ? y - r.height : y,
    })
  }, [x, y])

  useEffect(() => {
    const h = (e: MouseEvent | TouchEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('mousedown', h)
    document.addEventListener('touchstart', h)
    document.addEventListener('keydown', k)
    return () => { document.removeEventListener('mousedown', h); document.removeEventListener('touchstart', h); document.removeEventListener('keydown', k) }
  }, [onClose])

  return createPortal(
    <div ref={ref} style={{ left: pos.x, top: pos.y }}
      className="fixed z-[9999] min-w-[200px] rounded-2xl border border-border/60 bg-popover shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-100 ring-1 ring-black/10 dark:ring-white/10"
      onClick={e => e.stopPropagation()}
    >
      {canReact && (
        <div className="flex items-center gap-1 px-3 py-2.5 border-b border-border/40 bg-muted/20">
          {QUICK_EMOJIS.map(emoji => (
            <button key={emoji} onClick={() => { onQuickReact(emoji); onClose() }}
              className={cn('text-xl h-9 w-9 flex items-center justify-center rounded-full transition-all hover:scale-125 hover:bg-accent',
                reactedEmojis.includes(emoji) && 'ring-2 ring-primary/60 bg-primary/10 scale-110')}
              title={emoji}>{emoji}</button>
          ))}
          <button onClick={() => { onOpenFullPicker(); onClose() }}
            className="h-9 w-9 flex items-center justify-center rounded-full bg-muted text-muted-foreground hover:bg-accent hover:text-foreground transition-all"
            title="More reactions"><Plus className="h-4 w-4" /></button>
        </div>
      )}
      <div className="py-1">
        {hasReply && (
          <button onClick={() => { onReply(); onClose() }}
            className="flex items-center gap-3 w-full px-4 py-2.5 text-sm text-foreground hover:bg-accent transition-colors cursor-pointer">
            <Reply className="h-4 w-4 text-muted-foreground" />Reply
          </button>
        )}
        {hasText && (
          <button onClick={() => { onCopy(); onClose() }}
            className="flex items-center gap-3 w-full px-4 py-2.5 text-sm text-foreground hover:bg-accent transition-colors cursor-pointer">
            <Copy className="h-4 w-4 text-muted-foreground" />Copy text
          </button>
        )}
        {canDelete && (
          <>
            <div className="h-px bg-border/40 mx-2 my-1" />
            {isAdmin && (
              <button onClick={() => { onDelete('all'); onClose() }}
                className="flex items-center gap-3 w-full px-4 py-2.5 text-sm text-destructive hover:bg-destructive/10 transition-colors">
                <Trash2 className="h-4 w-4" />Delete for everyone
              </button>
            )}
            <button onClick={() => { onDelete('me'); onClose() }}
              className="flex items-center gap-3 w-full px-4 py-2.5 text-sm text-destructive/80 hover:bg-destructive/10 transition-colors">
              <Trash2 className="h-4 w-4" />Delete for me
            </button>
          </>
        )}
      </div>
    </div>,
    document.body
  )
}

// ─── Mobile bottom sheet ──────────────────────────────────────────────────────
function MobileSheet({ isMine: _isMine, isAdmin, canDelete, hasText, canReact, hasReply,
  onClose, onReply, onCopy, onDelete, onOpenFullPicker, onQuickReact, reactedEmojis }: {
  isMine: boolean; isAdmin: boolean; canDelete: boolean; hasText: boolean
  canReact: boolean; hasReply: boolean
  onClose: () => void; onReply: () => void; onCopy: () => void
  onDelete: (s: 'me' | 'all') => void; onOpenFullPicker: () => void
  onQuickReact: (e: string) => void; reactedEmojis: string[]
}) {
  return createPortal(
    <div className="fixed inset-0 z-[9998] flex items-end animate-in fade-in duration-150" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[2px]" />
      <div className="relative w-full rounded-t-3xl border-t border-border/40 bg-popover shadow-2xl animate-in slide-in-from-bottom duration-200"
        onClick={e => e.stopPropagation()}>
        <div className="flex justify-center pt-3 pb-1">
          <div className="h-1 w-10 rounded-full bg-muted-foreground/30" />
        </div>
        {canReact && (
          <div className="flex items-center justify-center gap-2 px-4 py-3 border-b border-border/30">
            {QUICK_EMOJIS.map(emoji => (
              <button key={emoji} onClick={() => { onQuickReact(emoji); onClose() }}
                className={cn('text-2xl h-12 w-12 flex items-center justify-center rounded-full transition-all active:scale-90',
                  reactedEmojis.includes(emoji) ? 'ring-2 ring-primary/60 bg-primary/10 scale-110 cursor-pointer' : 'hover:bg-accent cursor-pointer')}
              >{emoji}</button>
            ))}
            <button onClick={() => { onOpenFullPicker(); onClose() }}
              className="h-12 w-12 flex items-center justify-center rounded-full bg-muted text-muted-foreground active:scale-90">
              <Plus className="h-5 w-5" />
            </button>
          </div>
        )}
        <div className="py-2">
          {hasReply && (
            <button onClick={() => { onReply(); onClose() }}
              className="flex items-center gap-4 w-full px-5 py-3.5 text-[15px] text-foreground active:bg-accent">
              <Reply className="h-5 w-5 text-muted-foreground" />Reply
            </button>
          )}
          {hasText && (
            <button onClick={() => { onCopy(); onClose() }}
              className="flex items-center gap-4 w-full px-5 py-3.5 text-[15px] text-foreground active:bg-accent">
              <Copy className="h-5 w-5 text-muted-foreground" />Copy text
            </button>
          )}
          {canDelete && (
            <>
              <div className="h-px bg-border/40 mx-4 my-1" />
              {isAdmin && (
                <button onClick={() => { onDelete('all'); onClose() }}
                  className="flex items-center gap-4 w-full px-5 py-3.5 text-[15px] text-destructive active:bg-destructive/10">
                  <Trash2 className="h-5 w-5" />Delete for everyone
                </button>
              )}
              <button onClick={() => { onDelete('me'); onClose() }}
                className="flex items-center gap-4 w-full px-5 py-3.5 text-[15px] text-destructive/80 active:bg-destructive/10">
                <Trash2 className="h-5 w-5" />Delete for me
              </button>
            </>
          )}
        </div>
        <div className="px-4 pb-6 pt-1">
          <button onClick={onClose}
            className="w-full py-3.5 rounded-xl bg-muted text-foreground font-semibold text-[15px] active:bg-muted/70">
            Cancel
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}

// ─── Quick react bar (desktop hover, floats above bubble) ────────────────────
// ─── Emoji trigger button + click-opened reaction popup ──────────────────────
function ReactButton({ isMine, reactedEmojis, onReact, onOpenFullPicker }: {
  isMine: boolean; reactedEmojis: string[]
  onReact: (e: string) => void; onOpenFullPicker: () => void
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [open])

  return (
    <div className="relative" ref={ref}>
      {/* Small emoji trigger — visible on group-hover only */}
      <button
        onClick={e => { e.stopPropagation(); setOpen(v => !v) }}
        className={cn(
          'h-7 w-7 flex items-center justify-center rounded-full text-[15px]',
          'opacity-0 group-hover:opacity-100 transition-all duration-150',
          'hover:bg-accent hover:scale-110',
          open && 'opacity-100 bg-accent',
        )}
        title="React"
      >
        😊
      </button>

      {/* Quick reaction popup — only opens on click */}
      {open && (
        <div className={cn(
          'absolute bottom-full mb-1 flex items-center gap-0.5 px-2 py-1.5 rounded-full',
          'bg-popover border border-border/60 shadow-xl z-30',
          'animate-in fade-in zoom-in-90 duration-100',
          isMine ? 'right-0' : 'left-0',
        )}>
          {QUICK_EMOJIS.map(emoji => (
            <button key={emoji}
              onClick={e => { e.stopPropagation(); onReact(emoji); setOpen(false) }}
              className={cn(
                'text-[22px] h-9 w-9 flex items-center justify-center rounded-full transition-all hover:scale-125 hover:bg-accent',
                reactedEmojis.includes(emoji) && 'ring-2 ring-primary/60 bg-primary/10 scale-110',
              )}
              title={emoji}>{emoji}</button>
          ))}
          <button
            onClick={e => { e.stopPropagation(); onOpenFullPicker(); setOpen(false) }}
            className="h-9 w-9 flex items-center justify-center rounded-full bg-muted text-muted-foreground hover:bg-accent hover:text-foreground transition-all"
            title="More reactions"
          ><Plus className="h-4 w-4" /></button>
        </div>
      )}
    </div>
  )
}

// ─── Main bubble ──────────────────────────────────────────────────────────────
function MessageBubbleInner({
  message, hideAvatar, isNextSame, bubbleClassName, onReply, onReact, onDelete, onRetry, canDeleteOverride,
  onAvatarClick, isSelectMode, isSelected, onSelect, groupMode, groupSize, readCount,
}: MessageBubbleProps) {
  const user = useAuthStore((s) => s.user)
  const navigate = useNavigate()

  const [viewerOpen, setViewerOpen] = useState(false)
  const [viewerIndex, setViewerIndex] = useState(0)
  const [fullPickerOpen, setFullPickerOpen] = useState(false)
  const fullPickerRef = useRef<HTMLDivElement>(null)
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null)
  const [mobileSheetOpen, setMobileSheetOpen] = useState(false)
  const longPressTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const isMine = user?.id === message.senderId || (message.sender && user?.id === message.sender.id)
  const isFailed = (message as any).status === 'FAILED'
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const isDeleted = 'deletedAt' in message ? !!message.deletedAt : false
  const isTemp = message.id.startsWith('temp-')

  const mediaList = message.media ? [message.media] : []
  const imagesOnly = mediaList.filter((m) => m.type === 'IMAGE')
  const documentItems = mediaList.filter((m) => m.type === 'DOCUMENT')

  const canDelete = canDeleteOverride ?? (!isDeleted && !isTemp && (isAdmin || isMine))
  const canReact = !isDeleted && !isTemp && !!onReact
  // Trim and normalize so whitespace-only or newline-heavy messages don't bloat the bubble.
  // Collapses leading/trailing whitespace AND 3+ consecutive newlines → max 2 (one blank line).
  const trimmedContent = message.content?.trim().replace(/\n{3,}/g, '\n\n') ?? ''
  const hasText = !!trimmedContent
  const hasReply = !!onReply && !isDeleted && !isTemp

  const groupedReactions = useMemo(() => {
    const groups: Record<string, ReactionGroup> = {}
    for (const r of message.reactions ?? []) {
      if (!groups[r.emoji]) groups[r.emoji] = { emoji: r.emoji, count: 0, users: [], hasReacted: false }
      groups[r.emoji].count++
      if (r.userId === user?.id) groups[r.emoji].hasReacted = true
      if (r.user?.name) groups[r.emoji].users.push(r.user.name)
    }
    return Object.values(groups)
  }, [message.reactions, user?.id])

  const reactedEmojis = useMemo(() => groupedReactions.filter(r => r.hasReacted).map(r => r.emoji), [groupedReactions])

  const replyTo = message.replyTo ? {
    id: ('id' in message.replyTo) ? message.replyTo.id : (message as any).replyToId,
    senderName: message.replyTo.sender?.name || 'User',
    content: message.replyTo.content,
    isDeleted: 'deletedAt' in message.replyTo ? !!message.replyTo.deletedAt : false,
    type: message.replyTo.type,
  } : undefined

  // Close full picker on outside click
  useEffect(() => {
    if (!fullPickerOpen) return
    const h = (e: MouseEvent) => {
      if (fullPickerRef.current && !fullPickerRef.current.contains(e.target as Node)) setFullPickerOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [fullPickerOpen])

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    if (isSelectMode) { e.preventDefault(); onSelect?.(message.id); return }
    if (isDeleted || isTemp) return
    e.preventDefault()
    setCtxMenu({ x: e.clientX, y: e.clientY })
  }, [isSelectMode, onSelect, message.id, isDeleted, isTemp])

  const handleTouchStart = useCallback(() => {
    if (isSelectMode || isDeleted || isTemp) return
    longPressTimer.current = setTimeout(() => {
      setMobileSheetOpen(true)
      if ('vibrate' in navigator) navigator.vibrate(10)
    }, 450)
  }, [isSelectMode, isDeleted, isTemp])

  const handleTouchEnd = useCallback(() => {
    if (longPressTimer.current) { clearTimeout(longPressTimer.current); longPressTimer.current = null }
  }, [])

  const handleCopy = useCallback(() => {
    if (message.content) navigator.clipboard.writeText(message.content)
  }, [message.content])

  const handleReact = useCallback((emoji: string) => onReact?.(emoji), [onReact])
  const handleDelete = useCallback((scope: 'me' | 'all') => onDelete?.(scope), [onDelete])

  const onReplyPreviewClick = useCallback(() => {
    const el = document.getElementById(`msg-${replyTo?.id}`)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [replyTo?.id])

  const onAnnouncementClick = useCallback(() => {
    if (!message.linkedAnnouncement) return
    navigate(isAdmin ? `/admin/announcements/${message.linkedAnnouncement.id}` : `/home/announcements/${message.linkedAnnouncement.id}`)
  }, [message.linkedAnnouncement, isAdmin, navigate])

  const senderName = message.sender?.name ?? 'User'
  const senderRole = message.sender?.role ?? 'USER'
  const formattedRole = senderRole === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'
  const senderLabel = senderRole !== 'USER' 
    ? (senderName.toLowerCase() === formattedRole.toLowerCase() ? formattedRole : `${senderName} (${formattedRole})`) 
    : senderName
  const initials = getInitials(senderName)

  if (isDeleted) {
    return (
      <div className={cn('flex mb-3', isMine ? 'justify-end' : 'justify-start')}>
        <div className="max-w-[75%] rounded-lg px-3 py-2 text-xs italic text-muted-foreground bg-muted/50">
          This message was deleted
        </div>
      </div>
    )
  }

  return (
    <>
      <div
        id={`msg-${message.id}`}
        className={cn(
          'flex group items-end gap-2 w-full',
          isNextSame ? 'mb-0.5' : 'mb-3',
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
        {/* Select checkbox */}
        {isSelectMode && (
          <div className={cn(
            'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 mb-1 transition-all',
            isMine ? 'order-last ml-1' : 'order-first mr-1',
            isSelected ? 'bg-primary border-primary text-primary-foreground' : 'border-muted-foreground/40 bg-background',
          )}>
            {isSelected && (
              <svg viewBox="0 0 12 12" className="h-3 w-3 fill-current">
                <polyline points="2,6 5,9 10,3" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </div>
        )}

        {/* Incoming avatar */}
        {!isMine && (
          onAvatarClick && !hideAvatar ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <div role="button" tabIndex={0}
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-[11px] font-bold text-muted-foreground mb-0.5 select-none cursor-pointer hover:ring-2 hover:ring-primary/40 transition-all">
                  {initials}
                </div>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" side="top" className="min-w-[160px]">
                <DropdownMenuItem className="gap-2 cursor-pointer" onSelect={() => onAvatarClick(message.senderId, senderName)}>
                  <MessageCircle className="h-4 w-4" />Message privately
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-[11px] font-bold text-muted-foreground mb-0.5 select-none', hideAvatar && 'invisible')}>
              {initials}
            </div>
          )
        )}

        <div className={cn('flex items-end gap-1.5 max-w-[75%]', isMine ? 'flex-row-reverse' : 'flex-row')}>
          {/* Bubble wrapper */}
          <div className={cn('flex flex-col relative', isMine ? 'items-end' : 'items-start min-w-0 flex-1')}>

            {/* Full emoji picker overlay (opened from ReactButton "more" or context menu) */}
            {fullPickerOpen && onReact && (
              <div ref={fullPickerRef}
                className={cn('absolute z-50', isMine ? 'right-0' : 'left-0', 'bottom-full mb-2')}>
                <EmojiPicker
                  onSelect={(emoji) => { handleReact(emoji); setFullPickerOpen(false) }}
                  selectedEmojis={reactedEmojis}
                />
              </div>
            )}

            <div className={cn(
              'rounded-2xl px-2.5 pt-1.5 shadow-[0_1px_1px_rgba(0,0,0,0.1)] relative break-words overflow-visible',
              groupedReactions.length > 0 ? 'pb-3.5 mb-2.5' : 'pb-1.5',
              isMine
                ? ['bg-[#d9fdd3] dark:bg-[#005c4b] text-foreground border border-black/5 dark:border-white/5', !hideAvatar && 'rounded-tr-none']
                : ['bg-card text-card-foreground border border-black/5 dark:border-white/5', !hideAvatar && 'rounded-tl-none'],
              isTemp && 'opacity-70',
              isFailed && 'border-destructive/40 bg-destructive/5 dark:bg-destructive/10',
              isFailed && isMine && '!bg-destructive/10 dark:!bg-destructive/15',
              bubbleClassName,
            )}>
              {!isMine && !hideAvatar && (
                <p className="text-[10px] font-semibold uppercase tracking-wider mb-1 line-clamp-1 text-muted-foreground">{senderLabel}</p>
              )}

              {/* Announcement link */}
              {message.linkedAnnouncement && (
                <button type="button" onClick={onAnnouncementClick}
                  className={cn('mb-1 rounded-lg px-2.5 py-1.5 border flex items-start gap-2 text-xs w-full text-left transition-opacity hover:opacity-80',
                    isMine ? 'bg-black/5 dark:bg-white/5 border-black/10 dark:border-white/10' : 'bg-background/50 border-border')}>
                  <Megaphone className="h-3.5 w-3.5 mt-0.5 shrink-0 text-primary" />
                  <div className="min-w-0 flex-1">
                    <p className="text-[10px] font-semibold uppercase tracking-wider mb-0.5 text-muted-foreground">Announcement</p>
                    <p className="font-medium truncate text-foreground">{message.linkedAnnouncement.title}</p>
                  </div>
                  <ExternalLink className="h-3 w-3 mt-0.5 shrink-0 opacity-60" />
                </button>
              )}

              {/* Reply preview */}
              {replyTo && (
                <div onClick={onReplyPreviewClick}
                  className={cn('mb-1 rounded-lg px-2.5 py-1.5 border-l-4 text-xs cursor-pointer hover:opacity-80 transition-opacity',
                    isMine ? 'bg-black/5 dark:bg-black/20 border-primary/50' : 'bg-background/50 border-primary/40')}>
                  <p className="font-semibold text-[10px] mb-0.5 text-primary">{replyTo.senderName}</p>
                  <p className="truncate text-[11px] text-foreground/80">
                    {replyTo.isDeleted ? 'Message deleted'
                      : replyTo.content ? replyTo.content.slice(0, 80) + (replyTo.content.length > 80 ? '…' : '')
                      : replyTo.type === 'IMAGE' ? '🖼 Image'
                      : replyTo.type === 'DOCUMENT' ? '📄 Document'
                      : `[${(replyTo.type || 'media').toLowerCase()}]`}
                  </p>
                </div>
              )}

              {/* Media */}
              {imagesOnly.length > 0 && (
                <div className="mb-1.5 -mx-1 -mt-0.5">
                  <MediaGrid media={imagesOnly} onMediaClick={(i) => { setViewerIndex(i); setViewerOpen(true) }} />
                </div>
              )}
              {documentItems.map((doc) => <DocumentPreview key={doc.id} media={doc} isMine={isMine} />)}

              {/* Text + timestamp — flex-wrap tail keeps timestamp on the last line of text
                  without the float/spacer trick that causes bubble-width jitter at threshold lengths */}
              {trimmedContent ? (
                <div className={cn('flex flex-wrap items-end justify-between gap-x-2', mediaList.length > 0 && 'px-1 pb-1 pt-0.5')}>
                  <p className="text-[14px] whitespace-pre-wrap leading-relaxed flex-1 min-w-0 break-words pr-2">
                    {trimmedContent}
                  </p>
                  <div className="flex items-center gap-1 opacity-70 self-end shrink-0 mb-[1px] ml-1">
                    <span className="text-[10px] text-foreground/80">{format(parseTimestamp(message.createdAt), 'HH:mm')}</span>
                    {isMine && (isTemp
                      ? <LeafLogo className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                      : message.status && (
                        <StatusIcon status={message.status} groupMode={groupMode} groupSize={groupSize}
                          readCount={readCount ?? (message as any).readBy?.length ?? 0} />
                      )
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-end gap-1 mt-1 opacity-70">
                  <span className="text-[10px] text-foreground/80">{format(parseTimestamp(message.createdAt), 'HH:mm')}</span>
                  {isMine && (isTemp
                    ? <LeafLogo className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                    : message.status && (
                      <StatusIcon status={message.status} groupMode={groupMode} groupSize={groupSize}
                        readCount={readCount ?? (message as any).readBy?.length ?? 0} />
                    )
                  )}
                </div>
              )}

              {/* WhatsApp-style Overlapping Reactions */}
              {groupedReactions.length > 0 && (
                <div className={cn(
                  'absolute -bottom-3 flex items-center gap-0.5 shadow-sm rounded-full z-10',
                  isMine ? 'right-4' : 'right-4'
                )}>
                  {groupedReactions.map((group) => (
                    <button key={group.emoji} onClick={(e) => { e.stopPropagation(); onReact?.(group.emoji); }}
                      className={cn(
                        'flex items-center justify-center px-1.5 py-0.5 rounded-full select-none cursor-pointer transition-transform hover:scale-110',
                        'bg-card border-2 border-background dark:border-[#0b141a]', 
                        group.hasReacted ? 'bg-primary/10 border-background dark:border-[#0b141a]' : ''
                      )}
                      title={group.users.length > 0 ? group.users.join(', ') : group.emoji}
                      aria-pressed={group.hasReacted}>
                      <span className="text-[13px] leading-none mb-[1px]">{group.emoji}</span>
                      {group.count > 1 && <span className="text-[10px] font-bold text-muted-foreground ml-0.5 leading-none">{group.count}</span>}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Failed message retry — shown below bubble */}
          {isFailed && isMine && onRetry && (
            <button
              onClick={onRetry}
              className="flex items-center gap-1 mt-1 text-[11px] text-destructive hover:text-destructive/80 transition-colors self-end"
            >
              <RotateCcw className="h-3 w-3" />
              Tap to retry
            </button>
          )}

          {/* Hover action buttons beside the bubble — desktop only */}
          {!isTemp && !isSelectMode && (
            <div className={cn(
              'hidden sm:flex items-center gap-0.5 shrink-0 mb-1',
              isMine ? 'flex-row-reverse' : 'flex-row',
            )}>
              {canReact && (
                <ReactButton
                  isMine={!!isMine}
                  reactedEmojis={reactedEmojis}
                  onReact={handleReact}
                  onOpenFullPicker={() => setFullPickerOpen(true)}
                />
              )}
              {hasReply && (
                <button
                  onClick={() => onReply!(message)}
                  className={cn(
                    'h-7 w-7 flex items-center justify-center rounded-full text-muted-foreground',
                    'opacity-0 group-hover:opacity-100 transition-all hover:bg-accent hover:text-foreground',
                  )}
                  title="Reply"
                >
                  <Reply className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Image lightbox */}
      {viewerOpen && imagesOnly.length > 0 && (() => {
        const img = imagesOnly[viewerIndex]
        return img ? (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm animate-in fade-in duration-200"
            onClick={() => setViewerOpen(false)}>
            <img src={img.cdnUrl} alt={img.filename}
              className="max-h-[90vh] max-w-[90vw] object-contain rounded-lg shadow-2xl"
              onClick={e => e.stopPropagation()} />
            <button onClick={() => setViewerOpen(false)}
              className="absolute top-4 right-4 flex h-9 w-9 items-center justify-center rounded-full bg-black/50 text-white hover:bg-black/70">
              ✕
            </button>
            <a href={img.cdnUrl} download={img.filename} target="_blank" rel="noopener noreferrer"
              className="absolute top-4 right-16 flex h-9 w-9 items-center justify-center rounded-full bg-black/50 text-white hover:bg-black/70"
              onClick={e => e.stopPropagation()}>
              ↓
            </a>
          </div>
        ) : null
      })()}

      {/* Desktop right-click context menu */}
      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} isMine={!!isMine} isAdmin={isAdmin} canDelete={canDelete}
          hasText={hasText} canReact={canReact} hasReply={hasReply} reactedEmojis={reactedEmojis}
          onClose={() => setCtxMenu(null)} onReply={() => onReply?.(message)} onCopy={handleCopy}
          onDelete={handleDelete} onOpenFullPicker={() => setFullPickerOpen(true)} onQuickReact={handleReact} />
      )}

      {/* Mobile long-press bottom sheet */}
      {mobileSheetOpen && (
        <MobileSheet isMine={!!isMine} isAdmin={isAdmin} canDelete={canDelete} hasText={hasText}
          canReact={canReact} hasReply={hasReply} reactedEmojis={reactedEmojis}
          onClose={() => setMobileSheetOpen(false)} onReply={() => onReply?.(message)}
          onCopy={handleCopy} onDelete={handleDelete}
          onOpenFullPicker={() => { setFullPickerOpen(true); setMobileSheetOpen(false) }}
          onQuickReact={handleReact} />
      )}
    </>
  )
}

export const MessageBubble = memo(MessageBubbleInner, (prev, next) =>
  prev.message === next.message &&
  prev.hideAvatar === next.hideAvatar &&
  prev.isNextSame === next.isNextSame &&
  prev.bubbleClassName === next.bubbleClassName &&
  prev.canDeleteOverride === next.canDeleteOverride &&
  prev.onRetry === next.onRetry &&
  prev.onAvatarClick === next.onAvatarClick &&
  prev.isSelectMode === next.isSelectMode &&
  prev.isSelected === next.isSelected &&
  prev.onSelect === next.onSelect &&
  prev.groupMode === next.groupMode &&
  prev.groupSize === next.groupSize &&
  prev.readCount === next.readCount
)

export const TypingIndicator = memo(function TypingIndicator({ userName }: { userName: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-1 mb-2">
      <span className="text-xs text-muted-foreground italic">{userName} is typing…</span>
      <span className="flex gap-0.5">
        {[0, 1, 2].map((i) => (
          <span key={i} className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50 animate-bounce"
            style={{ animationDelay: `${i * 150}ms` }} />
        ))}
      </span>
    </div>
  )
})
