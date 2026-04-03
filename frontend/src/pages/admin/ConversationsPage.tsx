import { useState, useCallback, useEffect, useRef, useMemo, type UIEvent } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { 
  Archive, ArchiveRestore, UserCheck, FileWarning, MoreVertical,
  Users, X, Search, UserCog,
  Megaphone, ArrowLeft, PanelLeft, PanelLeftClose, Building2, Square, CheckSquare,
  UserMinus, ShieldOff, CheckCircle, Inbox, Plus, Mail, Clock, AlertCircle, ChevronDown
} from 'lucide-react'
import { toast } from '@/components/ui/sonner'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
} from '@/components/ui/dropdown-menu'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { cn, getInitials, formatRelativeTime } from '@/lib/utils'
import { useAdminConversations, useMessages, useSendMessage, useMarkRead, useDeleteMessage } from '@/hooks/useMessages'
import { useVisibilityMarkRead } from '@/hooks/useVisibilityMarkRead'
import { useReaction } from '@/hooks/useReactions'
import { useUpdateUserStatus, useAdminList } from '@/hooks/useUsers'
import { useAnnouncements } from '@/hooks/useAnnouncements'
import { useAppConfig } from '@/hooks/useConfig'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'
import { MessageList } from '@/components/chat/MessageList'
import { MessageInput } from '@/components/chat/MessageInput'
import { BulkDeleteBar } from '@/components/chat/BulkDeleteBar'
import { useChatStore } from '@/stores/chatStore'
import { useAuthStore } from '@/stores/authStore'
import { getSocket, setActiveFocusedConversation } from '@/lib/socket'
import { conversations as convApi } from '@/lib/api'
import { prependMessage, replaceTempMessage, softDeleteMessage, markMessagesRead, applyReaction } from '@/lib/messageCache'
import type { MessagesCache } from '@/lib/messageCache'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Conversation, Message, MessageReaction, Status, Role } from '@/lib/schemas'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useQueue, formatWaitDuration } from '@/hooks/useQueue'
import { useArchiveConversation as useArchiveConversationHook, useUnarchiveConversation } from '@/hooks/useArchiveConversation'

const SELECTED_CONV_KEY = 'admin-selected-conversation'

function ConversationItem({
  conversation,
  isSelected,
  isNewlyAssigned,
  subsidiaryName,
  isUserOnline,
  onClick,
  showArchive,
  onArchive,
  onClaim,
}: {
  conversation: Conversation
  isSelected: boolean
  isNewlyAssigned?: boolean
  subsidiaryName?: string
  isUserOnline?: boolean
  onClick: () => void
  showArchive?: boolean
  onArchive?: (archive: boolean) => void
  onClaim?: () => void
}) {
  const userName = conversation.user?.name ?? 'Unknown User'
  const lastMsg = conversation.lastMessage as Message | null | undefined
  const [confirmArchive, setConfirmArchive] = useState(false)
  const senderPrefix = lastMsg?.sender?.role && lastMsg.sender.role !== 'USER' ? `${lastMsg.sender.name}: ` : ''
  const preview = lastMsg?.deletedAt
    ? 'Message deleted'
    : lastMsg?.content
      ? senderPrefix + lastMsg.content.slice(0, 50) + (lastMsg.content.length > 50 ? '…' : '')
      : lastMsg?.type
        ? `${senderPrefix}Sent ${(lastMsg.type as string).toLowerCase()}`
        : 'No messages yet'

  const hasUnread = (conversation.adminUnreadCount ?? 0) > 0

  return (
    <div
      className={cn(
        'w-full flex items-center gap-3 px-3 py-3 text-left transition-all border-b border-border/40 group',
        isSelected ? 'bg-accent' : 'hover:bg-accent/50',
        isNewlyAssigned && !isSelected && 'ring-1 ring-inset ring-amber-400/50 bg-amber-50/30 dark:bg-amber-900/10',
      )}
    >
      <button onClick={onClick} className="flex-1 flex items-center gap-3 min-w-0 cursor-pointer">
        <div className="relative shrink-0">
          <div className={cn(
            'flex h-10 w-10 items-center justify-center rounded-full text-xs font-bold transition-colors',
            isNewlyAssigned ? 'bg-amber-500 text-white' : hasUnread ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground',
          )}>
            {getInitials(userName)}
          </div>
          {isUserOnline && (
            <span className="absolute bottom-0 right-0 h-2.5 w-2.5 rounded-full bg-green-500 border-2 border-background" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className={cn('text-sm truncate', hasUnread || isNewlyAssigned ? 'font-bold' : 'font-medium')}>{userName}</span>
            {conversation.lastMessageAt && (
              <span className={cn('text-[10px] shrink-0', hasUnread ? 'text-primary font-semibold' : 'text-muted-foreground')}>
                {formatRelativeTime(conversation.lastMessageAt)}
              </span>
            )}
          </div>
          <div className="flex items-center justify-between gap-2 mt-0.5">
            <p className={cn('text-xs truncate', hasUnread ? 'text-foreground font-medium' : 'text-muted-foreground')}>{preview}</p>
          <div className="flex items-center gap-1 shrink-0">
                {isNewlyAssigned && <Badge className="h-5 px-1.5 text-[9px] bg-amber-500 text-white rounded-full font-semibold">New</Badge>}
                {/* Waiting badge: user sent a message with no admin reply yet */}
                {!isNewlyAssigned && conversation.waitingSince && (() => {
                  const waitMs = Date.now() - conversation.waitingSince
                  const urgencyClass = waitMs < 15 * 60_000
                    ? 'bg-amber-500'
                    : waitMs < 60 * 60_000
                      ? 'bg-orange-500'
                      : 'bg-destructive'
                  return (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Badge className={`h-5 px-1.5 text-[9px] ${urgencyClass} text-white rounded-full font-semibold flex items-center gap-0.5`}>
                          <Clock className="h-2.5 w-2.5" />
                          {formatWaitDuration(waitMs)}
                        </Badge>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p className="text-xs">
                          {waitMs >= 60 * 60_000 ? 'High priority — waiting over 1h' : 'Waiting for reply'}
                        </p>
                      </TooltipContent>
                    </Tooltip>
                  )
                })()}
                {conversation.registrationReportId && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge 
                        variant="secondary" 
                        className="h-5 px-1.5 text-[9px] bg-amber-100 text-amber-700 hover:bg-amber-200 font-bold border-0 cursor-pointer"
                        onClick={(e) => {
                          e.stopPropagation();
                          window.open(`/admin/reports?highlight=${conversation.registrationReportId}`, '_blank');
                        }}
                      >
                        <FileWarning className="h-3 w-3 mr-0.5" />
                        Report
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="text-xs">Linked to registration report</p>
                      <p className="text-[10px] text-muted-foreground">{conversation.registrationReport?.subject ?? 'View report'}</p>
                    </TooltipContent>
                  </Tooltip>
                )}
                {subsidiaryName && !isNewlyAssigned && (
                  <Badge variant="secondary" className="h-5 px-1.5 text-[9px] bg-primary/15 text-primary hover:bg-primary/25 font-bold border-0">
                    {subsidiaryName}
                  </Badge>
                )}
                {conversation.assignedAdmin && !isNewlyAssigned && (
                  <span className="text-[10px] text-muted-foreground hidden sm:inline">{conversation.assignedAdmin.name.split(' ')[0]}</span>
                )}
                {hasUnread && !isSelected && (
                  <Badge className="h-5 min-w-5 rounded-full px-1.5 text-[10px] bg-primary text-primary-foreground">
                    {conversation.adminUnreadCount}
                  </Badge>
                )}
              </div>
          </div>
        </div>
      </button>
      {/* FIX #24: Claim button for SUPER_ADMIN on unassigned conversations */}
      {onClaim && !conversation.assignedAdminId && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity text-primary hover:bg-primary/10"
              onClick={(e) => { e.stopPropagation(); onClaim() }}
            >
              <UserCheck className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Claim — assign to me</TooltipContent>
        </Tooltip>
      )}
      {/* Archive/Unarchive button for Super Admin */}
      {showArchive && onArchive && (
        conversation.archivedAt ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-9 w-9 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
                onClick={(e) => { e.stopPropagation(); onArchive(false) }}
              >
                <ArchiveRestore className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Unarchive conversation</TooltipContent>
          </Tooltip>
        ) : confirmArchive ? (
          <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
            <span className="text-[10px] text-destructive font-medium whitespace-nowrap">Archive?</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-destructive hover:bg-destructive/10 rounded-lg"
              onClick={(e) => { e.stopPropagation(); setConfirmArchive(false); onArchive(true) }}
            >
              <Archive className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-muted-foreground rounded-lg"
              onClick={(e) => { e.stopPropagation(); setConfirmArchive(false) }}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-9 w-9 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
                onClick={(e) => { e.stopPropagation(); setConfirmArchive(true) }}
              >
                <Archive className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Archive conversation</TooltipContent>
          </Tooltip>
        )
      )}
    </div>
  )
}

type AssignVars = { conversationId: string; adminId: string | null; admin?: { id: string; name: string; role: Role } | null }

function useAssignConversation() {
  const queryClient = useQueryClient()
  return useMutation<{ success: boolean }, unknown, AssignVars, { previousData: unknown }>({
    mutationFn: ({ conversationId, adminId }: AssignVars) =>
      convApi.assign(conversationId, adminId),
    onMutate: ({ conversationId, adminId, admin }: AssignVars) => {
      const previousData = queryClient.getQueryData(['conversations'])
      queryClient.setQueryData<{ pages: Array<{ conversations: Conversation[]; hasMore: boolean }> }>(
        ['conversations'],
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              conversations: p.conversations.map((c) =>
                c.id === conversationId ? { ...c, assignedAdminId: adminId, assignedAdmin: adminId ? (admin ?? c.assignedAdmin) : null } : c
              ),
            })),
          }
        },
      )
      return { previousData }
    },
    onError: (_err: unknown, _vars: AssignVars, context: { previousData: unknown } | undefined) => {
      if (context?.previousData) {
        queryClient.setQueryData(['conversations'], context.previousData)
      }
      toast.error('Failed to update assignment')
    },
    onSuccess: (_data: unknown, { adminId, admin }: AssignVars) => {
      if (adminId && admin) {
        toast.success(`Assigned to ${admin.name.split(' ')[0]}`)
      } else if (!adminId) {
        toast.success('Conversation unassigned')
      }
    },
  })
}



function AdminChatView({
  conversation,
  subsidiaryName,
  subsidiaryIndustry,
  onBack,
  sidebarCollapsed,
  onToggleSidebar,
  onUnarchive,
  isUserOnline,
  workloadMap,
}: {
  conversation: Conversation
  subsidiaryName?: string
  subsidiaryIndustry?: string
  onBack: () => void
  sidebarCollapsed: boolean
  onToggleSidebar: () => void
  onUnarchive: () => void
  isUserOnline: boolean
  workloadMap: Map<string, { activeCount: number; isOnline: boolean }>
}) {
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const conversationId = conversation.id
  const queryClient = useQueryClient()
  const { data: configData } = useAppConfig()
  const subsidiaries = configData?.subsidiaries ?? []

  const { data: msgData, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useMessages(conversationId)
  const sendMessage = useSendMessage(conversationId)
  const markRead = useMarkRead(conversationId)
  const adminUnreadCount = conversation.adminUnreadCount ?? 0
  const { sentinelRef: lastMsgRef } = useVisibilityMarkRead({
    hasUnread: adminUnreadCount > 0,
    onRead: markRead.mutate,
    conversationId,
  })
  // Timer fallback (belt+suspenders with viewport hook)
  const markReadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markReadRef = useRef(markRead.mutate)
  useEffect(() => { markReadRef.current = markRead.mutate })
  const deleteMsg = useDeleteMessage()
  const reactionMut = useReaction()
  const updateStatus = useUpdateUserStatus()
  const assignConv = useAssignConversation()
  const { data: adminListData } = useAdminList()
  const { data: annData } = useAnnouncements(true, 8)
  const announcements = annData?.announcements ?? []

  const [typingUsers, setTypingUsers] = useState<Map<string, string>>(new Map())
  const typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())
  const setReplyTo = useChatStore(s => s.setReplyTo)

  const [statusDialog, setStatusDialog] = useState(false)
  const [newStatus, setNewStatus] = useState<Status>('PENDING')
  const [statusReason, setStatusReason] = useState('')

  // Mobile keyboard: update --chat-h so the input is never hidden by the virtual keyboard.
  // Also toggle keyboard-open on <html> so AdminLayout can zero out its bottom padding,
  // matching the behaviour in ChatPage and DMPage.
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const update = () => {
      const h = vv.height
      document.documentElement.style.setProperty('--chat-h', `${h}px`)
      document.documentElement.classList.toggle('keyboard-open', window.innerHeight - h > 100)
    }
    update()
    vv.addEventListener('resize', update)
    vv.addEventListener('scroll', update)
    return () => {
      vv.removeEventListener('resize', update)
      vv.removeEventListener('scroll', update)
      document.documentElement.classList.remove('keyboard-open')
    }
  }, [])
  const [linkedAnnouncement, setLinkedAnnouncement] = useState<{ id: string; title: string; type: string } | null>(null)
  const [showAnnPicker, setShowAnnPicker] = useState(false)
  const annPickerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!showAnnPicker) return
    const handler = (e: MouseEvent) => {
      if (annPickerRef.current && !annPickerRef.current.contains(e.target as Node)) {
        setShowAnnPicker(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showAnnPicker])

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isBulkDeleting, setIsBulkDeleting] = useState(false)

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const exitSelectMode = useCallback(() => {
    setSelectMode(false)
    setSelectedIds(new Set())
  }, [])

  const handleBulkDelete = useCallback(async (permanent?: boolean) => {
    if (selectedIds.size === 0) return
    setIsBulkDeleting(true)
    const ids = Array.from(selectedIds)
    const CHUNK = 5
    let succeeded = 0
    let failed = 0
    for (let i = 0; i < ids.length; i += CHUNK) {
      const results = await Promise.allSettled(
        ids.slice(i, i + CHUNK).map(messageId =>
          deleteMsg.mutateAsync({ messageId, conversationId, scope: 'all', permanent })
        )
      )
      results.forEach(r => r.status === 'fulfilled' ? succeeded++ : failed++)
    }
    setIsBulkDeleting(false)
    exitSelectMode()
    if (failed === 0) {
      toast.success(`Deleted ${succeeded} message${succeeded !== 1 ? 's' : ''}`)
    } else if (succeeded > 0) {
      toast.warning(`Deleted ${succeeded} of ${ids.length} messages — ${failed} failed`)
    } else {
      toast.error('Failed to delete messages')
    }
  }, [selectedIds, deleteMsg, conversationId, exitSelectMode])

  const typingContent = useMemo(
    () => Array.from(typingUsers.entries()).map(([uid, name]) => <TypingIndicator key={uid} userName={name} />),
    [typingUsers]
  )

  const allMessages = useMemo(
    () => msgData?.pages.flatMap((p) => p.messages) ?? [],
    [msgData]
  )

  useEffect(() => {
    if (conversationId && allMessages.length > 0 && adminUnreadCount > 0) {
      if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current)
      markReadTimerRef.current = setTimeout(() => markReadRef.current(), 300)
    }
    return () => { if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current) }
  }, [conversationId, allMessages.length, adminUnreadCount])

  useEffect(() => {
    const socket = getSocket()
    if (!socket || !conversationId) return

    // 8s: matches ChatPage's typing timeout — 2× the 3s heartbeat so the indicator
    // never flickers off between re-emits on a slow connection.
    const TYPING_TIMEOUT_MS = 8000

    const clearTypingTimer = (userId: string) => {
      const t = typingTimersRef.current.get(userId)
      if (t) { clearTimeout(t); typingTimersRef.current.delete(userId) }
    }

    const handleTypingStart = (data: { userId: string; userName: string; conversationId: string }) => {
      if (data.conversationId !== conversationId || data.userId === user?.id) return
      setTypingUsers((prev) => new Map(prev).set(data.userId, data.userName))
      clearTypingTimer(data.userId)
      typingTimersRef.current.set(data.userId, setTimeout(() => {
        setTypingUsers((prev) => { const n = new Map(prev); n.delete(data.userId); return n })
        typingTimersRef.current.delete(data.userId)
      }, TYPING_TIMEOUT_MS))
    }

    const handleTypingStop = (data: { userId: string; conversationId: string }) => {
      if (data.conversationId !== conversationId) return
      clearTypingTimer(data.userId)
      setTypingUsers((prev) => { const n = new Map(prev); n.delete(data.userId); return n })
    }

    const handleNewMessage = (data: { message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      queryClient.setQueryData<MessagesCache>(
        ['messages', conversationId],
        old => prependMessage(old, data.message),
      )
    }

    const handleMessageSent = (data: { tempId: string; message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      queryClient.setQueryData<MessagesCache>(['messages', conversationId], old => {
        const { cache } = replaceTempMessage(old, data.tempId, data.message)
        return cache
      })
    }

    const handleMessageDeleted = (data: { messageId: string; conversationId: string; deletedAt: number }) => {
      if (data.conversationId !== conversationId) return
      queryClient.setQueryData<MessagesCache>(
        ['messages', conversationId],
        old => softDeleteMessage(old, data.messageId, data.deletedAt),
      )
    }

    const handleMessagesRead = (data: { conversationId: string; readBy: string; readAt: number }) => {
      if (data.conversationId !== conversationId) return
      queryClient.setQueryData<MessagesCache>(
        ['messages', conversationId],
        old => markMessagesRead(old, data.readAt),
      )
    }

    const handleReaction = (data: { messageId: string; reaction: MessageReaction | { userId: string; emoji: string }; action: 'add' | 'remove' }) => {
      queryClient.setQueryData<MessagesCache>(
        ['messages', conversationId],
        old => applyReaction(old, data.messageId, data.reaction, data.action),
      )
    }

    socket.on('typing:start', handleTypingStart)
    socket.on('typing:stop', handleTypingStop)
    socket.on('message:new', handleNewMessage)
    socket.on('message:sent', handleMessageSent)
    socket.on('message:deleted', handleMessageDeleted)
    socket.on('message:reaction', handleReaction)
    socket.on('messages:read', handleMessagesRead)

    // Tell the server we are actively viewing this conversation so push notifications
    // are suppressed while the admin has the chat open — mirrors ChatPage behaviour.
    socket.emit('conversation:focus', { conversationId })
    // Also register in the per-tab module variable so the global useSocket hook
    // can detect "admin is actively watching this exact conversation in THIS tab"
    // without reading localStorage (which is shared across tabs and causes false-pop).
    setActiveFocusedConversation(conversationId)

    const handleVisibilityChange = () => {
      if (!document.hidden) {
        socket.emit('conversation:focus', { conversationId })
        setActiveFocusedConversation(conversationId)
      } else {
        socket.emit('conversation:blur')
        setActiveFocusedConversation(null)
      }
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)

    return () => {
      socket.off('typing:start', handleTypingStart)
      socket.off('typing:stop', handleTypingStop)
      socket.off('message:new', handleNewMessage)
      socket.off('message:sent', handleMessageSent)
      socket.off('message:deleted', handleMessageDeleted)
      socket.off('message:reaction', handleReaction)
      socket.off('messages:read', handleMessagesRead)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      socket.emit('conversation:blur')
      setActiveFocusedConversation(null)
      typingTimersRef.current.forEach(t => clearTimeout(t))
      typingTimersRef.current.clear()
    }
  }, [conversationId, user?.id, queryClient])

  return (
    <div className="chat-viewport-height flex flex-col overflow-hidden bg-accent/20 dark:bg-background relative">
      <div className="flex items-center gap-3 border-b px-4 py-2.5 bg-sidebar shrink-0 z-10 shadow-sm pt-[max(0.625rem,env(safe-area-inset-top))]">
        <Button variant="ghost" size="icon" className="sm:hidden h-8 w-8 shrink-0" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="icon" className="hidden sm:flex h-8 w-8 shrink-0" onClick={onToggleSidebar}>
              {sidebarCollapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{sidebarCollapsed ? 'Show sidebar' : 'Hide sidebar'}</TooltipContent>
        </Tooltip>

        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary relative font-bold text-xs">
          {getInitials(conversation.user?.name ?? 'User')}
          <span className={cn('absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-background', isUserOnline ? 'bg-green-500' : 'bg-muted-foreground')} />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-semibold truncate">{conversation.user?.name}</p>
            {subsidiaries.length > 0 ? (
              <DropdownMenu>
                <DropdownMenuTrigger className="focus:outline-none">
                  <Badge variant="secondary" className="px-2 py-0.5 text-xs font-semibold bg-primary/15 text-primary hover:bg-primary/25 transition-colors border-0 cursor-pointer flex items-center gap-1.5 focus:ring-0">
                    <Building2 className="h-3 w-3" />
                    {subsidiaryName || 'General Inquiry'}
                    {subsidiaryIndustry ? ` · ${subsidiaryIndustry}` : ''}
                    <ChevronDown className="h-3 w-3 opacity-50 ml-0.5" />
                  </Badge>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-56">
                  <DropdownMenuLabel>Change Category</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem 
                    className={!conversation.subsidiaryId ? 'bg-primary/10 font-medium' : ''}
                    onClick={() => {
                      if (conversation.subsidiaryId !== null) {
                        convApi.updateSubsidiary(conversationId, null).catch(() => toast.error('Failed to update subsidiary'))
                      }
                    }}
                  >
                    General Inquiry
                  </DropdownMenuItem>
                  {subsidiaries.map(sub => (
                    <DropdownMenuItem 
                      key={sub.id}
                      className={conversation.subsidiaryId === sub.id ? 'bg-primary/10 font-medium' : ''}
                      onClick={() => {
                        if (conversation.subsidiaryId !== sub.id) {
                          convApi.updateSubsidiary(conversationId, sub.id).catch(() => toast.error('Failed to update subsidiary'))
                        }
                      }}
                    >
                      {sub.name}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            ) : subsidiaryName ? (
              <Badge variant="secondary" className="px-2 py-0.5 text-xs font-semibold bg-primary/15 text-primary border-0 flex items-center gap-1.5">
                <Building2 className="h-3 w-3" />
                {subsidiaryName}
                {subsidiaryIndustry ? ` · ${subsidiaryIndustry}` : ''}
              </Badge>
            ) : null}
          </div>
          <p className="text-[11px] text-muted-foreground truncate">
            {typingUsers.size > 0 ? 'typing…' : isUserOnline ? 'Online' : conversation.user?.email}
          </p>
        </div>

        {conversation.assignedAdmin && (
          <Badge variant="outline" className="text-[10px] gap-1 shrink-0 hidden md:flex">
            <UserCheck className="h-3 w-3" />
            {conversation.assignedAdmin.name.split(' ')[0]}
          </Badge>
        )}

{conversation.user?.status && (
                <Badge variant="outline" className={cn('text-[10px] shrink-0 hidden md:flex', conversation.user.status === 'APPROVED' ? 'border-green-200 text-green-700' : 'border-red-200 text-red-700')}>
                  {conversation.user.status}
                </Badge>
              )}

              {conversation.registrationReport && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-[10px] shrink-0 hidden sm:flex gap-1 border-amber-200 text-amber-700 hover:bg-amber-50 hover:text-amber-800 max-w-[140px]"
                      onClick={() => window.open(`/admin/reports?highlight=${conversation.registrationReportId}`, '_blank')}
                    >
                      <FileWarning className="h-3 w-3 shrink-0" />
                      <span className="truncate">Report: {conversation.registrationReport.subject.slice(0, 15)}{conversation.registrationReport.subject.length > 15 ? '…' : ''}</span>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="text-xs font-semibold">Registration Report</p>
                    <p className="text-[10px] text-muted-foreground">{conversation.registrationReport.description.slice(0, 100)}{conversation.registrationReport.description.length > 100 ? '…' : ''}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">Status: {conversation.registrationReport.status}</p>
                  </TooltipContent>
                </Tooltip>
              )}

              {announcements.length > 0 && (
          <div className="relative" ref={annPickerRef}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant={linkedAnnouncement ? 'default' : 'ghost'} size="icon" className="h-8 w-8 shrink-0 border" onClick={() => setShowAnnPicker(!showAnnPicker)}>
                  <Megaphone className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Link announcement</TooltipContent>
            </Tooltip>
            {showAnnPicker && (
              <div className="absolute right-0 top-10 z-50 w-72 rounded-xl border bg-popover shadow-lg p-2 space-y-1">
                <p className="text-[10px] font-semibold uppercase text-muted-foreground px-2 py-1">Select announcement</p>
                {announcements.slice(0, 8).map(ann => (
                  <button key={ann.id} className="w-full text-left rounded-lg px-3 py-2 text-xs hover:bg-accent cursor-pointer" onClick={() => { setLinkedAnnouncement({ id: ann.id, title: ann.title, type: ann.type }); setShowAnnPicker(false) }}>
                    <span className="font-medium">{ann.title}</span> <span className="text-muted-foreground ml-2">{ann.type}</span>
                  </button>
                ))}
                {linkedAnnouncement && (
                  <button className="w-full text-left rounded-lg px-3 py-2 text-xs text-destructive hover:bg-destructive/10 mt-1 flex items-center gap-1.5 border-t cursor-pointer" onClick={() => { setLinkedAnnouncement(null); setShowAnnPicker(false) }}>
                    <X className="h-3.5 w-3.5" /> Remove link
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* Select mode toggle */}
        <Button
          variant={selectMode ? 'secondary' : 'ghost'}
          size="icon"
          className="h-8 w-8 shrink-0"
          title={selectMode ? 'Cancel selection' : 'Select messages'}
          aria-label={selectMode ? 'Cancel selection' : 'Select messages'}
          onClick={() => selectMode ? exitSelectMode() : setSelectMode(true)}
        >
          {selectMode ? <Square className="h-4 w-4" /> : <CheckSquare className="h-4 w-4" />}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0"><MoreVertical className="h-4 w-4" /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {isSuperAdmin && (
              <>
                <DropdownMenuLabel className="text-[10px] uppercase text-muted-foreground font-normal">Assignment</DropdownMenuLabel>
                {conversation.assignedAdminId !== user?.id && (
                  <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => assignConv.mutate({ conversationId, adminId: user!.id, admin: { id: user!.id, name: user!.name, role: user!.role } })}>
                    <UserCheck className="h-4 w-4" /> Assign to me
                  </DropdownMenuItem>
                )}
                {(() => {
                  const allAdmins = [...(adminListData?.admins ?? [])].filter(a => a.id !== user?.id && a.id !== conversation.assignedAdminId)
                  return allAdmins.length > 0 ? (
                    <DropdownMenuSub>
                      <DropdownMenuSubTrigger className="gap-2"><Users className="h-4 w-4" /> Assign to admin</DropdownMenuSubTrigger>
                      <DropdownMenuSubContent className="w-56 max-h-60 overflow-y-auto">
                        {allAdmins
                          .map(a => ({ ...a, workload: workloadMap.get(a.id) }))
                          .sort((a, b) => (a.workload?.activeCount ?? 99) - (b.workload?.activeCount ?? 99))
                          .map(a => (
                          <DropdownMenuItem key={a.id} className="gap-2" onClick={() => assignConv.mutate({ conversationId, adminId: a.id, admin: { id: a.id, name: a.name, role: a.role } })}>
                            <div className={cn('h-1.5 w-1.5 rounded-full shrink-0', a.workload?.isOnline ? 'bg-green-500' : 'bg-muted-foreground/40')} />
                            <span className="flex-1 truncate">{a.name}</span>
                            {a.workload && (
                              <span className="text-[10px] text-muted-foreground shrink-0">{a.workload.activeCount} active</span>
                            )}
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuSubContent>
                    </DropdownMenuSub>
                  ) : null
                })()}
                {conversation.assignedAdminId && (
                  <DropdownMenuItem className="gap-2 text-muted-foreground" onClick={() => assignConv.mutate({ conversationId, adminId: null, admin: null })}>
                    <UserMinus className="h-4 w-4" /> Unassign
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuLabel className="text-[10px] uppercase text-muted-foreground font-normal">User Action</DropdownMenuLabel>
            {conversation.user?.status === 'APPROVED' ? (
              <DropdownMenuItem className="gap-2 text-red-600" onClick={() => { setNewStatus('SUSPENDED'); setStatusReason(''); setStatusDialog(true); }}>
                <ShieldOff className="h-4 w-4" /> Suspend User
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem className="gap-2 text-green-600" onClick={() => { setNewStatus('APPROVED'); setStatusReason(''); setStatusDialog(true); }}>
                <CheckCircle className="h-4 w-4" /> Reactivate User
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="flex-1 min-h-0 relative flex flex-col">
        <MessageList<Message>
          messages={allMessages}
          isLoading={isLoading}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={hasNextPage}
          fetchNextPage={fetchNextPage}
          getTimestamp={(msg) => msg.createdAt}
          lastMessageRef={lastMsgRef}
          scrollDependencies={[conversationId]}
          emptyState={
            <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
              <Inbox className="h-8 w-8" />
              <p className="text-sm">No messages yet</p>
            </div>
          }
          bottomContent={typingContent}
          renderMessage={(msg, idx, groupMessages) => {
            const prevMsg = idx > 0 ? groupMessages[idx - 1] : null
            const nextMsg = idx < groupMessages.length - 1 ? groupMessages[idx + 1] : null
            const hideAvatar = !!prevMsg && prevMsg.senderId === msg.senderId && (new Date(msg.createdAt).getTime() - new Date(prevMsg.createdAt).getTime() < 300000)
            const isNextSame = !!nextMsg && nextMsg.senderId === msg.senderId && (new Date(nextMsg.createdAt).getTime() - new Date(msg.createdAt).getTime() < 300000)

            return (
            <div key={msg.id}>
              <MessageBubble
                message={msg}
                hideAvatar={hideAvatar}
                isNextSame={isNextSame}
                isSelectMode={selectMode}
                isSelected={selectedIds.has(msg.id)}
                onSelect={toggleSelect}
                onReply={selectMode ? undefined : (m) => setReplyTo({ id: m.id, content: m.content, type: m.type, sender: { name: m.sender?.name ?? '' } })}
                onReact={selectMode ? undefined : (emoji) => {
                  const hasReacted = msg.reactions?.some(r => r.userId === user?.id && r.emoji === emoji)
                  reactionMut.mutate({ messageId: msg.id, emoji, action: hasReacted ? 'remove' : 'add' })
                }}
                onDelete={selectMode ? undefined : (scope) => deleteMsg.mutate({ messageId: msg.id, conversationId: msg.conversationId, scope })}
                onRetry={msg.status === 'FAILED' ? () => {
                  queryClient.setQueryData<{ pages: Array<{ messages: Message[]; hasMore: boolean; success: boolean }> }>(
                    ['messages', conversationId],
                    (old) => old ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter(m => m.id !== msg.id) })) } : old
                  )
                  sendMessage.mutate({ type: msg.type, content: msg.content ?? undefined, mediaId: msg.media?.id, replyToId: msg.replyToId ?? undefined })
                } : undefined}
              />
            </div>
          )}}
        />
      </div>

      {selectMode ? (
        <BulkDeleteBar
          count={selectedIds.size}
          onDelete={handleBulkDelete}
          onCancel={exitSelectMode}
          isDeleting={isBulkDeleting}
          isSuperAdmin={isSuperAdmin}
        />
      ) : conversation.archivedAt ? (
        <div className="border-t p-3 flex items-center justify-between gap-3 bg-muted/30 shrink-0">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium">
            <Archive className="h-3.5 w-3.5 shrink-0" />
            This conversation is archived
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1.5 shrink-0"
            onClick={onUnarchive}
          >
            <ArchiveRestore className="h-3.5 w-3.5" />
            Unarchive
          </Button>
        </div>
      ) : (
        <MessageInput
          conversationId={conversationId}
          onSend={(data) => {
            sendMessage.mutate(data)
            setLinkedAnnouncement(null)
          }}
          onTyping={(isTyping) => {
            const socket = getSocket()
            if (socket?.connected) socket.emit(isTyping ? 'typing:start' : 'typing:stop', { conversationId })
          }}
          linkedAnnouncement={linkedAnnouncement}
          onClearAnnouncement={() => setLinkedAnnouncement(null)}
        />
      )}

      <Dialog open={statusDialog} onOpenChange={setStatusDialog}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><UserCog className="h-5 w-5 text-primary" />Update Account Status</DialogTitle>
            <DialogDescription>Change the account status for {conversation.user?.name}.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Reason {(newStatus === 'REJECTED' || newStatus === 'SUSPENDED') ? (
                  <span className="font-semibold text-destructive normal-case">(required)</span>
                ) : (
                  <span className="font-normal normal-case text-muted-foreground">(optional)</span>
                )}
              </Label>
              <Textarea
                value={statusReason}
                onChange={(e) => setStatusReason(e.target.value)}
                placeholder="Provide a reason..."
                rows={3}
                className={cn(
                  "rounded-xl resize-none",
                  (newStatus === 'REJECTED' || newStatus === 'SUSPENDED') && !statusReason.trim()
                    ? "border-destructive focus-visible:ring-destructive"
                    : ""
                )}
              />
              {(newStatus === 'REJECTED' || newStatus === 'SUSPENDED') && !statusReason.trim() && (
                <p className="text-[11px] text-destructive">A reason is required for this status change.</p>
              )}
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setStatusDialog(false)} className="rounded-xl">Cancel</Button>
            <Button 
              onClick={() => {
                if (conversation.user) {
                  updateStatus.mutate(
                    { userId: conversation.user.id, status: newStatus, reason: statusReason.trim() || undefined },
                    { onSuccess: () => setStatusDialog(false) }
                  )
                }
              }} 
              disabled={
                updateStatus.isPending ||
                ((newStatus === 'REJECTED' || newStatus === 'SUSPENDED') && !statusReason.trim())
              } 
              className="rounded-xl gap-2"
            >
              {updateStatus.isPending && <LeafLogo className="h-4 w-4 animate-spin mr-2" />}Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export function ConversationsPage() {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const { data: configData } = useAppConfig()
  const archiveConv = useArchiveConversationHook()
  const unarchiveConv = useUnarchiveConversation()
  const assignConv = useAssignConversation()
  const { data: queueData } = useQueue()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()

  const [selectedId, setSelectedIdState] = useState<string | null>(() => localStorage.getItem(SELECTED_CONV_KEY))
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState<'mine' | 'all' | 'archived'>(() => isSuperAdmin ? 'all' : 'mine')
  const [filterUnassigned, setFilterUnassigned] = useState(false)
  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useAdminConversations(activeTab === 'archived')
  const [newlyAssignedIds, setNewlyAssignedIds] = useState<Set<string>>(new Set())
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('admin-sidebar-collapsed') === 'true')
  const [onlineUserIds, setOnlineUserIds] = useState<Set<string>>(new Set())

  // Derived once from queueData — passed to AdminChatView so it doesn't call useQueue again
  const workloadMap = useMemo(() => {
    const map = new Map<string, { activeCount: number; isOnline: boolean }>()
    for (const w of queueData?.adminWorkloads ?? []) {
      map.set(w.adminId, { activeCount: w.activeCount, isOnline: w.isOnline })
    }
    return map
  }, [queueData?.adminWorkloads])

  const allConversations = useMemo(() => data?.pages.flatMap((p) => p.conversations) ?? [], [data])

  // Clear stale persisted selection if the conversation no longer exists in the loaded list
  useEffect(() => {
    if (!isLoading && allConversations.length > 0 && selectedId) {
      const stillExists = allConversations.some(c => c.id === selectedId)
      if (!stillExists) {
        setSelectedIdState(null)
        localStorage.removeItem(SELECTED_CONV_KEY)
      }
    }
  }, [isLoading, allConversations, selectedId])

  useEffect(() => {
    const targetConvId = searchParams.get('conversationId')
    const targetUserId = searchParams.get('userId')

    if (targetConvId) {
      setSelectedIdState(targetConvId)
      localStorage.setItem(SELECTED_CONV_KEY, targetConvId)
      setSearchParams({}, { replace: true })
      // If this conversation isn't in the cache yet (just created), force a refetch
      const alreadyInCache = allConversations.some(c => c.id === targetConvId)
      if (!alreadyInCache) {
        queryClient.invalidateQueries({ queryKey: ['conversations', { archived: false }] })
      }
    } else if (targetUserId && allConversations.length > 0) {
      const match = allConversations.find(c => c.user?.id === targetUserId)
      if (match) {
        setSelectedIdState(match.id)
        localStorage.setItem(SELECTED_CONV_KEY, match.id)
        setSearchParams({}, { replace: true })
      }
    }
  }, [searchParams, allConversations, setSearchParams, queryClient])

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const updateAllConvCaches = (updater: (old: any) => any) => {
      // Only update the active conversations cache — archived cache is unaffected by new messages
      queryClient.setQueryData<any>(['conversations', { archived: false }], updater)
    }

    const handleConvUpdated = (upd: { conversationId: string; lastMessageAt?: number | null; lastMessage?: Message | null; unreadCount?: number; adminUnreadCount?: number; assignedAdminId?: string | null; waitingSince?: number | null }) => {
      const activeCache = queryClient.getQueryData<{ pages: Array<{ conversations: Conversation[] }> }>(['conversations', { archived: false }])
      const archivedCache = queryClient.getQueryData<{ pages: Array<{ conversations: Conversation[] }> }>(['conversations', { archived: true }])
      
      const found = !!(activeCache?.pages.some(p => p.conversations.some(c => c.id === upd.conversationId)) ||
        archivedCache?.pages.some(p => p.conversations.some(c => c.id === upd.conversationId)))

      if (!found) {
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
        return
      }

      // Only re-sort (lift to top) when a new message arrives — i.e. lastMessageAt changed.
      // Read-count zeroing, waitingSince clears, and assignment updates must NOT re-order
      // the sidebar or marking a conversation as read will jump it to the top.
      const shouldReorder = upd.lastMessageAt !== undefined

      updateAllConvCaches((old: any) => {
        if (!old) return old

        if (shouldReorder) {
          // Find and extract conversation, re-inject at top of page 0
          let target: any = null
          const pagesWithout = old.pages.map((p: any) => {
            const match = p.conversations.find((c: any) => c.id === upd.conversationId)
            if (match) target = match
            return { ...p, conversations: p.conversations.filter((c: any) => c.id !== upd.conversationId) }
          })
          if (!target) return old
          const updatedConv = {
            ...target,
            lastMessageAt: upd.lastMessageAt,
            ...(upd.lastMessage !== undefined && { lastMessage: upd.lastMessage }),
            ...(upd.unreadCount !== undefined && { unreadCount: upd.unreadCount }),
            ...(upd.adminUnreadCount !== undefined && { adminUnreadCount: upd.adminUnreadCount }),
            ...(upd.assignedAdminId !== undefined && { assignedAdminId: upd.assignedAdminId }),
            ...(upd.waitingSince !== undefined && { waitingSince: upd.waitingSince }),
          }
          return {
            ...old,
            pages: pagesWithout.map((p: any, idx: number) =>
              idx === 0 ? { ...p, conversations: [updatedConv, ...p.conversations] } : p
            )
          }
        }

        // In-place update only — no re-ordering
        return {
          ...old,
          pages: old.pages.map((p: any) => ({
            ...p,
            conversations: p.conversations.map((c: any) => {
              if (c.id !== upd.conversationId) return c
              return {
                ...c,
                ...(upd.lastMessage !== undefined && { lastMessage: upd.lastMessage }),
                ...(upd.unreadCount !== undefined && { unreadCount: upd.unreadCount }),
                ...(upd.adminUnreadCount !== undefined && { adminUnreadCount: upd.adminUnreadCount }),
                ...(upd.assignedAdminId !== undefined && { assignedAdminId: upd.assignedAdminId }),
                ...(upd.waitingSince !== undefined && { waitingSince: upd.waitingSince }),
              }
            })
          }))
        }
      })
    }

    const handleConvRemoved = (data: { conversationId: string; userName: string }) => {
      if (!isSuperAdmin) {
        updateAllConvCaches((old: any) => !old ? old : ({
          ...old,
          pages: old.pages.map((p: any) => ({
            ...p,
            conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
          }))
        }))
        setSelectedIdState(prev => {
          if (prev === data.conversationId) {
            localStorage.removeItem(SELECTED_CONV_KEY)
            return null
          }
          return prev
        })
        // Toast is fired by the global useSocket hook — this handler only updates the cache
        queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      }
    }

    const handleAssignedToYou = async (data: { conversationId: string; userName: string }) => {
      // Toast is fired by the global useSocket hook — this handler only updates the cache
      setNewlyAssignedIds(prev => new Set([...prev, data.conversationId]))
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      try {
        const res = await convApi.getOne(data.conversationId)
        queryClient.setQueryData<{ pages: Array<{ conversations: Conversation[]; hasMore: boolean }>; pageParams: unknown[] }>(
          ['conversations', { archived: false }],
          (old) => {
            if (!old) return old
            const alreadyIn = old.pages.some(p => p.conversations.some(c => c.id === data.conversationId))
            if (alreadyIn) return old
            return {
              ...old,
              pages: [{ ...old.pages[0], conversations: [res.conversation, ...(old.pages[0]?.conversations ?? [])] }, ...old.pages.slice(1)],
            }
          }
        )
      } catch {
        queryClient.invalidateQueries({ queryKey: ['conversations', { archived: false }] })
      }
    }

    const handleConvAssigned = (data: { conversationId: string; assignedAdminId: string | null; assignedAdminName?: string; assignedAdminRole?: string }) => {
      // FIX #9: For regular ADMIN, if this conversation was reassigned AWAY from them, remove it from their list
      if (!isSuperAdmin && data.assignedAdminId !== user?.id) {
        updateAllConvCaches((old: any) => !old ? old : ({
          ...old,
          pages: old.pages.map((p: any) => ({
            ...p,
            conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
          }))
        }))
        queryClient.invalidateQueries({ queryKey: ['admin', 'queue'] })
        return
      }
      updateAllConvCaches((old: any) => !old ? old : ({
        ...old,
        pages: old.pages.map((p: any) => ({
          ...p,
          conversations: p.conversations.map((c: any) => {
            if (c.id !== data.conversationId) return c
            const newAdmin = data.assignedAdminId ? {
              id: data.assignedAdminId,
              name: data.assignedAdminName || 'Unknown',
              role: data.assignedAdminRole || 'ADMIN'
            } : null
            return {
              ...c,
              assignedAdminId: data.assignedAdminId,
              assignedAdmin: newAdmin,
            }
          })
        }))
      }))
      // Keep queue panel in sync — workloads change on every assignment
      queryClient.invalidateQueries({ queryKey: ['admin', 'queue'] })
    }

    // FIX #9: Handle conversation:unassigned — remove from ADMIN's list when unassigned from anyone
    const handleConvUnassigned = (data: { conversationId: string; oldAdminId: string; reason: string }) => {
      if (!isSuperAdmin) {
        // Only remove if this admin was the one being unassigned
        if (data.oldAdminId !== user?.id) return
        updateAllConvCaches((old: any) => !old ? old : ({
          ...old,
          pages: old.pages.map((p: any) => ({
            ...p,
            conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
          }))
        }))
      } else {
        // SUPER_ADMIN: update the conversation to show it as unassigned
        updateAllConvCaches((old: any) => !old ? old : ({
          ...old,
          pages: old.pages.map((p: any) => ({
            ...p,
            conversations: p.conversations.map((c: any) =>
              c.id === data.conversationId ? { ...c, assignedAdminId: null, assignedAdmin: null } : c
            )
          }))
        }))
      }
      queryClient.invalidateQueries({ queryKey: ['admin', 'queue'] })
    }

    const handleConvArchived = (data: { conversationId: string; archivedBy: string }) => {
      // Remove from non-archived cache
      queryClient.setQueryData<any>(['conversations', { archived: false }], (old: any) => !old ? old : ({
        ...old,
        pages: old.pages.map((p: any) => ({
          ...p,
          conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
        }))
      }))
      // Refetch archived list so the newly archived conversation appears
      queryClient.invalidateQueries({ queryKey: ['conversations', { archived: true }] })
    }

    const handleConvUnarchived = (data: { conversationId: string; unarchivedBy?: string }) => {
      // Remove from archived cache
      queryClient.setQueryData<any>(['conversations', { archived: true }], (old: any) => !old ? old : ({
        ...old,
        pages: old.pages.map((p: any) => ({
          ...p,
          conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
        }))
      }))
      // Refetch non-archived list
      queryClient.invalidateQueries({ queryKey: ['conversations', { archived: false }] })
    }

    const handleConvNew = (data: { conversation: Conversation }) => {
      // SUPER_ADMIN sees all new conversations; ADMIN only if assigned to them
      if (!isSuperAdmin && data.conversation.assignedAdminId !== user?.id) return
      queryClient.setQueryData<any>(['conversations', { archived: false }], (old: any) => {
        if (!old) return old
        const alreadyIn = old.pages.some((p: any) => p.conversations.some((c: any) => c.id === data.conversation.id))
        if (alreadyIn) return old
        return {
          ...old,
          pages: [{ ...old.pages[0], conversations: [data.conversation, ...(old.pages[0]?.conversations ?? [])] }, ...old.pages.slice(1)],
        }
      })
      // New conversation means unassigned count changed — refresh queue
      queryClient.invalidateQueries({ queryKey: ['admin', 'queue'] })
    }

    const handleUserOnline = (data: { userId: string }) => {
      setOnlineUserIds(prev => { const next = new Set(prev); next.add(data.userId); return next })
    }
    const handleUserOffline = (data: { userId: string }) => {
      setOnlineUserIds(prev => { const next = new Set(prev); next.delete(data.userId); return next })
    }

    socket.on('conversation:new', handleConvNew)
    socket.on('conversation:updated', handleConvUpdated)
    socket.on('conversation:removed', handleConvRemoved)
    socket.on('conversation:assigned_to_you', handleAssignedToYou)
    socket.on('conversation:assigned', handleConvAssigned)
    socket.on('conversation:unassigned', handleConvUnassigned)
    socket.on('conversation:archived', handleConvArchived)
    socket.on('conversation:unarchived', handleConvUnarchived)
    socket.on('conversation:reopened', handleConvUnarchived)
    socket.on('user:online', handleUserOnline)
    socket.on('user:offline', handleUserOffline)

    return () => {
      socket.off('conversation:new', handleConvNew)
      socket.off('conversation:updated', handleConvUpdated)
      socket.off('conversation:removed', handleConvRemoved)
          socket.off('conversation:assigned_to_you', handleAssignedToYou)
      socket.off('conversation:assigned', handleConvAssigned)
      socket.off('conversation:unassigned', handleConvUnassigned)
      socket.off('conversation:archived', handleConvArchived)
      socket.off('conversation:unarchived', handleConvUnarchived)
      socket.off('conversation:reopened', handleConvUnarchived)
      socket.off('user:online', handleUserOnline)
      socket.off('user:offline', handleUserOffline)
    }
  }, [queryClient, isSuperAdmin, user?.id])


  const effectiveSelectedId = useMemo(() => {
    if (selectedId === '__none__') return null
    if (selectedId && allConversations.some(c => c.id === selectedId)) return selectedId
    // Do NOT auto-open any conversation — admin must explicitly select one.
    // Auto-opening the first conversation silently fires markRead on conversations
    // the admin never actually viewed.
    return null
  }, [allConversations, selectedId])

  const selectedConv = useMemo(() => allConversations.find(c => c.id === effectiveSelectedId), [allConversations, effectiveSelectedId])

  const tabFiltered = useMemo(() => {
    if (activeTab === 'archived') return allConversations.filter(c => c.archivedAt)
    // Regular admins: backend already scopes to their assigned conversations.
    // Support 'mine' (non-archived) only — 'all' tab is super-admin-only.
    if (!isSuperAdmin) return allConversations.filter(c => !c.archivedAt)
    if (activeTab === 'mine') return allConversations.filter(c => c.assignedAdminId === user?.id && !c.archivedAt)
    const base = allConversations.filter(c => !c.archivedAt)
    if (filterUnassigned) return base.filter(c => !c.assignedAdminId)
    return base
  }, [allConversations, isSuperAdmin, activeTab, user?.id, filterUnassigned])

  const filtered = useMemo(() =>
    search
      ? tabFiltered.filter(c => {
        const q = search.toLowerCase()
        return c.user?.name?.toLowerCase().includes(q) || c.user?.email?.toLowerCase().includes(q)
      })
      : tabFiltered
    , [search, tabFiltered])

  const handleScroll = useCallback((e: UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 100 && hasNextPage && !isFetchingNextPage) fetchNextPage()
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])

  const selectConv = (id: string | null) => {
    if (id) {
      // Warn regular admins when they click a conversation they're not assigned to
      if (!isSuperAdmin) {
        const conv = allConversations.find(c => c.id === id)
        if (conv && conv.assignedAdminId !== user?.id) {
          toast.warning(
            conv.assignedAdminId
              ? 'You are not assigned to this conversation. Ask a Super Admin to assign it to you before assisting the user.'
              : 'This conversation is unassigned. Ask a Super Admin to assign it to you before assisting the user.',
            { duration: 5000 }
          )
          // Block normal admin from viewing unassigned conversations
          id = null
        }
      }

      if (id) {
        setSelectedIdState(id)
        localStorage.setItem(SELECTED_CONV_KEY, id)
        // Optimistically zero the unread badge immediately — before the 300ms markRead
        // debounce fires — so the badge never flashes when clicking into a conversation.
        queryClient.setQueriesData<{ pages: Array<{ conversations: import('@/lib/schemas').Conversation[]; hasMore: boolean }> }>(
          { queryKey: ['conversations'] },
          (old) => {
            if (!old?.pages) return old
            return {
              ...old,
              pages: old.pages.map((p) => ({
                ...p,
                conversations: (p.conversations || []).map((c) =>
                  c.id === id ? { ...c, adminUnreadCount: 0 } : c
                ),
              })),
            }
          }
        )
        setNewlyAssignedIds(prev => {
          const next = new Set(prev)
          // Tell TS definitively that id is a string here
          next.delete(id as string)
          return next
        })
      } else {
        setSelectedIdState('__none__')
        localStorage.removeItem(SELECTED_CONV_KEY)
      }
    } else {
      setSelectedIdState('__none__')
      localStorage.removeItem(SELECTED_CONV_KEY)
    }
  }

  const toggleSidebar = () => setSidebarCollapsed(v => {
    const next = !v;
    localStorage.setItem('admin-sidebar-collapsed', String(next));
    return next;
  })

  return (
    <div className="flex h-full overflow-hidden">
      {/* Sidebar */}
      <div className={cn(
        'flex flex-col border-r bg-background shrink-0 transition-all duration-300 ease-in-out',
        effectiveSelectedId && !sidebarCollapsed ? 'hidden sm:flex sm:w-[280px] md:w-[320px]' : '',
        effectiveSelectedId && sidebarCollapsed ? 'hidden sm:flex sm:w-0 sm:overflow-hidden sm:border-r-0' : '',
        !effectiveSelectedId ? 'w-full sm:w-[280px] md:w-[320px]' : '',
      )}>
        <div className="p-3 bg-background z-10 space-y-3 pb-2">
          <div className="flex items-center justify-between px-2 pt-1">
            <h2 className="text-xl font-bold tracking-tight">Chats</h2>
            <div className="flex items-center gap-2">
              {isSuperAdmin && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-8 w-8 p-0 rounded-lg"
                  onClick={() => navigate('/admin/users')}
                  title="Start new chat from Users page"
                >
                  <Plus className="h-4 w-4" />
                </Button>
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge variant="secondary" className="text-[10px] tabular-nums cursor-default">{filtered.length}</Badge>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">
                    {activeTab === 'archived' ? `${filtered.length} archived` : activeTab === 'mine' ? `${filtered.length} assigned to you` : `${filtered.length} total`}
                    {filterUnassigned ? ' (unassigned filter active)' : ''}
                  </p>
                </TooltipContent>
              </Tooltip>
            </div>
          </div>
          {/* Tab switcher — super admins get Mine/All/Archived; regular admins get Mine/Archived */}
          <div className="flex gap-1 p-1 bg-muted/50 rounded-lg">
            <button onClick={() => { setActiveTab('mine'); setFilterUnassigned(false) }} className={cn('flex-1 text-xs font-medium py-1.5 rounded-md transition-all', activeTab === 'mine' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground')}>My Chats</button>
            {isSuperAdmin && (
              <button onClick={() => { setActiveTab('all'); setFilterUnassigned(false) }} className={cn('flex-1 text-xs font-medium py-1.5 rounded-md transition-all', activeTab === 'all' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground')}>All Chats</button>
            )}
            <button onClick={() => { setActiveTab('archived'); setFilterUnassigned(false) }} className={cn('flex-1 text-xs font-medium py-1.5 rounded-md transition-all', activeTab === 'archived' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground')}>Archived</button>
          </div>
          <div className="relative px-2">
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search conversations…" value={search} onChange={e => setSearch(e.target.value)} className="pl-9 h-9 rounded-xl border-none bg-accent focus-visible:ring-0 shadow-none transition-colors" />
          </div>

          {/* Queue summary bar — only show when there's something actionable for this admin */}
          {queueData && (isSuperAdmin ? (queueData.unassignedCount > 0 || queueData.waiting.length > 0) : queueData.waiting.length > 0) && (
            <div className={cn(
              'mx-2 flex items-center gap-2 rounded-lg border px-3 py-1.5 transition-colors',
              filterUnassigned
                ? 'bg-orange-100 dark:bg-orange-900/50 border-orange-400 dark:border-orange-600'
                : 'bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-800'
            )}>
              {queueData.unassignedCount > 0 && isSuperAdmin && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      className="flex items-center gap-1 text-orange-700 dark:text-orange-400 hover:text-orange-900 dark:hover:text-orange-200 transition-colors"
                      onClick={() => {
                        setActiveTab('all')
                        setFilterUnassigned(v => !v)
                      }}
                    >
                      <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                      <span className="text-[11px] font-semibold underline-offset-2 hover:underline">
                        {queueData.unassignedCount} unassigned
                      </span>
                    </button>
                  </TooltipTrigger>
                  <TooltipContent><p className="text-xs">{filterUnassigned ? 'Click to show all' : 'Click to filter unassigned conversations'}</p></TooltipContent>
                </Tooltip>
              )}
              {queueData.unassignedCount > 0 && isSuperAdmin && queueData.waiting.length > 0 && (
                <span className="text-orange-300 dark:text-orange-700 text-xs">·</span>
              )}
              {queueData.waiting.length > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex items-center gap-1 text-orange-700 dark:text-orange-400">
                      <Clock className="h-3.5 w-3.5 shrink-0" />
                      <span className="text-[11px] font-semibold">
                        {queueData.waiting.length} waiting
                        {queueData.waiting[0]?.waitMs ? ` · longest ${formatWaitDuration(queueData.waiting[0].waitMs)}` : ''}
                      </span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent><p className="text-xs">Users waiting for a reply — sorted by longest wait first</p></TooltipContent>
                </Tooltip>
              )}
              {filterUnassigned && (
                <button
                  className="ml-auto text-orange-700 dark:text-orange-400 hover:text-orange-900 transition-colors"
                  onClick={() => setFilterUnassigned(false)}
                  title="Clear filter"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="p-3 space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-3 py-3"><Skeleton className="h-10 w-10 rounded-full shrink-0" /><div className="flex-1 space-y-2"><Skeleton className="h-4 w-28" /><Skeleton className="h-3 w-40" /></div></div>
            ))}
          </div>
        ) : (
          <ScrollArea className="flex-1" onScrollCapture={handleScroll}>
            <div className="px-2 pb-2 space-y-0.5">
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
                  <Inbox className="h-10 w-10 opacity-50" />
                  <p className="text-sm font-medium">
                    {search
                      ? 'No conversations match your search'
                      : activeTab === 'archived'
                        ? 'No archived conversations'
                        : !isSuperAdmin
                          ? 'No conversations assigned to you yet'
                          : 'No conversations found'}
                  </p>
                </div>
              ) : (
                filtered.map(conv => {
                  const sub = configData?.subsidiaries?.find(s => s.id === conv.subsidiaryId)
                  return (
                    <ConversationItem
                      key={conv.id}
                      conversation={conv}
                      isSelected={conv.id === effectiveSelectedId}
                      isNewlyAssigned={newlyAssignedIds.has(conv.id)}
                      subsidiaryName={sub?.name}
                      isUserOnline={conv.user ? onlineUserIds.has(conv.user.id) : false}
              onClick={() => selectConv(conv.id)}
              showArchive={isSuperAdmin || (user?.role === 'ADMIN' && conv.assignedAdminId === user?.id)}
              onArchive={(archive) => {
                if (archive) archiveConv.mutate({ conversationId: conv.id })
                else unarchiveConv.mutate(conv.id)
              }}
              onClaim={isSuperAdmin && !conv.assignedAdminId ? () => {
                assignConv.mutate({ conversationId: conv.id, adminId: user!.id, admin: user ? { id: user.id, name: user.email, role: user.role } : null })
              } : undefined}
                    />
                  )
                })
              )}
              {isFetchingNextPage && <div className="flex justify-center py-3"><LeafLogo className="h-4 w-4 animate-spin text-muted-foreground" /></div>}
            </div>
          </ScrollArea>
        )}
      </div>

      {/* Main View */}
      <div className={cn('flex-1 flex flex-col min-w-0 overflow-hidden bg-accent/20 dark:bg-background', !effectiveSelectedId && 'hidden sm:flex')}>
        {effectiveSelectedId && selectedConv ? (
          <AdminChatView
            conversation={selectedConv}
            subsidiaryName={configData?.subsidiaries?.find(s => s.id === selectedConv.subsidiaryId)?.name}
            subsidiaryIndustry={configData?.subsidiaries?.find(s => s.id === selectedConv.subsidiaryId)?.industry}
            onBack={() => selectConv(null)}
            sidebarCollapsed={sidebarCollapsed}
            onToggleSidebar={toggleSidebar}
            onUnarchive={() => unarchiveConv.mutate(selectedConv.id)}
            isUserOnline={selectedConv.user ? onlineUserIds.has(selectedConv.user.id) : false}
            workloadMap={workloadMap}
          />
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-4 text-muted-foreground p-8">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted"><Mail className="h-8 w-8 opacity-50" /></div>
            <div className="text-center space-y-1.5">
              <p className="text-sm font-semibold text-foreground">No conversation selected</p>
              <p className="text-xs text-muted-foreground max-w-[200px] leading-relaxed">Choose a conversation from the sidebar to start messaging</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
