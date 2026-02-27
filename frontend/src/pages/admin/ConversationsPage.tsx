import * as React from 'react'
import { useState, useCallback, useEffect, useRef, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search, ArrowLeft, Inbox, Mail, PanelLeftClose, PanelLeft,
  MoreVertical, ShieldOff, CheckCircle, UserCheck, Megaphone, X, Users, UserMinus,
  CheckSquare, Square,
} from 'lucide-react'
import { toast } from 'sonner'
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
import { cn, getInitials, formatRelativeTime } from '@/lib/utils'
import { useAdminConversations, useMessages, useSendMessage, useMarkRead, useDeleteMessage } from '@/hooks/useMessages'
import { useReaction } from '@/hooks/useReactions'
import { useUpdateUserStatus, useAdminList } from '@/hooks/useUsers'
import { useAnnouncements } from '@/hooks/useAnnouncements'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'
import { MessageList } from '@/components/chat/MessageList'
import { MessageInput } from '@/components/chat/MessageInput'
import { BulkDeleteBar } from '@/components/chat/BulkDeleteBar'
import { useChatStore } from '@/stores/chatStore'
import { useAuthStore } from '@/stores/authStore'
import { getSocket } from '@/lib/socket'
import { conversations as convApi } from '@/lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Conversation, Message, MessageReaction } from '@/lib/schemas'
import { LeafLogo } from '@/components/ui/LeafLogo'

const SELECTED_CONV_KEY = 'admin-selected-conversation'

function ConversationItem({
  conversation,
  isSelected,
  isNewlyAssigned,
  onClick,
}: {
  conversation: Conversation
  isSelected: boolean
  isNewlyAssigned?: boolean
  onClick: () => void
}) {
  const userName = conversation.user?.name ?? 'Unknown User'
  const lastMsg = conversation.lastMessage as Message | null | undefined
  const senderPrefix = lastMsg?.sender?.role && lastMsg.sender.role !== 'USER' ? `${lastMsg.sender.name}: ` : ''
  const preview = lastMsg?.deletedAt
    ? 'Message deleted'
    : lastMsg?.content
      ? senderPrefix + lastMsg.content.slice(0, 50) + (lastMsg.content.length > 50 ? '...' : '')
      : lastMsg?.type
        ? `${senderPrefix}Sent ${(lastMsg.type as string).toLowerCase()}`
        : 'No messages yet'

  const hasUnread = (conversation.adminUnreadCount ?? 0) > 0

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-3 px-3 py-3 text-left transition-all border-b border-border/40',
        isSelected ? 'bg-accent' : 'hover:bg-accent/50',
        isNewlyAssigned && !isSelected && 'ring-1 ring-inset ring-amber-400/50 bg-amber-50/30 dark:bg-amber-900/10',
      )}
    >
      <div className={cn(
        'flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-xs font-bold transition-colors',
        isNewlyAssigned ? 'bg-amber-500 text-white' : hasUnread ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground',
      )}>
        {getInitials(userName)}
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
            {conversation.assignedAdmin && !isNewlyAssigned && (
              <span className="text-[10px] text-muted-foreground hidden sm:inline">{conversation.assignedAdmin.name.split(' ')[0]}</span>
            )}
            {hasUnread && (
              <Badge className="h-5 min-w-5 rounded-full px-1.5 text-[10px] bg-primary text-primary-foreground">
                {conversation.adminUnreadCount}
              </Badge>
            )}
          </div>
        </div>
      </div>
    </button>
  )
}

function useAssignConversation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ conversationId, adminId }: { conversationId: string; adminId: string | null; admin?: { id: string, name: string, role: any } | null }) =>
      convApi.assign(conversationId, adminId),
    onMutate: ({ conversationId, adminId, admin }) => {
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
    },
  })
}

function AdminChatView({
  conversation,
  onBack,
  sidebarCollapsed,
  onToggleSidebar,
}: {
  conversation: Conversation
  onBack: () => void
  sidebarCollapsed: boolean
  onToggleSidebar: () => void
}) {
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const conversationId = conversation.id
  const queryClient = useQueryClient()

  const { data: msgData, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useMessages(conversationId)
  const sendMessage = useSendMessage(conversationId)
  const markRead = useMarkRead(conversationId)
  const deleteMsg = useDeleteMessage()
  const reactionMut = useReaction()
  const updateStatus = useUpdateUserStatus()
  const assignConv = useAssignConversation()
  const { data: adminListData } = useAdminList()
  const { data: annData } = useAnnouncements(true, 8)
  const announcements = annData?.announcements ?? []

  const [typingUsers, setTypingUsers] = useState<Map<string, string>>(new Map())
  const [isUserOnline, setIsUserOnline] = useState(false)
  const setReplyTo = useChatStore(s => s.setReplyTo)
  const [linkedAnnouncement, setLinkedAnnouncement] = useState<{ id: string; title: string; type: string } | null>(null)
  const [showAnnPicker, setShowAnnPicker] = useState(false)

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

  const handleBulkDelete = useCallback(async () => {
    if (selectedIds.size === 0) return
    setIsBulkDeleting(true)
    await Promise.allSettled(
      Array.from(selectedIds).map(messageId =>
        deleteMsg.mutateAsync({ messageId, conversationId, scope: 'all' })
      )
    )
    setIsBulkDeleting(false)
    exitSelectMode()
  }, [selectedIds, deleteMsg, conversationId, exitSelectMode])

  const typingContent = useMemo(
    () => Array.from(typingUsers.entries()).map(([uid, name]) => <TypingIndicator key={uid} userName={name} />),
    [typingUsers]
  )

  const markReadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markReadRef = useRef(markRead.mutate)
  useEffect(() => { markReadRef.current = markRead.mutate })

  const allMessages = useMemo(
    () => msgData?.pages.flatMap((p) => p.messages) ?? [],
    [msgData]
  )

  useEffect(() => {
    if (conversationId && allMessages.length > 0) {
      if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current)
      markReadTimerRef.current = setTimeout(() => markReadRef.current(), 300)
    }
  }, [conversationId, allMessages.length])

  useEffect(() => {
    const socket = getSocket()
    if (!socket || !conversationId) return

    const handleTypingStart = (data: { userId: string; userName: string; conversationId: string }) => {
      if (data.conversationId !== conversationId || data.userId === user?.id) return
      setTypingUsers((prev) => new Map(prev).set(data.userId, data.userName))
    }

    const handleTypingStop = (data: { userId: string; conversationId: string }) => {
      if (data.conversationId !== conversationId) return
      setTypingUsers((prev) => { const next = new Map(prev); next.delete(data.userId); return next })
    }

    const handleUserOnline = (data: { userId: string }) => { if (data.userId === conversation.user?.id) setIsUserOnline(true) }
    const handleUserOffline = (data: { userId: string }) => { if (data.userId === conversation.user?.id) setIsUserOnline(false) }

    type CacheShape = { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }
    const updateCache = (updater: (old: CacheShape) => CacheShape) =>
      queryClient.setQueryData<CacheShape>(['messages', conversationId], (old) => old ? updater(old) : old)

    const handleNewMessage = (data: { message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      updateCache((old) => {
        const first = old.pages[0]
        if (first.messages.some(m => m.id === data.message.id)) return old
        return { ...old, pages: [{ ...first, messages: [...first.messages, data.message] }, ...old.pages.slice(1)] }
      })
      markReadRef.current()
    }

    const handleMessageSent = (data: { tempId: string; message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({ ...p, messages: p.messages.map(m => m.id === data.tempId ? data.message : m) }))
      }))
    }

    const handleMessageDeleted = (data: { messageId: string; conversationId: string; deletedAt: number }) => {
      if (data.conversationId !== conversationId) return
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({ ...p, messages: p.messages.map(m => m.id === data.messageId ? { ...m, deletedAt: data.deletedAt } : m) }))
      }))
    }

    const handleReaction = (data: { messageId: string; reaction: MessageReaction | { userId: string; emoji: string }; action: 'add' | 'remove' }) => {
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({
          ...p,
          messages: p.messages.map(m => {
            if (m.id !== data.messageId) return m
            const reactions = m.reactions ?? []
            if (data.action === 'add') {
              // Create a proper MessageReaction object if it's not complete
              const reaction: MessageReaction = 'id' in data.reaction
                ? data.reaction as MessageReaction
                : {
                  id: '', // Will be updated by server
                  messageId: data.messageId,
                  userId: data.reaction.userId,
                  emoji: data.reaction.emoji
                }
              return { ...m, reactions: [...reactions.filter(r => r.userId !== reaction.userId), reaction] }
            }
            return { ...m, reactions: reactions.filter(r => !(r.userId === data.reaction.userId && r.emoji === data.reaction.emoji)) }
          })
        }))
      }))
    }

    socket.on('typing:start', handleTypingStart)
    socket.on('typing:stop', handleTypingStop)
    socket.on('user:online', handleUserOnline)
    socket.on('user:offline', handleUserOffline)
    socket.on('message:new', handleNewMessage)
    socket.on('message:sent', handleMessageSent)
    socket.on('message:deleted', handleMessageDeleted)
    socket.on('message:reaction', handleReaction)

    return () => {
      socket.off('typing:start', handleTypingStart)
      socket.off('typing:stop', handleTypingStop)
      socket.off('user:online', handleUserOnline)
      socket.off('user:offline', handleUserOffline)
      socket.off('message:new', handleNewMessage)
      socket.off('message:sent', handleMessageSent)
      socket.off('message:deleted', handleMessageDeleted)
      socket.off('message:reaction', handleReaction)
    }
  }, [conversationId, user?.id, conversation.user?.id, queryClient])

  return (
    <div className="flex h-full flex-col overflow-hidden bg-accent/20 dark:bg-background relative">
      <div className="flex items-center gap-3 border-b px-4 py-2.5 bg-sidebar shrink-0 z-10 shadow-sm">
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
          <p className="text-sm font-semibold truncate">{conversation.user?.name}</p>
          <p className="text-[11px] text-muted-foreground truncate">
            {typingUsers.size > 0 ? 'typing...' : isUserOnline ? 'Online' : conversation.user?.email}
          </p>
        </div>

        {conversation.assignedAdmin && (
          <Badge variant="outline" className="text-[10px] gap-1 shrink-0 hidden sm:flex">
            <UserCheck className="h-3 w-3" />
            {conversation.assignedAdmin.name.split(' ')[0]}
          </Badge>
        )}

        {conversation.user?.status && (
          <Badge variant="outline" className={cn('text-[10px] shrink-0 hidden sm:flex', conversation.user.status === 'APPROVED' ? 'border-green-200 text-green-700' : 'border-red-200 text-red-700')}>
            {conversation.user.status}
          </Badge>
        )}

        {announcements.length > 0 && (
          <div className="relative">
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
                  <button key={ann.id} className="w-full text-left rounded-lg px-3 py-2 text-xs hover:bg-accent" onClick={() => { setLinkedAnnouncement({ id: ann.id, title: ann.title, type: ann.type }); setShowAnnPicker(false) }}>
                    <span className="font-medium">{ann.title}</span> <span className="text-muted-foreground ml-2">{ann.type}</span>
                  </button>
                ))}
                {linkedAnnouncement && (
                  <button className="w-full text-left rounded-lg px-3 py-2 text-xs text-destructive hover:bg-destructive/10 mt-1 flex items-center gap-1.5 border-t" onClick={() => { setLinkedAnnouncement(null); setShowAnnPicker(false) }}>
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
                  <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => assignConv.mutate({ conversationId, adminId: user!.id, admin: { id: user!.id, name: user!.name, role: user!.role as any } })}>
                    <UserCheck className="h-4 w-4" /> Assign to me
                  </DropdownMenuItem>
                )}
                {(() => {
                  const allAdmins = [...(adminListData?.admins ?? []), ...(adminListData?.superAdmins ?? [])].filter(a => a.id !== user?.id && a.id !== conversation.assignedAdminId)
                  return allAdmins.length > 0 ? (
                    <DropdownMenuSub>
                      <DropdownMenuSubTrigger className="gap-2"><Users className="h-4 w-4" /> Assign to admin</DropdownMenuSubTrigger>
                      <DropdownMenuSubContent className="w-48 max-h-60 overflow-y-auto">
                        {allAdmins.map(a => (
                          <DropdownMenuItem key={a.id} className="gap-2" onClick={() => assignConv.mutate({ conversationId, adminId: a.id, admin: { id: a.id, name: a.name, role: a.role as any } })}>
                            <UserCheck className="h-4 w-4" /> {a.name}
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
              <DropdownMenuItem className="gap-2 text-red-600" onClick={() => updateStatus.mutate({ userId: conversation.user!.id, status: 'SUSPENDED' })}>
                <ShieldOff className="h-4 w-4" /> Suspend User
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem className="gap-2 text-green-600" onClick={() => updateStatus.mutate({ userId: conversation.user!.id, status: 'APPROVED' })}>
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
          scrollDependencies={[conversationId]}
          emptyState={
            <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
              <Inbox className="h-8 w-8" />
              <p className="text-sm">No messages yet</p>
            </div>
          }
          bottomContent={typingContent}
          renderMessage={(msg) => (
            <div key={msg.id}>
              <MessageBubble
                message={msg}
                isSelectMode={selectMode}
                isSelected={selectedIds.has(msg.id)}
                onSelect={toggleSelect}
                onReply={selectMode ? undefined : (m) => setReplyTo(m as any)}
                onReact={selectMode ? undefined : (emoji) => {
                  const hasReacted = msg.reactions?.some(r => r.userId === user?.id && r.emoji === emoji)
                  reactionMut.mutate({ messageId: msg.id, emoji, action: hasReacted ? 'remove' : 'add' })
                }}
                onDelete={selectMode ? undefined : (scope) => deleteMsg.mutate({ messageId: msg.id, conversationId: msg.conversationId, scope })}
              />
            </div>
          )}
        />
      </div>

      {selectMode ? (
        <BulkDeleteBar
          count={selectedIds.size}
          onDelete={handleBulkDelete}
          onCancel={exitSelectMode}
          isDeleting={isBulkDeleting}
        />
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
    </div>
  )
}

export function ConversationsPage() {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useAdminConversations()
  const [searchParams, setSearchParams] = useSearchParams()

  const [selectedId, setSelectedIdState] = useState<string | null>(() => localStorage.getItem(SELECTED_CONV_KEY))
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState<'mine' | 'all'>('all')
  const [newlyAssignedIds, setNewlyAssignedIds] = useState<Set<string>>(new Set())
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('admin-sidebar-collapsed') === 'true')

  const allConversations = useMemo(() => data?.pages.flatMap((p) => p.conversations) ?? [], [data])

  useEffect(() => {
    const targetConvId = searchParams.get('conversationId')
    const targetUserId = searchParams.get('userId')

    if (targetConvId) {
      setSelectedIdState(targetConvId)
      localStorage.setItem(SELECTED_CONV_KEY, targetConvId)
      setSearchParams({}, { replace: true })
    } else if (targetUserId && allConversations.length > 0) {
      const match = allConversations.find(c => c.user?.id === targetUserId)
      if (match) {
        setSelectedIdState(match.id)
        localStorage.setItem(SELECTED_CONV_KEY, match.id)
        setSearchParams({}, { replace: true })
      }
    }
  }, [searchParams, allConversations, setSearchParams])

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const handleConvUpdated = (upd: { conversationId: string; lastMessageAt?: number | null; lastMessage?: Message | null; unreadCount?: number; adminUnreadCount?: number; assignedAdminId?: string | null }) => {
      const cacheData = queryClient.getQueryData<{ pages: Array<{ conversations: Conversation[] }> }>(['conversations'])
      const convFound = cacheData?.pages.some(p => p.conversations.some(c => c.id === upd.conversationId))

      if (!convFound && cacheData) {
        // New conversation from a brand-new user — refetch so it appears at the top of the list
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
      }

      queryClient.setQueryData(['conversations'], (old: any) => !old ? old : {
        ...old,
        pages: old.pages.map((p: any) => ({
          ...p,
          conversations: p.conversations.map((c: any) => {
            if (c.id !== upd.conversationId) return c
            return {
              ...c,
              ...(upd.lastMessageAt !== undefined && { lastMessageAt: upd.lastMessageAt }),
              ...(upd.lastMessage !== undefined && { lastMessage: upd.lastMessage }),
              ...(upd.unreadCount !== undefined && { unreadCount: upd.unreadCount }),
              ...(upd.adminUnreadCount !== undefined && { adminUnreadCount: upd.adminUnreadCount }),
              ...(upd.assignedAdminId !== undefined && { assignedAdminId: upd.assignedAdminId }),
            }
          })
        }))
      })
    }

    const handleConvRemoved = (data: { conversationId: string; userName: string }) => {
      queryClient.setQueryData(['conversations'], (old: any) => !old ? old : {
        ...old,
        pages: old.pages.map((p: any) => ({
          ...p,
          conversations: p.conversations.filter((c: any) => c.id !== data.conversationId)
        }))
      })
      setSelectedIdState(prev => {
        if (prev === data.conversationId) {
          localStorage.removeItem(SELECTED_CONV_KEY)
          return null
        }
        return prev
      })
      toast.warning(`You have been unassigned from ${data.userName}'s conversation`)
    }

    const handleAssignedToYou = async (data: { conversationId: string; userName: string }) => {
      setNewlyAssignedIds(prev => new Set([...prev, data.conversationId]))
      toast.success(`Assigned to ${data.userName}.`, { duration: 6000, icon: '👤' })
      try {
        const res = await convApi.getOne(data.conversationId)
        queryClient.setQueryData<{ pages: Array<{ conversations: Conversation[]; hasMore: boolean }>; pageParams: unknown[] }>(
          ['conversations'],
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
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
      }
    }

    socket.on('conversation:updated', handleConvUpdated)
    socket.on('conversation:removed', handleConvRemoved)
    socket.on('conversation:assigned_to_you', handleAssignedToYou)

    return () => {
      socket.off('conversation:updated', handleConvUpdated)
      socket.off('conversation:removed', handleConvRemoved)
      socket.off('conversation:assigned_to_you', handleAssignedToYou)
    }
  }, [queryClient])

  const effectiveSelectedId = useMemo(() => {
    if (selectedId === '__none__') return null
    if (selectedId && allConversations.some(c => c.id === selectedId)) return selectedId
    if (allConversations.length === 0) return null

    // API already returns conversations sorted by lastMessageAt desc
    return allConversations[0]?.id ?? null
  }, [allConversations, selectedId])

  const selectedConv = React.useMemo(() => allConversations.find(c => c.id === effectiveSelectedId), [allConversations, effectiveSelectedId])

  const tabFiltered = useMemo(() => {
    if (!isSuperAdmin) return allConversations
    if (activeTab === 'mine') return allConversations.filter(c => c.assignedAdminId === user?.id)
    return allConversations
  }, [allConversations, isSuperAdmin, activeTab, user?.id])

  const filtered = useMemo(() =>
    search
      ? tabFiltered.filter(c => {
        const q = search.toLowerCase()
        return c.user?.name?.toLowerCase().includes(q) || c.user?.email?.toLowerCase().includes(q)
      })
      : tabFiltered
    , [search, tabFiltered])

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 100 && hasNextPage && !isFetchingNextPage) fetchNextPage()
  }, [hasNextPage, isFetchingNextPage, fetchNextPage])

  const selectConv = (id: string | null) => {
    if (id) {
      setSelectedIdState(id)
      localStorage.setItem(SELECTED_CONV_KEY, id)
      setNewlyAssignedIds(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
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
        effectiveSelectedId && !sidebarCollapsed ? 'hidden sm:flex sm:w-[340px]' : '',
        effectiveSelectedId && sidebarCollapsed ? 'hidden sm:flex sm:w-0 sm:overflow-hidden sm:border-r-0' : '',
        !effectiveSelectedId ? 'w-full sm:w-[340px]' : '',
      )}>
        <div className="p-3 bg-background z-10 space-y-3 pb-2">
          <div className="flex items-center justify-between px-2 pt-1">
            <h2 className="text-xl font-bold tracking-tight">Chats</h2>
            <Badge variant="secondary" className="text-[10px] tabular-nums">{filtered.length}</Badge>
          </div>
          {isSuperAdmin && (
            <div className="flex gap-1 p-1 bg-muted/50 rounded-lg">
              <button onClick={() => setActiveTab('mine')} className={cn('flex-1 text-xs font-medium py-1.5 rounded-md transition-all', activeTab === 'mine' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground')}>My Chats</button>
              <button onClick={() => setActiveTab('all')} className={cn('flex-1 text-xs font-medium py-1.5 rounded-md transition-all', activeTab === 'all' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground')}>All Chats</button>
            </div>
          )}
          <div className="relative px-2">
            <Search className="absolute left-5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search or start a new chat" value={search} onChange={e => setSearch(e.target.value)} className="pl-9 h-9 rounded-xl border-none bg-accent focus-visible:ring-0 shadow-none transition-colors" />
          </div>
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
                <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground"><Inbox className="h-10 w-10 opacity-50" /><p className="text-sm font-medium">No conversations found</p></div>
              ) : (
                filtered.map(conv => (
                  <ConversationItem
                    key={conv.id}
                    conversation={conv}
                    isSelected={conv.id === effectiveSelectedId}
                    isNewlyAssigned={newlyAssignedIds.has(conv.id)}
                    onClick={() => selectConv(conv.id)}
                  />
                ))
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
            onBack={() => selectConv(null)}
            sidebarCollapsed={sidebarCollapsed}
            onToggleSidebar={toggleSidebar}
          />
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-4 text-muted-foreground p-8">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted"><Mail className="h-8 w-8 opacity-50" /></div>
            <div className="text-center space-y-1"><p className="text-sm font-semibold text-foreground">Select a conversation</p></div>
          </div>
        )}
      </div>
    </div>
  )
}
