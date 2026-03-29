import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { useLocation } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { MessageSquare, Send, Headphones, Sparkles, CheckSquare, Square, Building2, ChevronDown, Archive, RotateCcw } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'
import { MessageInput } from '@/components/chat/MessageInput'
import { AnnouncementsBanner } from '@/components/chat/AnnouncementsBanner'
import { BulkDeleteBar } from '@/components/chat/BulkDeleteBar'
import { useConversation, useMessages, useSendMessage, useMarkRead, useDeleteMessage } from '@/hooks/useMessages'
import { useVisibilityMarkRead } from '@/hooks/useVisibilityMarkRead'
import { useReopenConversation } from '@/hooks/useArchiveConversation'
import { useAuthStore } from '@/stores/authStore'
import { useChatStore } from '@/stores/chatStore'
import { useReaction } from '@/hooks/useReactions'
import { getSocket } from '@/lib/socket'
import type { Message } from '@/lib/schemas'
import { useAppConfig } from '@/hooks/useConfig'
import { conversations as convApi } from '@/lib/api'

import { MessageList } from '@/components/chat/MessageList'
function EmptyConversation() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-6 p-4 sm:p-6">
      <div className="relative">
        <div className="flex h-20 w-20 items-center justify-center rounded-3xl bg-primary/10 ring-8 ring-primary/5">
          <MessageSquare className="h-10 w-10 text-primary" />
        </div>
        <div className="absolute -right-1 -top-1 flex h-7 w-7 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg">
          <Sparkles className="h-3.5 w-3.5" />
        </div>
      </div>

      <div className="text-center space-y-2 max-w-sm">
        <h2 className="text-xl font-bold tracking-tight">Start a Conversation</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">
          Send your first message to connect with our support team. We typically respond within minutes.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 w-full max-w-sm">
        {[
          { icon: Headphones, label: 'Dedicated support team' },
          { icon: Send, label: 'Real-time messaging' },
        ].map(({ icon: Icon, label }) => (
          <div key={label} className="flex items-center gap-2.5 rounded-xl bg-muted/50 px-4 py-3">
            <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function ChatSkeleton() {
  return (
    <div className="flex-1 p-6 space-y-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className={`flex ${i % 2 === 0 ? 'justify-start' : 'justify-end'}`}>
          <Skeleton className={`rounded-2xl ${i % 2 === 0 ? 'rounded-bl-md' : 'rounded-br-md'} ${i === 2 ? 'h-20 w-56' : 'h-12 w-44'}`} />
        </div>
      ))}
    </div>
  )
}

export function ChatPage() {
  const user = useAuthStore((s) => s.user)
  const queryClient = useQueryClient()
  const location = useLocation()
  const { data: configData } = useAppConfig()
  const subsidiaries = configData?.subsidiaries ?? []

  const { data: convData, isLoading: convLoading } = useConversation()
  const conversationId = convData?.conversation?.id
  const { data: msgData, isLoading: msgLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useMessages(conversationId)
  const sendMessage = useSendMessage(conversationId)
  const markRead = useMarkRead(conversationId)
  const userUnreadCount = convData?.conversation?.unreadCount ?? 0
  const { sentinelRef: lastMsgRef } = useVisibilityMarkRead({
    hasUnread: userUnreadCount > 0,
    onRead: markRead.mutate,
    conversationId,
  })
  // Timer-based debounce markRead — fires when conversation/messages change (belt+suspenders with viewport hook)
  const markReadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markReadRef = useRef(markRead.mutate)
  useEffect(() => { markReadRef.current = markRead.mutate })
  const deleteMsg = useDeleteMessage()
  const reactionMut = useReaction()
  const reopenConv = useReopenConversation()
  const isArchived = convData?.conversation?.archivedAt

  // Subsidiary selector state — initialized from router state (set by HomePage subsidiary card click)
  // undefined = not chosen yet | null = user chose General Enquiry | string = specific subsidiary
  const [selectedSubsidiaryId, setSelectedSubsidiaryId] = useState<string | null | undefined>(
    (location.state as { subsidiaryId?: string } | null)?.subsidiaryId ?? undefined
  )
  const [showSubsidiaryPicker, setShowSubsidiaryPicker] = useState(false)
  const subsidiaryPickerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!showSubsidiaryPicker) return
    const handler = (e: MouseEvent) => {
      if (subsidiaryPickerRef.current && !subsidiaryPickerRef.current.contains(e.target as Node)) {
        setShowSubsidiaryPicker(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showSubsidiaryPicker])
  const convExists = !!convData?.conversation
  const convSubsidiaryId = convData?.conversation?.subsidiaryId ?? undefined
  // Lock subsidiary after first message
  const subsidiaryLocked = !!convData?.conversation?.id && !!convSubsidiaryId

  // Persist subsidiaryId to conversation when it changes and a conversation exists
  // Also hydrate from the backend if we arrived without route state
  useEffect(() => {
    if (!convExists) return
    const convId = convData?.conversation?.id
    if (selectedSubsidiaryId === undefined && convSubsidiaryId) {
      // Hydrate local state from the saved conversation
      setSelectedSubsidiaryId(convSubsidiaryId)
    } else if (
      convId &&
      selectedSubsidiaryId !== undefined &&
      (convSubsidiaryId ?? null) !== selectedSubsidiaryId
    ) {
      // Only update — never create a new conversation here
      // Pass null explicitly for General Enquiry (selectedSubsidiaryId === null),
      // never an empty string which would be stored as '' in the DB instead of NULL.
      convApi.updateSubsidiary(convId, selectedSubsidiaryId ?? null).catch(() => { })
    }
  }, [convExists, convData?.conversation?.id, convSubsidiaryId, selectedSubsidiaryId])

  const [typingUsers, setTypingUsers] = useState<Map<string, string>>(new Map())
  const typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())
  const setReplyTo = useChatStore(s => s.setReplyTo)

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isDeleting, setIsDeleting] = useState(false)

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
    setIsDeleting(true)
    const ids = Array.from(selectedIds)
    // Process in chunks of 5 to avoid flooding the server
    const CHUNK = 5
    for (let i = 0; i < ids.length; i += CHUNK) {
      await Promise.allSettled(
        ids.slice(i, i + CHUNK).map(messageId =>
          deleteMsg.mutateAsync({ messageId, conversationId: conversationId!, scope: 'all' })
        )
      )
    }
    setIsDeleting(false)
    exitSelectMode()
  }, [selectedIds, deleteMsg, conversationId, exitSelectMode])

  const typingContent = useMemo(
    () => Array.from(typingUsers.entries()).map(([userId, userName]) => (
      <TypingIndicator key={userId} userName={userName} />
    )),
    [typingUsers]
  )

  const allMessages = useMemo(
    () => msgData?.pages.flatMap((p: { messages: Message[] }) => p.messages) ?? [],
    [msgData]
  )

  // Timer fallback: also fire markRead on message arrival (in case viewport hook missed it)
  useEffect(() => {
    if (conversationId && allMessages.length > 0 && userUnreadCount > 0) {
      if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current)
      markReadTimerRef.current = setTimeout(() => markReadRef.current(), 300)
    }
    return () => { if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current) }
  }, [conversationId, allMessages.length, userUnreadCount])

  const sendTyping = useCallback((isTyping: boolean) => {
    const socket = getSocket()
    if (socket?.connected && conversationId) {
      socket.emit(isTyping ? 'typing:start' : 'typing:stop', { conversationId })
    }
  }, [conversationId])

  useEffect(() => {
    const socket = getSocket()
    if (!socket || !conversationId) return

    // 8s: slightly more than 2× the 3s heartbeat interval so the indicator
    // never flickers off between re-emits even on a slow connection.
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

    type CacheShape = { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }
    const updateCache = (updater: (old: CacheShape) => CacheShape) =>
      queryClient.setQueryData<CacheShape>(['messages', conversationId], (old) => old ? updater(old) : old)

    const handleNewMessage = (data: { message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      updateCache((old) => {
        if (!old || !old.pages || old.pages.length === 0) {
          return { pages: [{ messages: [data.message], hasMore: false }] as any, pageParams: [] }
        }
        const exists = old.pages.some((p) => p.messages.some((m) => m.id === data.message.id))
        if (exists) return old
        return { ...old, pages: old.pages.map((p, i) => i === 0 ? { ...p, messages: [data.message, ...p.messages] } : p) }
      })
      // Visibility-based markRead handles this — no timer needed
    }

    const handleMessageSent = (data: { tempId: string; message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      updateCache((old) => {
        const seen = new Set<string>()
        return {
          ...old,
          pages: old.pages.map(p => ({
            ...p,
            messages: p.messages
              .map(m => {
                if (m.id !== data.tempId) return m
                // Preserve optimistic media if server didn't return one (race with confirm)
                const media = data.message.media ?? m.media
                return { ...data.message, media }
              })
              .filter(m => { if (seen.has(m.id)) return false; seen.add(m.id); return true })
          }))
        }
      })
    }

    const handleMessageDeleted = (data: { messageId: string; conversationId: string; deletedAt: number }) => {
      if (data.conversationId !== conversationId) return
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({ ...p, messages: p.messages.map(m => m.id === data.messageId ? { ...m, deletedAt: data.deletedAt } : m) }))
      }))
    }

    const handleConvArchived = (data: { conversationId: string }) => {
      if (data.conversationId === conversationId) {
        queryClient.invalidateQueries({ queryKey: ['conversation'] })
      }
    }

    const handleConvUnarchived = (data: { conversationId: string }) => {
      if (data.conversationId === conversationId) {
        queryClient.invalidateQueries({ queryKey: ['conversation'] })
      }
    }

    const handleMessagesRead = (data: { conversationId: string; readBy: string; readAt: number }) => {
      if (data.conversationId !== conversationId) return
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({
          ...p,
          messages: p.messages.map(m => {
            const mAny = m as any
            const newReadBy = Array.from(new Set([...(mAny.readBy || []), data.readBy]))
            return { ...m, status: 'READ' as any, readBy: newReadBy }
          })
        }))
      }))
    }

    type MessageReaction = { id: string; messageId: string; userId: string; emoji: string }

    const handleReaction = (data: { messageId: string; reaction: MessageReaction | { userId: string; emoji: string }; action: 'add' | 'remove' }) => {
      updateCache((old) => ({
        ...old,
        pages: old.pages.map(p => ({
          ...p,
          messages: p.messages.map(m => {
            if (m.id !== data.messageId) return m
            const reactions = m.reactions ?? []
            if (data.action === 'add') {
              const reaction: MessageReaction = 'id' in data.reaction
                ? data.reaction as MessageReaction
                : { id: '', messageId: data.messageId, userId: data.reaction.userId, emoji: data.reaction.emoji }
              return { ...m, reactions: [...reactions.filter(r => r.userId !== reaction.userId), reaction] }
            }
            return { ...m, reactions: reactions.filter(r => !(r.userId === data.reaction.userId && r.emoji === data.reaction.emoji)) }
          })
        }))
      }))
    }

    socket.on('typing:start', handleTypingStart)
    socket.on('typing:stop', handleTypingStop)
    socket.on('message:new', handleNewMessage)
    socket.on('message:sent', handleMessageSent)
    socket.on('message:deleted', handleMessageDeleted)
    socket.on('message:reaction', handleReaction)
    socket.on('messages:read', handleMessagesRead)
    socket.on('conversation:archived', handleConvArchived)
    socket.on('conversation:unarchived', handleConvUnarchived)
    socket.on('conversation:reopened', handleConvUnarchived)

    // Keep user-side conversation cache (unreadCount, archivedAt) in sync with
    const handleConvUpdated = (data: { conversationId: string; unreadCount?: number; assignedAdminId?: string | null }) => {
      if (!conversationId || data.conversationId !== conversationId) return
      queryClient.setQueryData<{ success: boolean; conversation: Record<string, unknown> | null }>(
        ['conversation'],
        (old) => {
          if (!old?.conversation) return old
          return {
            ...old,
            conversation: {
              ...old.conversation,
              ...(data.unreadCount !== undefined && { unreadCount: data.unreadCount }),
              ...(data.assignedAdminId !== undefined && { assignedAdminId: data.assignedAdminId }),
            },
          }
        }
      )
    }

    socket.on('conversation:updated', handleConvUpdated)
    return () => {
      socket.off('typing:start', handleTypingStart)
      socket.off('typing:stop', handleTypingStop)
      socket.off('message:new', handleNewMessage)
      socket.off('message:sent', handleMessageSent)
      socket.off('message:deleted', handleMessageDeleted)
      socket.off('message:reaction', handleReaction)
      socket.off('messages:read', handleMessagesRead)
      socket.off('conversation:archived', handleConvArchived)
      socket.off('conversation:unarchived', handleConvUnarchived)
      socket.off('conversation:reopened', handleConvUnarchived)
      socket.off('conversation:updated', handleConvUpdated)
      typingTimersRef.current.forEach(t => clearTimeout(t))
      typingTimersRef.current.clear()
    }
  }, [conversationId, user?.id, queryClient])

  type SendData = { type: string; content?: string; mediaId?: string; media?: { id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null; replyToId?: string; announcementId?: string; subsidiaryId?: string }

  const handleSend = useCallback(
    (data: SendData) => {
      // If undefined (not picked), it defaults to null on the backend, which is fine (General Inquiry)
      sendMessage.mutate({ ...data, subsidiaryId: selectedSubsidiaryId ?? undefined })
    },
    [sendMessage, selectedSubsidiaryId],
  )

  // ── Mobile keyboard fix ──────────────────────────────────────────────────────
  // visualViewport.height shrinks when the keyboard opens; window.innerHeight does not.
  // We push --chat-h onto <html> so .chat-viewport-height collapses to the visible area.
  // We also toggle .keyboard-open so UserLayout can zero out its bottom-nav padding
  // (the fixed nav sits behind the keyboard anyway — the padding is just wasted space).
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const update = () => {
      const h = vv.height
      document.documentElement.style.setProperty('--chat-h', `${h}px`)
      const keyboardOpen = window.innerHeight - h > 100
      document.documentElement.classList.toggle('keyboard-open', keyboardOpen)
    }
    update()
    vv.addEventListener('resize', update)
    return () => {
      vv.removeEventListener('resize', update)
      document.documentElement.style.removeProperty('--chat-h')
      document.documentElement.classList.remove('keyboard-open')
    }
  }, [])

  return (
    <div className="chat-viewport-height flex flex-col bg-background overflow-hidden">

      <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col overflow-hidden min-h-0">
        {/* Chat header bar */}
        <div className="flex items-center gap-3 border-b px-3 sm:px-5 py-2 sm:py-3 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-primary">
            <Headphones className="h-4 w-4" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold">Support Team</p>
            <p className="text-[11px] text-muted-foreground">
              {isArchived
                ? 'This conversation has been closed'
                : typingUsers.size > 0
                  ? `${Array.from(typingUsers.values()).join(', ')} typing…`
                  : 'We typically reply within minutes'}
            </p>
          </div>

          {/* Subsidiary selector — locked after first message, changeable before */}
          {subsidiaries.length > 0 && (
            <div className="relative" ref={subsidiaryPickerRef}>
              {subsidiaryLocked ? (
                <div className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary max-w-[120px] sm:max-w-[200px]">
                  <Building2 className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate text-[11px] sm:text-[12px] font-medium">
                    {subsidiaries.find(s => s.id === selectedSubsidiaryId)?.name ?? 'General Enquiry'}
                  </span>
                </div>
              ) : (
                <>
                  <button
                    className={`flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-3 py-1.5 rounded-full border shadow-sm transition-all max-w-[120px] sm:max-w-[200px] ${selectedSubsidiaryId
                      ? 'bg-primary/10 border-primary/20 text-primary hover:bg-primary/20 hover:border-primary/30'
                      : 'bg-muted/40 hover:bg-muted text-muted-foreground'
                      }`}
                    onClick={() => setShowSubsidiaryPicker(v => !v)}
                  >
                    <Building2 className={`h-3.5 w-3.5 shrink-0 ${selectedSubsidiaryId ? 'text-primary' : ''}`} />
                    <span className="truncate text-[11px] sm:text-[13px] font-medium hidden sm:inline">
                      {selectedSubsidiaryId
                        ? (subsidiaries.find(s => s.id === selectedSubsidiaryId)?.name ?? 'Select subsidiary')
                        : selectedSubsidiaryId === null
                          ? 'General Enquiry'
                          : 'Select area…'}
                    </span>
                    <ChevronDown className="h-3.5 w-3.5 shrink-0 opacity-50" />
                  </button>
                  {showSubsidiaryPicker && (
                    <div className="absolute right-0 top-full mt-1 w-48 rounded-xl border bg-popover shadow-lg z-50 overflow-hidden">
                      <button
                        className="w-full text-left px-3 py-2.5 text-xs text-muted-foreground hover:bg-muted transition-colors"
                        onClick={() => { setSelectedSubsidiaryId(null); setShowSubsidiaryPicker(false) }}
                      >
                        None (general inquiry)
                      </button>
                      {subsidiaries.map(sub => (
                        <button
                          key={sub.id}
                          className={`w-full text-left px-3 py-2.5 text-xs hover:bg-muted transition-colors ${selectedSubsidiaryId === sub.id ? 'text-primary font-medium bg-primary/5' : ''}`}
                          onClick={() => { setSelectedSubsidiaryId(sub.id); setShowSubsidiaryPicker(false) }}
                        >
                          {sub.name}
                        </button>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* Select mode toggle */}
          {allMessages.length > 0 && (
            <Button
              variant={selectMode ? 'secondary' : 'ghost'}
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => selectMode ? exitSelectMode() : setSelectMode(true)}
              title={selectMode ? 'Cancel selection' : 'Select messages'}
              aria-label={selectMode ? 'Cancel selection' : 'Select messages'}
            >
              {selectMode ? <Square className="h-4 w-4" /> : <CheckSquare className="h-4 w-4" />}
            </Button>
          )}

        </div>

        {/* Announcements */}
        <AnnouncementsBanner />

        {/* Messages area */}
        <div className="relative flex-1 overflow-hidden min-h-0 flex flex-col">
          {/* Sticky archived banner — visible at all scroll positions */}
          {isArchived && (
            <div className="shrink-0 flex items-center justify-between gap-3 px-4 py-2.5 bg-muted/60 border-b text-sm">
              <div className="flex items-center gap-2 text-muted-foreground font-medium">
                <Archive className="h-4 w-4 shrink-0" />
                <span>This conversation was closed by the support team.</span>
              </div>
              {user?.role === 'USER' && conversationId && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={reopenConv.isPending}
                  onClick={() => reopenConv.mutate(conversationId)}
                  className="gap-1.5 shrink-0 h-7 text-xs"
                >
                  <RotateCcw className="h-3 w-3" />
                  Reopen
                </Button>
              )}
            </div>
          )}
          {(convLoading || msgLoading) ? (
            <ChatSkeleton />
          ) : allMessages.length === 0 && !conversationId ? (
            <EmptyConversation />
          ) : (
            <MessageList<Message>
              messages={allMessages}
              isLoading={msgLoading}
              isFetchingNextPage={isFetchingNextPage}
              hasNextPage={hasNextPage}
              fetchNextPage={fetchNextPage}
              getTimestamp={(msg) => msg.createdAt}
              lastMessageRef={lastMsgRef}
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
                    onReply={selectMode ? undefined : setReplyTo}
                    onReact={selectMode ? undefined : (emoji) => {
                      const hasReacted = msg.reactions?.some(r => r.userId === user?.id && r.emoji === emoji)
                      reactionMut.mutate({
                        messageId: msg.id,
                        emoji,
                        action: hasReacted ? 'remove' : 'add'
                      })
                    }}
                    onDelete={selectMode ? undefined : (scope) => deleteMsg.mutate({ messageId: msg.id, conversationId: msg.conversationId, scope })}
                    onRetry={(msg as any).status === 'FAILED' ? () => {
                      // Re-send failed message: strip the failed tempId from cache first,
                      // then fire a fresh send so a new optimistic entry is created
                      queryClient.setQueryData<{ pages: Array<{ messages: import('@/lib/schemas').Message[]; hasMore: boolean; success: boolean }> }>(
                        ['messages', conversationId],
                        (old) => old ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter(m => m.id !== msg.id) })) } : old
                      )
                      handleSend({ type: msg.type, content: msg.content ?? undefined, mediaId: (msg.media as any)?.id, replyToId: msg.replyToId ?? undefined })
                    } : undefined}
                  />
                </div>
              )}}
              emptyState={
                conversationId ? (
                  <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
                    <MessageSquare className="h-8 w-8" />
                    <p className="text-sm">No messages yet. Say hello!</p>
                  </div>
                ) : null
              }
              bottomContent={typingContent}
            />
          )}
        </div>

        {selectMode ? (
          <BulkDeleteBar
            count={selectedIds.size}
            onDelete={handleBulkDelete}
            onCancel={exitSelectMode}
            isDeleting={isDeleting}
          />
        ) : isArchived ? (
          <div className="border-t p-4 flex flex-col items-center gap-3 bg-muted/30">
            <div className="flex items-center gap-2 text-muted-foreground text-sm font-medium bg-muted px-4 py-2 rounded-full border">
              <Archive className="h-4 w-4" />
              This conversation has been closed by the support team.
            </div>
            {/* Users can reopen; admins use the header button */}
            {user?.role === 'USER' && conversationId && (
              <Button
                variant="outline"
                size="sm"
                disabled={reopenConv.isPending}
                onClick={() => reopenConv.mutate(conversationId)}
                className="gap-2"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Reopen conversation
              </Button>
            )}
          </div>
        ) : (
          <MessageInput
            conversationId={conversationId}
            onSend={handleSend}
            onTyping={sendTyping}
          />
        )}
      </div>


    </div>
  )
}