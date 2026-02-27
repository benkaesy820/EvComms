import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { MessageSquare, Send, Headphones, Sparkles, CheckSquare, Square } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'
import { MessageInput } from '@/components/chat/MessageInput'
import { AnnouncementsBanner } from '@/components/chat/AnnouncementsBanner'
import { BulkDeleteBar } from '@/components/chat/BulkDeleteBar'
import { useConversation, useMessages, useSendMessage, useMarkRead, useDeleteMessage } from '@/hooks/useMessages'
import { useAuthStore } from '@/stores/authStore'
import { useChatStore } from '@/stores/chatStore'
import { useReaction } from '@/hooks/useReactions'
import { getSocket } from '@/lib/socket'
import type { Message } from '@/lib/schemas'

import { MessageList } from '@/components/chat/MessageList'
function EmptyConversation() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-6 p-6">
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
  const { data: convData, isLoading: convLoading } = useConversation()
  const conversationId = convData?.conversation?.id
  const { data: msgData, isLoading: msgLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useMessages(conversationId)
  const sendMessage = useSendMessage(conversationId)
  const markRead = useMarkRead(conversationId)
  const deleteMsg = useDeleteMessage()
  const reactionMut = useReaction()

  const [typingUsers, setTypingUsers] = useState<Map<string, string>>(new Map())
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
    await Promise.allSettled(
      ids.map(messageId =>
        deleteMsg.mutateAsync({ messageId, conversationId: conversationId!, scope: 'all' })
      )
    )
    setIsDeleting(false)
    exitSelectMode()
  }, [selectedIds, deleteMsg, conversationId, exitSelectMode])

  const typingContent = useMemo(
    () => Array.from(typingUsers.entries()).map(([userId, userName]) => (
      <TypingIndicator key={userId} userName={userName} />
    )),
    [typingUsers]
  )

  const markReadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markReadRef = useRef(markRead.mutate)
  useEffect(() => { markReadRef.current = markRead.mutate })

  const allMessages = useMemo(
    () => msgData?.pages.flatMap((p: { messages: Message[] }) => p.messages) ?? [],
    [msgData]
  )

  useEffect(() => {
    if (conversationId && allMessages.length > 0) {
      if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current)
      markReadTimerRef.current = setTimeout(() => markReadRef.current(), 300)
    }
    return () => { if (markReadTimerRef.current) clearTimeout(markReadTimerRef.current) }
  }, [conversationId, allMessages.length])

  const sendTyping = useCallback((isTyping: boolean) => {
    const socket = getSocket()
    if (socket?.connected && conversationId) {
      socket.emit(isTyping ? 'typing:start' : 'typing:stop', { conversationId })
    }
  }, [conversationId])

  useEffect(() => {
    const socket = getSocket()
    if (!socket || !conversationId) return

    const handleTypingStart = (data: { userId: string; userName: string; conversationId: string }) => {
      if (data.conversationId !== conversationId || data.userId === user?.id) return
      setTypingUsers((prev) => new Map(prev).set(data.userId, data.userName))
    }

    const handleTypingStop = (data: { userId: string; conversationId: string }) => {
      if (data.conversationId !== conversationId) return
      setTypingUsers((prev) => {
        const next = new Map(prev)
        next.delete(data.userId)
        return next
      })
    }

    type CacheShape = { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }
    const updateCache = (updater: (old: CacheShape) => CacheShape) =>
      queryClient.setQueryData<CacheShape>(['messages', conversationId], (old) => old ? updater(old) : old)

    const handleNewMessage = (data: { message: Message }) => {
      if (data.message.conversationId !== conversationId) return
      updateCache((old) => {
        const exists = old.pages.some((p) => p.messages.some((m) => m.id === data.message.id))
        if (exists) return old
        return { ...old, pages: old.pages.map((p, i) => i === 0 ? { ...p, messages: [...p.messages, data.message] } : p) }
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

    socket.on('typing:start', handleTypingStart)
    socket.on('typing:stop', handleTypingStop)
    socket.on('message:new', handleNewMessage)
    socket.on('message:sent', handleMessageSent)
    socket.on('message:deleted', handleMessageDeleted)
    return () => {
      socket.off('typing:start', handleTypingStart)
      socket.off('typing:stop', handleTypingStop)
      socket.off('message:new', handleNewMessage)
      socket.off('message:sent', handleMessageSent)
      socket.off('message:deleted', handleMessageDeleted)
    }
  }, [conversationId, user?.id, queryClient])

  const handleSend = useCallback(
    (data: { type: string; content?: string; mediaId?: string; replyToId?: string; announcementId?: string }) => {
      sendMessage.mutate(data)
    },
    [sendMessage],
  )

  return (
    <div className="flex h-full flex-col bg-background overflow-hidden">

      <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col overflow-hidden min-h-0">
        {/* Chat header bar */}
        <div className="flex items-center gap-3 border-b px-5 py-3 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-primary">
            <Headphones className="h-4 w-4" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold">Support Team</p>
            <p className="text-[11px] text-muted-foreground">
              {typingUsers.size > 0
                ? `${Array.from(typingUsers.values()).join(', ')} typing...`
                : 'We typically reply within minutes'}
            </p>
          </div>
          {/* Select mode toggle */}
          {allMessages.length > 0 && (
            <Button
              variant={selectMode ? 'secondary' : 'ghost'}
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => selectMode ? exitSelectMode() : setSelectMode(true)}
              title={selectMode ? 'Cancel selection' : 'Select messages'}
            >
              {selectMode ? <Square className="h-4 w-4" /> : <CheckSquare className="h-4 w-4" />}
            </Button>
          )}
        </div>

        {/* Announcements */}
        <AnnouncementsBanner />

        {/* Messages area */}
        <div className="relative flex-1 overflow-hidden min-h-0 flex flex-col">
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
              renderMessage={(msg) => (
                <div key={msg.id}>
                  <MessageBubble
                    message={msg}
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
                  />
                </div>
              )}
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

        {/* Bulk delete bar OR message input */}
        {selectMode ? (
          <BulkDeleteBar
            count={selectedIds.size}
            onDelete={handleBulkDelete}
            onCancel={exitSelectMode}
            isDeleting={isDeleting}
          />
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
