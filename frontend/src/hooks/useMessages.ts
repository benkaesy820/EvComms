import { useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query'
import { conversations as api } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import { useAuthStore } from '@/stores/authStore'
import { toast } from '@/components/ui/sonner'
import type { Message } from '@/lib/schemas'

export function useConversation() {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const queryClient = useQueryClient()

  useEffect(() => {
    if (isAdmin) return
    const socket = getSocket()
    if (!socket) return

    // FIX: Only zero unreadCount when the current user read the messages.
    // messages:read is also sent to the user when the ADMIN reads the user's outgoing
    // messages (to trigger double blue ticks). In that case readBy === adminId, not
    // the user's own ID, so unreadCount must NOT be zeroed — that would make the
    // unread badge disappear even though the admin's messages are still unread by the user.
    const handleMessagesRead = (data: { conversationId: string; readBy: string; readAt: number }) => {
      if (data.readBy !== user?.id) return  // Admin read the user's messages — only update ticks, not badge
      queryClient.setQueryData<{ success: boolean; conversation: { unreadCount: number;[key: string]: unknown } | null }>(
        ['conversation'],
        (old) => {
          if (!old?.conversation) return old
          return { ...old, conversation: { ...old.conversation, unreadCount: 0 } }
        }
      )
    }

    socket.on('messages:read', handleMessagesRead)
    return () => {
      socket.off('messages:read', handleMessagesRead)
    }
  }, [isAdmin, queryClient, user?.id])

  return useQuery({
    queryKey: ['conversation'],
    queryFn: async () => {
      const result = await api.get()

      // Validate conversation data
      if (result.conversation) {
        const conv = result.conversation
        result.conversation = {
          ...conv,
          id: conv.id || '',
          userId: conv.userId || user?.id || '',
          unreadCount: typeof conv.unreadCount === 'number' ? conv.unreadCount : 0,
          createdAt: typeof conv.createdAt === 'number' ? conv.createdAt : Date.now(),
          lastMessageAt: conv.lastMessageAt || null,
        }
      }

      return result
    },
    enabled: !!user && !isAdmin,
    staleTime: 0,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
  })
}

export function useAdminConversations(archived = false) {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'

  return useInfiniteQuery({
    queryKey: ['conversations', { archived }],
    queryFn: ({ pageParam }) =>
      archived
        ? api.getArchived({ before: pageParam, limit: 30 })
        : api.getAdmin({ before: pageParam, limit: 30 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      if (!lastPage || !lastPage.hasMore) return undefined
      // Prefer the composite nextCursor returned by the server (prevents duplicate
      // waiting-tier rows on Load More). Fall back to lastMessageAt for old responses.
      if (lastPage.nextCursor) return lastPage.nextCursor
      const convs = lastPage.conversations
      if (!Array.isArray(convs) || convs.length === 0) return undefined
      const last = convs[convs.length - 1]
      if (!last || last.lastMessageAt == null) return undefined
      return String(last.lastMessageAt)
    },
    enabled: !!user && isAdmin,
    staleTime: 0,
  })
}

export function useMessages(conversationId: string | undefined) {
  return useInfiniteQuery({
    queryKey: ['messages', conversationId],
    queryFn: async ({ pageParam }) => {
      if (!conversationId) {
        throw new Error('No conversation ID provided')
      }

      const result = await api.messages(conversationId, { before: pageParam, limit: 30 })

      // Validate that messages have required fields
      if (result.messages) {
        result.messages = result.messages.map((msg, i) => ({
          ...msg,
          id: msg.id || `temp-${Date.now()}-${i}`,
          senderId: msg.senderId || 'unknown',
          type: msg.type || 'TEXT',
          status: msg.status || 'SENT',
          createdAt: msg.createdAt || new Date().toISOString(),
        }))
      }

      return result
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      // Defensive: ensure lastPage and messages exist
      if (!lastPage || !lastPage.hasMore || !lastPage.messages || !Array.isArray(lastPage.messages) || lastPage.messages.length === 0) {
        return undefined
      }
      const lastMsg = lastPage.messages[lastPage.messages.length - 1]
      if (!lastMsg || !lastMsg.id) return undefined
      return lastMsg.id
    },
    enabled: !!conversationId,
    staleTime: 0,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
  })
}

export function useSendMessage(conversationId: string | undefined) {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const tempIdRef = useRef<string>('')
  const failureTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  // Cancel the pending failure timers on unmount
  useEffect(() => {
    return () => {
      failureTimersRef.current.forEach(timer => clearTimeout(timer))
    }
  }, [])

  return useMutation({
    mutationFn: async (data: { type: string; content?: string; mediaId?: string; media?: { id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null; replyToId?: string; announcementId?: string; subsidiaryId?: string }) => {
      let convId = conversationId

      // Auto-create conversation if user doesn't have one yet
      if (!convId) {
        // Pass subsidiaryId when auto-creating the conversation
        const res = await api.create(data.subsidiaryId)
        convId = res.conversation.id

        // Move the optimistic message from the undefined cache to the new conversation cache.
        // Do this BEFORE activating useMessages(convId) so the optimistic message is in
        // place when the component re-renders.
        const tempMsgs = queryClient.getQueryData(['messages', undefined])
        if (tempMsgs) {
          queryClient.setQueryData(['messages', convId], tempMsgs)
          queryClient.removeQueries({ queryKey: ['messages', undefined] })
        }

        const socket = getSocket()
        if (socket?.connected) {
          const tempId = tempIdRef.current

          // CRITICAL ORDER: emit via socket FIRST, THEN update ['conversation'].
          // Updating ['conversation'] activates useMessages(convId) which immediately
          // fires a background HTTP GET (staleTime:0). If socket.emit came after, that
          // HTTP GET would race with the server saving the message and return empty,
          // wiping the optimistic message from the UI.
          // By emitting first the server starts the DB write before the HTTP GET fires.
          socket.emit('message:send', {
            conversationId: convId,
            type: data.type,
            content: data.content,
            mediaId: data.mediaId,
            tempId,
            replyToId: data.replyToId,
            announcementId: data.announcementId,
          })

          // Now safe to activate useMessages — server is already processing the message
          queryClient.setQueryData(['conversation'], { success: true, conversation: res.conversation })

          // Timeout: if message:sent hasn't replaced tempId within 8s, mark as failed
          const cid = convId
          const timer = setTimeout(() => {
            failureTimersRef.current.delete(tempId)
            const cache = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(['messages', cid])
            const stillPending = cache?.pages.some((p) => p.messages.some((m) => m.id === tempId))
            if (stillPending) {
              markMessageFailed(queryClient as any, cid, tempId)
              toast.error('Message failed to send. Tap to retry.')
            }
          }, 8000)
          failureTimersRef.current.set(tempId, timer)

          return { tempId, conversationId: convId }
        }

        // No socket — update conversation cache then fall through to HTTP send
        queryClient.setQueryData(['conversation'], { success: true, conversation: res.conversation })
      }

      const socket = getSocket()
      if (socket?.connected) {
        const tempId = tempIdRef.current
        socket.emit('message:send', {
          conversationId: convId,
          type: data.type,
          content: data.content,
          mediaId: data.mediaId,
          tempId,
          replyToId: data.replyToId,
          announcementId: data.announcementId,
        })

        // Timeout: if message:sent hasn't replaced tempId within 8s, mark as failed
        const cid = convId
        const timer = setTimeout(() => {
          failureTimersRef.current.delete(tempId)
          const cache = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(['messages', cid])
          const stillPending = cache?.pages.some((p) => p.messages.some((m) => m.id === tempId))
          if (stillPending) {
            markMessageFailed(queryClient as any, cid, tempId)
            toast.error('Message failed to send. Please try again.')
          }
        }, 8000)
        failureTimersRef.current.set(tempId, timer)

        return { tempId, conversationId: convId }
      }

      // HTTP fallback — remove optimistic and let real data come through
      const res = await api.sendMessage(convId, { type: data.type, content: data.content, mediaId: data.mediaId, replyToId: data.replyToId, announcementId: data.announcementId })
      if (tempIdRef.current && conversationId) {
        queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(
          ['messages', conversationId],
        (old) => {
          if (!old || !old.pages) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: (page.messages || []).filter((m) => m.id !== tempIdRef.current),
            })),
          }
        },
        )
      }
      return { message: res.message, conversationId: convId }
    },

    onMutate: async (data: { type: string; content?: string; mediaId?: string; media?: { id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null; replyToId?: string; announcementId?: string; subsidiaryId?: string }) => {
      // Always generate tempId so mutationFn can use it
      const tempId = `temp-${Date.now()}-${Math.random().toString(36).slice(2)}`
      tempIdRef.current = tempId

      if (!user) return { tempId }

      await queryClient.cancelQueries({ queryKey: ['messages', conversationId] })

      const optimisticMessage: Message = {
        id: tempId,
        conversationId: conversationId || '',
        senderId: user.id,
        sender: { id: user.id, name: user.name, role: user.role },
        type: data.type as Message['type'],
        content: data.content || null,
        status: 'SENT',
        readAt: null,
        deletedAt: null,
        createdAt: new Date().toISOString(),
        media: data.media ? { ...data.media, type: data.media.type as import('@/lib/schemas').MessageType } : null,
        reactions: [],
        replyToId: data.replyToId || null,
        replyTo: null,
        announcementId: data.announcementId || null,
      }

      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', conversationId],
        (old) => {
          if (!old) {
            return {
              pages: [{ success: true, messages: [optimisticMessage], hasMore: false }],
              pageParams: [undefined],
            }
          }
      // Append to FIRST page (most recent) — matches message:new handler
      // Defensive: handle empty pages array
      if (!old.pages || old.pages.length === 0) {
        return {
          pages: [{ success: true, messages: [optimisticMessage], hasMore: false }],
          pageParams: [undefined],
        }
      }
      const firstPage = old.pages[0]
      if (!firstPage) {
        return {
          pages: [{ success: true, messages: [optimisticMessage], hasMore: false }],
          pageParams: [undefined],
        }
      }
      return {
        ...old,
        pages: [
          { ...firstPage, messages: [...(firstPage.messages || []), optimisticMessage] },
          ...old.pages.slice(1),
        ],
      }
        },
      )

      return { tempId }
    },

    onError: (_err, _data, context) => {
      if (context?.tempId) {
        const timer = failureTimersRef.current.get(context.tempId)
        if (timer) {
          clearTimeout(timer)
          failureTimersRef.current.delete(context.tempId)
        }
        if (conversationId) {
          markMessageFailed(queryClient as any, conversationId, context.tempId)
        }
      }
    },

  })
}

// Marks an optimistic (temp) message as FAILED in the cache instead of deleting it.
// The bubble shows a retry affordance so the user can resend.
function markMessageFailed(
  queryClient: ReturnType<typeof import('@tanstack/react-query').useQueryClient>,
  conversationId: string,
  tempId: string
) {
  queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: import('@/lib/schemas').Message[]; hasMore: boolean }> }>(
    ['messages', conversationId],
    (old) => {
      if (!old) return old
      return {
        ...old,
        pages: old.pages.map((page) => ({
          ...page,
          messages: page.messages.map((m) =>
            m.id === tempId ? { ...m, status: 'FAILED' as any } : m
          ),
        })),
      }
    }
  )
}

export function useMarkRead(conversationId: string | undefined) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => {
      if (!conversationId) throw new Error('No conversation')

      const socket = getSocket()
      if (socket?.connected) {
        socket.emit('messages:mark_read', { conversationId })
        return Promise.resolve({ success: true, readCount: 0 })
      }

      return api.markRead(conversationId)
    },
    onSuccess: () => {
      // Immediately zero adminUnreadCount across ALL conversations cache variants
      queryClient.setQueriesData<{ pages: Array<{ conversations: import('@/lib/schemas').Conversation[]; hasMore: boolean }> }>(
        { queryKey: ['conversations'] },
        (old) => {
          if (!old || !old.pages) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              conversations: (p.conversations || []).map((c) =>
                c.id === conversationId ? { ...c, adminUnreadCount: 0 } : c
              ),
            })),
          }
        },
      )
    },
  })
}

export function useDeleteMessage() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ messageId, permanent, scope }: { messageId: string; conversationId?: string; permanent?: boolean; scope?: 'me' | 'all' }) =>
      api.deleteMessage(messageId, permanent, scope),
    onMutate: async ({ messageId, conversationId }) => {
      if (!conversationId) return { previousMessages: undefined }
      await queryClient.cancelQueries({ queryKey: ['messages', conversationId] })

      const previousMessages = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(['messages', conversationId])
      const now = Date.now()

      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', conversationId],
        (old) => {
          if (!old || !old.pages) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: (page.messages || []).map((m) =>
                m.id === messageId ? { ...m, deletedAt: now } : m,
              ),
            })),
          }
        },
      )
      return { previousMessages }
    },
    onError: (_err, { conversationId }, context) => {
      if (conversationId && context?.previousMessages) {
        queryClient.setQueryData(['messages', conversationId], context.previousMessages)
      }
      toast.error('Failed to delete message')
    },
  })
}
