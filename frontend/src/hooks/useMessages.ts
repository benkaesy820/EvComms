import { useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query'
import { conversations as api } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import { useAuthStore } from '@/stores/authStore'
import { toast } from 'sonner'
import type { Message } from '@/lib/schemas'

export function useConversation() {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const queryClient = useQueryClient()

  useEffect(() => {
    if (isAdmin) return
    const socket = getSocket()
    if (!socket) return

    const handleMessagesRead = () => {
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
  }, [isAdmin, queryClient])

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
    staleTime: 300_000,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
  })
}

export function useAdminConversations() {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'

  return useInfiniteQuery({
    queryKey: ['conversations'],
    queryFn: ({ pageParam }) => api.getAdmin({ before: pageParam, limit: 30 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      if (!lastPage.hasMore || lastPage.conversations.length === 0) return undefined
      return lastPage.conversations[lastPage.conversations.length - 1].id
    },
    enabled: !!user && isAdmin,
    staleTime: 5 * 60_000,
  })
}

export function useMessages(conversationId: string | undefined) {
  return useInfiniteQuery({
    queryKey: ['messages', conversationId],
    queryFn: async ({ pageParam }) => {
      if (!conversationId) {
        throw new Error('No conversation ID provided')
      }

      const result = await api.messages(conversationId, { before: pageParam, limit: 20 })

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
      if (!lastPage.hasMore || lastPage.messages.length === 0) return undefined
      return lastPage.messages[0].id
    },
    enabled: !!conversationId,
    staleTime: 5 * 60_000,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
  })
}

export function useSendMessage(conversationId: string | undefined) {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const tempIdRef = useRef<string>('')

  return useMutation({
    mutationFn: async (data: { type: string; content?: string; mediaId?: string; replyToId?: string; announcementId?: string }) => {
      let convId = conversationId

      // Auto-create conversation if user doesn't have one yet
      if (!convId) {
        const res = await api.create()
        convId = res.conversation.id

        // Move the optimistic message from the undefined cache to the new conversation cache
        const tempMsgs = queryClient.getQueryData(['messages', undefined])
        if (tempMsgs) {
          queryClient.setQueryData(['messages', convId], tempMsgs)
          queryClient.removeQueries({ queryKey: ['messages', undefined] })
        }

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
        setTimeout(() => {
          const cache = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(['messages', cid])
          const stillPending = cache?.pages.some((p) => p.messages.some((m) => m.id === tempId))
          if (stillPending) {
            queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(
              ['messages', cid],
              (old) => {
                if (!old) return old
                return {
                  ...old,
                  pages: old.pages.map((page) => ({
                    ...page,
                    messages: page.messages.filter((m) => m.id !== tempId),
                  })),
                }
              },
            )
            toast.error('Message failed to send. Please try again.')
          }
        }, 8000)

        return { tempId, conversationId: convId }
      }

      // HTTP fallback — remove optimistic and let real data come through
      const res = await api.sendMessage(convId, { type: data.type, content: data.content, mediaId: data.mediaId, replyToId: data.replyToId, announcementId: data.announcementId })
      if (tempIdRef.current && conversationId) {
        queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(
          ['messages', conversationId],
          (old) => {
            if (!old) return old
            return {
              ...old,
              pages: old.pages.map((page) => ({
                ...page,
                messages: page.messages.filter((m) => m.id !== tempIdRef.current),
              })),
            }
          },
        )
      }
      return { message: res.message, conversationId: convId }
    },

    onMutate: async (data: { type: string; content?: string; mediaId?: string; replyToId?: string; announcementId?: string }) => {
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
        media: null,
        replyToId: data.replyToId || null,
        announcementId: data.announcementId || null,
      }

      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(
        ['messages', conversationId],
        (old) => {
          if (!old) {
            return {
              pages: [{ success: true, messages: [optimisticMessage], hasMore: false }]
            }
          }
          // Append to FIRST page (most recent) — matches message:new handler
          const firstPage = old.pages[0]
          return {
            ...old,
            pages: [
              { ...firstPage, messages: [...firstPage.messages, optimisticMessage] },
              ...old.pages.slice(1),
            ],
          }
        },
      )

      return { tempId }
    },

    onError: (_err, _data, context) => {
      if (context?.tempId && conversationId) {
        queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }> }>(
          ['messages', conversationId],
          (old) => {
            if (!old) return old
            return {
              ...old,
              pages: old.pages.map((page) => ({
                ...page,
                messages: page.messages.filter((m) => m.id !== context.tempId),
              })),
            }
          },
        )
      }
    },

  })
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
      // Immediately zero adminUnreadCount in the admin conversations list
      queryClient.setQueryData<{ pages: Array<{ conversations: import('@/lib/schemas').Conversation[]; hasMore: boolean }> }>(
        ['conversations'],
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              conversations: p.conversations.map((c) =>
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
    onMutate: ({ messageId, conversationId }) => {
      if (!conversationId) return
      const now = Date.now()
      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', conversationId],
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: page.messages.map((m) =>
                m.id === messageId ? { ...m, deletedAt: now } : m,
              ),
            })),
          }
        },
      )
    },
  })
}
