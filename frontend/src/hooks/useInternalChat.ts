import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { adminInternal } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import type { InternalMessage } from '@/lib/schemas'
import { toast } from '@/components/ui/sonner'
import { useAuthStore } from '@/stores/authStore'

const KEY = ['internal-messages'] as const
export const INTERNAL_UNREAD_KEY = ['internal', 'unread'] as const

export function useInternalMessages() {
  const queryClient = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const onNew = (data: { message: InternalMessage }) => {
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page, i) => {
            if (i !== 0) return page
            const currentUserId = useAuthStore.getState().user?.id
            const isOurs = data.message.senderId === currentUserId
            const enriched = (isOurs && !data.message.status) ? { ...data.message, status: 'SENT' as const } : data.message
            return { ...page, messages: [enriched, ...page.messages] }
          }),
        }
      })
    }

    const onDeleted = (data: { id: string }) => {
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: page.messages.filter((m) => m.id !== data.id),
          })),
        }
      })
    }

    const onCleared = (data: { scope: string }) => {
      if (data.scope === 'all') {
        queryClient.setQueryData(KEY, () => ({ pages: [{ success: true, messages: [], hasMore: false }], pageParams: [undefined] }))
      } else {
        queryClient.invalidateQueries({ queryKey: KEY })
      }
    }

    type ReactionEntry = { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } }
    const onReaction = (data: { type: 'add' | 'remove'; reaction: ReactionEntry }) => {
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: page.messages.map((m) => {
              if (m.id !== data.reaction.messageId) return m
              const reactions: ReactionEntry[] = (m.reactions as ReactionEntry[] | null) ?? []
              if (data.type === 'add') {
                return { ...m, reactions: [...reactions.filter(r => r.userId !== data.reaction.userId), data.reaction] }
              } else {
                return { ...m, reactions: reactions.filter(r => !(r.userId === data.reaction.userId && r.emoji === data.reaction.emoji)) }
              }
            })
          }))
        }
      })
    }

    // Handle the server's echo back to the sender when a TEXT message is sent via socket.
    // The main broadcast `internal:message` goes to all admins (including the sender's other tabs),
    // but `internal:message:sent` is targeted only at the emitting socket — use it to instantly
    // commit the real message on the sender's current tab without waiting for the broadcast echo.
    const onSent = (data: { tempId?: string; message: InternalMessage }) => {
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page, i) => {
            if (i !== 0) return page
            // Remove temp stub if present, then prepend the authoritative message
            const filtered = data.tempId
              ? page.messages.filter((m) => m.id !== data.tempId)
              : page.messages
            const exists = filtered.some((m) => m.id === data.message.id)
            const enriched = !data.message.status ? { ...data.message, status: 'SENT' as const } : data.message
            return { ...page, messages: exists ? filtered : [enriched, ...filtered] }
          }),
        }
      })
    }

    socket.on('internal:message', onNew)
    socket.on('internal:message:sent', onSent)
    socket.on('internal:message:deleted', onDeleted)
    socket.on('internal:chat:cleared', onCleared)
    socket.on('internal:message:reaction', onReaction)

    // Group read receipts: when any admin reads the chat, update readBy arrays
    // Blue double-tick fires when readBy.length >= (groupSize - 1)
    const onReadReceipt = (data: { userId: string; readAt: number }) => {
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: page.messages.map((m) => {
              const existing: string[] = (m as any).readBy ?? []
              if (existing.includes(data.userId)) return m
              return { ...m, readBy: [...existing, data.userId] }
            }),
          })),
        }
      })
    }

    socket.on('internal:read_receipt', onReadReceipt)
    return () => {
      socket.off('internal:message', onNew)
      socket.off('internal:message:sent', onSent)
      socket.off('internal:message:deleted', onDeleted)
      socket.off('internal:chat:cleared', onCleared)
      socket.off('internal:message:reaction', onReaction)
      socket.off('internal:read_receipt', onReadReceipt)
    }
  }, [queryClient])

  return useInfiniteQuery({
    queryKey: KEY,
    queryFn: async ({ pageParam }) => {
      const result = await adminInternal.list({ limit: 20, before: pageParam as string | undefined })
      const currentUserId = useAuthStore.getState().user?.id

      // Build status + readBy map from current cache
      const cache = queryClient.getQueryData<{
        pages: Array<{ messages: InternalMessage[]; hasMore: boolean }>
      }>(KEY)
      const metaMap = new Map<string, { status?: string; readBy?: string[] }>()
      if (cache) {
        for (const page of cache.pages) {
          for (const m of page.messages) {
            if (m.status || (m as any).readBy) {
              metaMap.set(m.id, { status: m.status, readBy: (m as any).readBy })
            }
          }
        }
      }

      const order: Record<string, number> = { SENT: 1, READ: 2 }

      result.messages = result.messages.map(m => {
        const cached = metaMap.get(m.id)
        const serverStatus = m.status
        const cachedStatus = cached?.status
        const defaultStatus = m.senderId === currentUserId ? 'SENT' : undefined
        const candidates = [serverStatus, cachedStatus, defaultStatus].filter(Boolean) as string[]
        const best = candidates.reduce<string | undefined>((acc, s) => {
          if (!acc) return s
          return (order[s] ?? 0) > (order[acc] ?? 0) ? s : acc
        }, undefined)
        return {
          ...m,
          ...(best ? { status: best as InternalMessage['status'] } : {}),
          ...(cached?.readBy ? { readBy: cached.readBy } : {}),
        }
      })

      return result
    },
    getNextPageParam: (last) => {
      if (!last.hasMore) return undefined
      return last.messages[last.messages.length - 1]?.id
    },
    initialPageParam: undefined as string | undefined,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  })
}

export function useSendInternalMessage(currentUser: { id: string; name: string; role: string } | null) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (vars: { type?: string; content?: string; mediaId?: string; replyToId?: string; tempId: string }) => {
      const socket = getSocket()
      const msgType = vars.type ?? 'TEXT'
      // Use HTTP for media messages so we get immediate cache update with CDN URL
      if (socket?.connected && msgType === 'TEXT') {
        socket.emit('internal:message:send', {
          type: msgType,
          content: vars.content,
          mediaId: vars.mediaId,
          replyToId: vars.replyToId,
          tempId: vars.tempId,
        } as any)
        return Promise.resolve(null as null)
      }
      return adminInternal.send({ type: msgType, content: vars.content, mediaId: vars.mediaId, replyToId: vars.replyToId })
    },
    onMutate: async (vars) => {
      const msgType = vars.type ?? 'TEXT'

      // Optimistic stub for ALL paths — gives the sender immediate visual feedback (LeafLogo spin)
      // For socket TEXT messages the stub is replaced when internal:message:sent fires.
      // For HTTP (media) it stays until onSuccess commits the real record.
      const tempMsg: InternalMessage = {
        id: vars.tempId,
        senderId: currentUser?.id ?? '__optimistic__',
        sender: {
          id: currentUser?.id ?? '__optimistic__',
          name: currentUser?.name ?? 'You',
          role: (currentUser?.role ?? 'ADMIN') as InternalMessage['sender']['role'],
        },
        type: (vars.type as InternalMessage['type']) ?? 'TEXT',
        content: vars.content ?? null,
        media: null,
        status: 'SENT',
        replyToId: vars.replyToId ?? null,
        replyTo: null,
        createdAt: new Date().toISOString(),
      }
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return { ...old, pages: old.pages.map((page, i) => i === 0 ? { ...page, messages: [tempMsg, ...page.messages] } : page) }
      })

      // For socket TEXT path the server will replace this stub via internal:message:sent
      // For HTTP path we need to do it in onSuccess
      if (msgType !== 'TEXT') return // only HTTP path needs onSuccess cleanup via returning context
    },
    onSuccess: (result, vars) => {
      if (!result) return // socket path — server will broadcast internal:message
      // HTTP path: replace optimistic with real message
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page, i) => {
            if (i !== 0) return page
            const filtered = page.messages.filter(m => m.id !== vars.tempId)
            const exists = filtered.some(m => m.id === result.message.id)
            const enriched = !result.message.status ? { ...result.message, status: 'SENT' as const } : result.message
            return { ...page, messages: exists ? filtered : [enriched, ...filtered] }
          }),
        }
      })
    },
    onError: () => {
      toast.error('Failed to send message')
    },
  })
}

export function useDeleteInternalMessage() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, scope }: { id: string; scope: 'me' | 'all' }) => adminInternal.delete(id, scope),
    onSuccess: (_data, { id }) => {
      // Remove from local cache immediately (for both scope=me and scope=all)
      queryClient.setQueryData<{
        pages: Array<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>
        pageParams: unknown[]
      }>(KEY, (old) => {
        if (!old) return old
        return { ...old, pages: old.pages.map((page) => ({ ...page, messages: page.messages.filter((m) => m.id !== id) })) }
      })
    },
    onError: () => toast.error('Failed to delete message'),
  })
}

export function useClearInternalChat() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => adminInternal.clear(),
    onSuccess: () => {
      queryClient.setQueryData(KEY, () => ({ pages: [{ success: true, messages: [], hasMore: false }], pageParams: [undefined] }))
    },
    onError: () => toast.error('Failed to clear chat'),
  })
}

export function useInternalReaction() {
  return useMutation({
    mutationFn: ({ messageId, emoji, action }: { messageId: string; emoji: string; action: 'add' | 'remove' }) => {
      if (action === 'add') {
        return adminInternal.react(messageId, emoji)
      } else {
        return adminInternal.removeReaction(messageId, emoji)
      }
    },
    onError: () => {
      toast.error('Failed to update reaction')
    },
  })
}

/**
 * Hook to get total unread internal message count.
 * Call this in AdminLayout to get the badge count.
 */
export function useInternalUnreadCount() {
  return useQuery({
    queryKey: INTERNAL_UNREAD_KEY,
    queryFn: () => adminInternal.getUnreadCount(),
    staleTime: 0,
  })
}

/**
 * Mark internal messages as read and update the unread count.
 */
export function useMarkInternalRead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => adminInternal.markAsRead(),
    onSuccess: () => {
      // Update cache to show 0 unread
      queryClient.setQueryData<{ success: boolean; unreadCount: number }>(
        INTERNAL_UNREAD_KEY,
        (_old) => ({ success: true, unreadCount: 0 })
      )
    },
    onError: () => { /* ignore */ },
  })
}

/**
 * Emit internal:mark_read via socket so the server broadcasts a read_receipt
 * to all other admins — enabling group blue-tick logic.
 * Call this when the InternalChatPage mounts / becomes visible.
 */
export function useEmitInternalRead() {
  useEffect(() => {
    const socket = getSocket()
    if (socket?.connected) {
      socket.emit('internal:mark_read')
    }
    // Also re-emit whenever the socket reconnects
    const onConnect = () => socket?.emit('internal:mark_read')
    socket?.on('connect', onConnect)
    return () => { socket?.off('connect', onConnect) }
  }, [])
}
