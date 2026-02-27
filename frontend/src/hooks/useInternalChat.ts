import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { adminInternal } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import type { InternalMessage } from '@/lib/schemas'
import { toast } from 'sonner'

const KEY = ['internal-messages'] as const

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
          pages: old.pages.map((page, i) =>
            i === 0 ? { ...page, messages: [data.message, ...page.messages] } : page
          ),
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

    socket.on('internal:message', onNew)
    socket.on('internal:message:deleted', onDeleted)
    socket.on('internal:chat:cleared', onCleared)
    socket.on('internal:message:reaction', onReaction)
    return () => {
      socket.off('internal:message', onNew)
      socket.off('internal:message:deleted', onDeleted)
      socket.off('internal:chat:cleared', onCleared)
      socket.off('internal:message:reaction', onReaction)
    }
  }, [queryClient])

  return useInfiniteQuery({
    queryKey: KEY,
    queryFn: ({ pageParam }) =>
      adminInternal.list({ limit: 20, before: pageParam as string | undefined }),
    getNextPageParam: (last) => {
      if (!last.hasMore) return undefined
      return last.messages[last.messages.length - 1]?.id
    },
    initialPageParam: undefined as string | undefined,
    staleTime: 30_000,
  })
}

export function useSendInternalMessage() {
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
      const socket = getSocket()
      const msgType = vars.type ?? 'TEXT'
      // For socket TEXT path: rely on server broadcast; no optimistic needed
      if (socket?.connected && msgType === 'TEXT') return

      // Optimistic for HTTP path (media or fallback)
      const tempMsg: InternalMessage = {
        id: vars.tempId,
        senderId: '__optimistic__',
        sender: { id: '__optimistic__', name: 'You', role: 'ADMIN' },
        type: (vars.type as InternalMessage['type']) ?? 'TEXT',
        content: vars.content ?? null,
        media: null,
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
            return { ...page, messages: exists ? filtered : [result.message, ...filtered] }
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
