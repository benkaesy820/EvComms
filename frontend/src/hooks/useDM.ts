import { useEffect, useRef } from 'react'
import { useQuery, useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminDM } from '@/lib/api'
import type { DMConversation } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import { toast } from 'sonner'
import type { DirectMessage } from '@/lib/schemas'
import { useAuthStore } from '@/stores/authStore'

const KEY = (adminId: string) => ['dm', adminId]
const CONVOS_KEY = ['dm', 'conversations']

export function useDMConversations() {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: CONVOS_KEY,
    queryFn: () => adminDM.listConversations(),
    staleTime: 30_000,
  })

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onDM = (data: { message: DirectMessage }) => {
      const currentUserId = useAuthStore.getState().user?.id
      if (!currentUserId) return
      const { message } = data
      const partnerId = message.senderId === currentUserId ? message.recipientId : message.senderId
      const lastMessage = {
        id: message.id,
        content: message.content,
        type: message.type,
        senderId: message.senderId,
        createdAt: typeof message.createdAt === 'number' ? message.createdAt : new Date(message.createdAt).getTime(),
      }
      queryClient.setQueryData<{ success: boolean; conversations: DMConversation[] }>(
        CONVOS_KEY,
        (old) => {
          if (!old) return old
          const exists = old.conversations.some((c) => c.partner.id === partnerId)
          if (!exists) {
            queryClient.invalidateQueries({ queryKey: CONVOS_KEY })
            return old
          }
          return {
            ...old,
            conversations: old.conversations.map((c) =>
              c.partner.id === partnerId ? { ...c, lastMessage } : c
            ),
          }
        },
      )
    }
    socket.on('dm:message', onDM)
    return () => { socket.off('dm:message', onDM) }
  }, [queryClient])

  return query
}

export function useDMMessages(adminId: string | null) {
  const queryClient = useQueryClient()

  const query = useInfiniteQuery({
    queryKey: adminId ? KEY(adminId) : ['dm', '__none__'],
    queryFn: ({ pageParam }) =>
      adminDM.list(adminId!, { before: pageParam as string | undefined, limit: 20 }),
    getNextPageParam: (last) => {
      if (!last.hasMore) return undefined
      return last.messages[last.messages.length - 1]?.id
    },
    initialPageParam: undefined as string | undefined,
    enabled: !!adminId,
    staleTime: 30_000,
  })

  useEffect(() => {
    if (!adminId) return
    const socket = getSocket()
    if (!socket) return

    const onDM = (data: { message: DirectMessage; tempId?: string }) => {
      const { message, tempId } = data
      const isInThread =
        message.senderId === adminId || message.recipientId === adminId
      if (!isInThread) return

      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          const pages = old.pages.map((p, i) => {
            if (i !== 0) return p
            const filtered = tempId
              ? p.messages.filter(m => m.id !== tempId)
              : p.messages
            const exists = filtered.some(m => m.id === message.id)
            return { ...p, messages: exists ? filtered : [message, ...filtered] }
          })
          return { ...old, pages }
        }
      )
    }

    const onDeleted = (data: { messageId: string }) => {
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map(p => ({
              ...p,
              messages: p.messages.filter(m => m.id !== data.messageId),
            })),
          }
        }
      )
    }

    type ReactionEntry = { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } }
    const onReaction = (data: { adminId: string; messageId: string; type: 'add' | 'remove'; reaction: ReactionEntry }) => {
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map(p => ({
              ...p,
              messages: p.messages.map(m => {
                if (m.id !== data.messageId) return m
                const reactions: ReactionEntry[] = (m.reactions as ReactionEntry[] | null) ?? []
                if (data.type === 'add') {
                  return { ...m, reactions: [...reactions.filter(r => r.userId !== data.reaction.userId), data.reaction] }
                } else {
                  return { ...m, reactions: reactions.filter(r => !(r.userId === data.reaction.userId && r.emoji === data.reaction.emoji)) }
                }
              })
            }))
          }
        }
      )
    }

    socket.on('dm:message', onDM)
    socket.on('dm:message:deleted', onDeleted)
    socket.on('dm:message:reaction', onReaction)
    return () => {
      socket.off('dm:message', onDM)
      socket.off('dm:message:deleted', onDeleted)
      socket.off('dm:message:reaction', onReaction)
    }
  }, [adminId, queryClient])

  return query
}

export function useSendDM(adminId: string | null) {
  const queryClient = useQueryClient()
  const tempCounter = useRef(0)
  const tempIdRef = useRef('')

  return useMutation({
    mutationFn: (data: { content?: string; type?: string; mediaId?: string; replyToId?: string }) => {
      if (!adminId) throw new Error('No admin selected')
      // onMutate runs before mutationFn — read the tempId it already stored
      const tempId = tempIdRef.current
      return adminDM.send(adminId, { ...data, tempId })
    },
    onMutate: async (data) => {
      if (!adminId) return
      const currentUser = useAuthStore.getState().user
      if (!currentUser) return
      // Generate here (onMutate runs first) and store for mutationFn to consume
      const tempId = `temp-dm-${Date.now()}-${tempCounter.current++}`
      tempIdRef.current = tempId
      const optimistic: DirectMessage = {
        id: tempId,
        senderId: currentUser.id,
        recipientId: adminId,
        sender: { id: currentUser.id, name: currentUser.name, role: currentUser.role },
        type: (data.type ?? 'TEXT') as DirectMessage['type'],
        content: data.content ?? null,
        media: null,
        replyToId: data.replyToId ?? null,
        replyTo: null,
        createdAt: new Date().toISOString(),
        deletedAt: null,
      }
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          return { ...old, pages: old.pages.map((p, i) => i === 0 ? { ...p, messages: [optimistic, ...p.messages] } : p) }
        }
      )
      return { tempId }
    },
    onError: (_err, _data, context) => {
      if (context?.tempId && adminId) {
        queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
          KEY(adminId),
          (old) => old ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter(m => m.id !== context.tempId) })) } : old
        )
      }
      toast.error('Failed to send message')
    },
    onSuccess: (res, _data, context) => {
      if (!adminId) return
      const tempId = context?.tempId
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          const pages = old.pages.map((p, i) => {
            if (i !== 0) return p
            const filtered = tempId ? p.messages.filter(m => m.id !== tempId) : p.messages
            const exists = filtered.some(m => m.id === res.message.id)
            return { ...p, messages: exists ? filtered : [res.message, ...filtered] }
          })
          return { ...old, pages }
        }
      )
    },
  })
}

export function useDeleteDM() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ messageId, adminId, scope }: { messageId: string; adminId: string; scope?: 'me' | 'all' }) =>
      adminDM.deleteMessage(messageId, scope).then(r => ({ ...r, adminId })),
    onSuccess: (_, { messageId, adminId }) => {
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => old
          ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter(m => m.id !== messageId) })) }
          : old
      )
    },
    onError: () => toast.error('Failed to delete message'),
  })
}

export function useDMReaction(adminId: string | null) {
  return useMutation({
    mutationFn: ({ messageId, emoji, action }: { messageId: string; emoji: string; action: 'add' | 'remove' }) => {
      if (!adminId) throw new Error('No admin selected')
      if (action === 'add') {
        return adminDM.react(adminId, messageId, emoji)
      } else {
        return adminDM.removeReaction(adminId, messageId, emoji)
      }
    },
    onError: () => toast.error('Failed to update reaction'),
  })
}
