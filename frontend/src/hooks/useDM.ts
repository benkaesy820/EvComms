import { useEffect, useRef } from 'react'
import { useQuery, useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminDM } from '@/lib/api'
import type { DMConversation } from '@/lib/api'
import { getSocket } from '@/lib/socket'
import { toast } from '@/components/ui/sonner'
import type { DirectMessage } from '@/lib/schemas'
import { useAuthStore } from '@/stores/authStore'
import { audio } from '@/lib/audio'
import { showOsNotification } from '@/lib/notify'

const KEY = (adminId: string) => ['dm', adminId]
export const CONVOS_KEY = ['dm', 'conversations']
const DM_UNREAD_KEY = ['dm', 'unread']

export function useDMConversations() {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: CONVOS_KEY,
    queryFn: () => adminDM.listConversations(),
    staleTime: 0,
  })

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onDM = (data: { message: DirectMessage }) => {
      const currentUserId = useAuthStore.getState().user?.id
      if (!currentUserId) return
      const { message } = data
      const partnerId = message.senderId === currentUserId ? message.recipientId : message.senderId
      const isInbound = message.senderId !== currentUserId

      // Sound: only play for inbound messages
      if (isInbound) {
        // Check if user is actively viewing this exact thread (partner ID is in query param)
        const urlParams = new URLSearchParams(window.location.search)
        const urlPartnerId = urlParams.get('partner')
        const isViewingThisThread = urlPartnerId === partnerId
        const isFocused = document.hasFocus() && isViewingThisThread

        if (isFocused) {
          audio.playPop()
        } else if (isViewingThisThread) {
          audio.playDing()
        } else {
          audio.playDing()
          const senderName = (message.sender as { name?: string })?.name ?? 'Direct Message'
          const preview = message.content
            ? (message.content.length > 60 ? message.content.slice(0, 60) + '\u2026' : message.content)
            : (message.type === 'IMAGE' ? '\ud83d\udcf7 Image' : '\ud83d\udcce File')
          toast(senderName, {
            description: preview,
            action: {
              label: 'View',
              onClick: () => { window.location.href = `/admin/dm/${partnerId}` }
            }
          })
          showOsNotification(senderName, preview, `dm:${partnerId}`, `/admin/dm/${partnerId}`)
        }
      }

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
            // Optimistically insert new conversation instead of full refetch
            const sender = message.sender as { id?: string; name?: string; role?: string } | undefined
            const partnerData = message.senderId === currentUserId
              ? { id: message.recipientId, name: 'Unknown', role: 'ADMIN' }
              : (sender ?? { id: message.senderId, name: 'Unknown', role: 'ADMIN' })
            const newConvo: DMConversation = {
              partner: { id: partnerData.id!, name: partnerData.name ?? 'Unknown', role: (partnerData.role ?? 'ADMIN') as 'ADMIN' | 'SUPER_ADMIN' },
              lastMessage,
              unreadCount: isInbound ? 1 : 0,
            }
            return {
              ...old,
              conversations: [newConvo, ...old.conversations],
            }
          }
          // Don't increment unread if user is actively viewing this exact thread
          const urlParams = new URLSearchParams(window.location.search)
          const urlPartnerId = urlParams.get('partner')
          const isViewingThisThread = urlPartnerId === partnerId
          if (isViewingThisThread) {
            return {
              ...old,
              conversations: old.conversations.map((c) => {
                if (c.partner.id !== partnerId) return c
                return { ...c, lastMessage }
              }),
            }
          }
          return {
            ...old,
            conversations: old.conversations.map((c) => {
              if (c.partner.id !== partnerId) return c
              return {
                ...c,
                lastMessage,
                // Only bump unread if the message came from the other person
                ...(isInbound && { unreadCount: (c.unreadCount ?? 0) + 1 }),
              }
            }),
          }
        },
      )

      // Also update global unread total optimistically
      if (isInbound) {
        queryClient.setQueryData<{ success: boolean; unreadCount: number }>(
          DM_UNREAD_KEY,
          (old) => old ? { ...old, unreadCount: (old.unreadCount ?? 0) + 1 } : old,
        )
      }
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
    queryFn: async ({ pageParam }) => {
      const result = await adminDM.list(adminId!, { before: pageParam as string | undefined, limit: 20 })
      const currentUserId = useAuthStore.getState().user?.id

      // Build a status map from current cache so we never downgrade a tick on refetch
      const cache = queryClient.getQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId!)
      )
      const statusMap = new Map<string, string>()
      if (cache) {
        for (const page of cache.pages) {
          for (const m of page.messages) {
            if (m.status) statusMap.set(m.id, m.status)
          }
        }
      }

      const order: Record<string, number> = { SENT: 1, READ: 2 }

      // Normalize every message — default our own to SENT so the tick always renders.
      // Preserve READ from cache (never downgrade).
      result.messages = result.messages.map(m => {
        const serverStatus = m.status
        const cachedStatus = statusMap.get(m.id)
        const defaultStatus = m.senderId === currentUserId ? 'SENT' : undefined
        const candidates = [serverStatus, cachedStatus, defaultStatus].filter(Boolean) as string[]
        const best = candidates.reduce<string | undefined>((acc, s) => {
          if (!acc) return s
          return (order[s] ?? 0) > (order[acc] ?? 0) ? s : acc
        }, undefined)
        return best ? { ...m, status: best as DirectMessage['status'] } : m
      })

      return result
    },
    getNextPageParam: (last) => {
      if (!last.hasMore) return undefined
      return last.messages[last.messages.length - 1]?.id
    },
    initialPageParam: undefined as string | undefined,
    enabled: !!adminId,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
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

      const currentUserId = useAuthStore.getState().user?.id

      // ── Own message sent — play confirmation sound ────────────────────────────
      if (message.senderId === currentUserId) {
        if (document.hasFocus()) {
          audio.playPop()
        } else {
          audio.playDing()
        }
      }

      // ── Incoming message — play notification sound ────────────────────────────
      // Global useSocket handles the off-page case (playDing + toast + OS banner).
      // Here we cover the on-page cases so the DM thread always gives audio feedback.
      if (message.senderId !== currentUserId) {
        const isOnDMPage = window.location.pathname.startsWith('/admin/dm')
        if (isOnDMPage) {
          if (document.hasFocus()) {
            audio.playPop()
          } else {
            audio.playDing()
            showOsNotification(
              data.message.sender?.name ?? 'Direct Message',
              message.content
                ? (message.content.length > 60 ? message.content.slice(0, 60) + '\u2026' : message.content)
                : '\ud83d\udcce Attachment',
              `dm:${message.senderId}`,
              '/admin/dm'
            )
          }
        }
        // Off-page sound/toast is handled by useSocket's global dm:message handler.
      }

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
            // Default our own messages to SENT so the single tick renders.
            const isOurs = message.senderId === currentUserId
            const enriched: DirectMessage = (isOurs && !message.status)
              ? { ...message, status: 'SENT' as const }
              : message
            return { ...p, messages: exists ? filtered : [enriched, ...filtered] }
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

    // Bulk delete: remove all specified message IDs from the thread cache
    const onBulkDeleted = (data: { adminId: string; ids: string[] }) => {
      if (!adminId) return
      // The event is emitted to both parties; adminId in the payload is the OTHER user
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          const removed = new Set(data.ids)
          return {
            ...old,
            pages: old.pages.map(p => ({
              ...p,
              messages: p.messages.filter(m => !removed.has(m.id)),
            })),
          }
        }
      )
      // Deleted messages may have been unread — re-fetch the badge count so it
      // doesn't stay inflated after the messages are gone from the thread cache.
      queryClient.invalidateQueries({ queryKey: DM_UNREAD_KEY })
    }
    socket.on('dm:messages:bulk_deleted', onBulkDeleted)

    // Partner opened thread → flip our SENT → READ (double blue tick)
    const onRead = (data: { partnerId: string; readAt: number }) => {
      if (data.partnerId !== adminId) return
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map(p => ({
              ...p,
              messages: p.messages.map(m => {
                const currentUser = useAuthStore.getState().user
                // Only upgrade OUR outgoing messages
                if (m.senderId !== currentUser?.id) return m
                if (m.status === 'READ') return m
                return { ...m, status: 'READ' as const }
              }),
            })),
          }
        }
      )
    }

    socket.on('dm:read', onRead)
    return () => {
      socket.off('dm:message', onDM)
      socket.off('dm:message:deleted', onDeleted)
      socket.off('dm:message:reaction', onReaction)
      socket.off('dm:messages:bulk_deleted', onBulkDeleted)
      socket.off('dm:read', onRead)
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
        status: 'SENT',
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
            // Keep SENT — becomes READ when partner reads it
            const confirmed = { ...res.message, status: 'SENT' as const }
            return { ...p, messages: exists ? filtered : [confirmed, ...filtered] }
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

export function useBulkDeleteDM() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ adminId, ids, scope }: { adminId: string; ids: string[]; scope?: 'me' | 'all' }) =>
      adminDM.bulkDelete(adminId, ids, scope).then(r => ({ ...r, adminId })),
    onSuccess: (_, { ids, adminId }) => {
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          const idSet = new Set(ids)
          return {
            ...old,
            pages: old.pages.map(p => ({
              ...p,
              messages: p.messages.filter(m => !idSet.has(m.id))
            }))
          }
        }
      )
      queryClient.invalidateQueries({ queryKey: CONVOS_KEY })
    },
    onError: () => toast.error('Failed to mass delete messages'),
  })
}

export function useClearDM() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ adminId }: { adminId: string }) => adminDM.clear(adminId).then(r => ({ ...r, adminId })),
    onSuccess: (_, { adminId }) => {
      // Optismitically wipe all messages from view
      queryClient.setQueryData<{ pages: Array<{ messages: DirectMessage[]; hasMore: boolean }> }>(
        KEY(adminId),
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map(p => ({ ...p, messages: [] }))
          }
        }
      )
      queryClient.invalidateQueries({ queryKey: CONVOS_KEY })
    },
    onError: () => toast.error('Failed to clear chat history'),
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

/**
 * Hook to get total unread DM count across all conversations.
 * Call this in AdminLayout to get the badge count.
 */
export function useDMUnreadCount() {
  return useQuery({
    queryKey: DM_UNREAD_KEY,
    queryFn: () => adminDM.getUnreadCount(),
    staleTime: 0,
  })
}

/**
 * Call this when an admin opens a DM thread with `adminId`.
 * Immediately zeroes the unread count on that conversation in the list cache
 * and notifies the server.
 */
export function useMarkDMRead(adminId: string | null) {
  const queryClient = useQueryClient()

  useEffect(() => {
    if (!adminId) return

    // Notify server via socket first (instant) then HTTP fallback
    const socket = getSocket()
    if (socket?.connected) {
      socket.emit('dm:mark_read', { partnerId: adminId })
    } else {
      adminDM.markAsRead(adminId).catch(() => { /* fire-and-forget mark-as-read — non-critical */ })
    }

    // Optimistically zero unread badge for this conversation
    queryClient.setQueryData<{ success: boolean; conversations: DMConversation[] }>(
      CONVOS_KEY,
      (old) => {
        if (!old) return old
        const convo = old.conversations.find(c => c.partner.id === adminId)
        const currentUnread = convo?.unreadCount ?? 0
        if (currentUnread > 0) {
          // Decrement global total by the amount we're clearing
          queryClient.setQueryData<{ success: boolean; unreadCount: number }>(
            DM_UNREAD_KEY,
            (old2) => old2 ? { ...old2, unreadCount: Math.max(0, (old2.unreadCount ?? 0) - currentUnread) } : old2,
          )
        }
        return {
          ...old,
          conversations: old.conversations.map((c) =>
            c.partner.id === adminId ? { ...c, unreadCount: 0 } : c
          ),
        }
      }
    )
  }, [adminId, queryClient])
}
