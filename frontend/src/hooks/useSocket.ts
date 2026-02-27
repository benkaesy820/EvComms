import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/authStore'
import { connectSocket, disconnectSocket, getSocket } from '@/lib/socket'
import type { Message } from '@/lib/schemas'
import { toast } from 'sonner'

export function useSocketConnection() {
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const reset = useAuthStore((s) => s.reset)
  const setUser = useAuthStore((s) => s.setUser)
  const queryClient = useQueryClient()

  const userId = user?.id

  useEffect(() => {
    if (!isAuthenticated || !userId) {
      disconnectSocket()
      return
    }

    const socket = connectSocket()

    socket.on('auth_error', () => {
      toast.error('Session expired. Please login again.')
      reset()
    })

    socket.on('session:revoked', (data) => {
      toast.error(data.reason || 'Session has been revoked')
      reset()
    })

    socket.on('message:new', (data) => {
      const msg = data.message
      // If this is a message from admin to user, optimistically bump unreadCount in user's conversation cache
      const currentUser = useAuthStore.getState().user
      if (currentUser?.role === 'USER' && msg.senderId !== currentUser.id) {
        queryClient.setQueryData<{ success: boolean; conversation: { unreadCount: number; lastMessageAt: number | null;[key: string]: unknown } | null }>(['conversation'],
          (old) => {
            if (!old?.conversation) return old
            return { ...old, conversation: { ...old.conversation, unreadCount: (old.conversation.unreadCount ?? 0) + 1, lastMessageAt: Date.now() } }
          }
        )
      }
      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', msg.conversationId],
        (old) => {
          if (!old || old.pages.length === 0) return old
          const exists = old.pages.some((p) => p.messages.some((m) => m.id === msg.id))
          if (exists) return old
          const firstPage = old.pages[0]
          return {
            ...old,
            pages: [
              { ...firstPage, messages: [...firstPage.messages, msg] },
              ...old.pages.slice(1),
            ],
          }
        },
      )
    })

    socket.on('message:sent', (data) => {
      const convId = data.message.conversationId
      const tempId = data.tempId

      const replaceTemp = (old: { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] } | undefined) => {
        if (!old) return { updated: undefined, found: false }
        let found = false
        const updated = {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: page.messages.map((m) => {
              if (m.id === tempId) {
                found = true
                return { ...m, ...data.message }
              }
              return m
            }),
          })),
        }
        return { updated, found }
      }

      const cacheData = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', convId]
      )
      const { updated, found } = replaceTemp(cacheData)

      if (found && updated) {
        queryClient.setQueryData(['messages', convId], updated)
      } else if (tempId) {
        const undefinedCache = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
          ['messages', undefined]
        )
        if (undefinedCache) {
          const { updated: undefinedUpdated, found: foundInUndefined } = replaceTemp(undefinedCache)
          if (foundInUndefined && undefinedUpdated) {
            queryClient.setQueryData(['messages', undefined], {
              ...undefinedUpdated,
              pages: undefinedUpdated.pages.map((page) => ({
                ...page,
                messages: page.messages.filter((m) => m.id !== tempId),
              })),
            })
            const newCache = queryClient.getQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
              ['messages', convId]
            )
            if (newCache) {
              queryClient.setQueryData(['messages', convId], {
                ...newCache,
                pages: newCache.pages.map((page, idx) =>
                  idx === 0
                    ? { ...page, messages: [...page.messages, data.message] }
                    : page
                ),
              })
            } else {
              queryClient.setQueryData(['messages', convId], {
                pages: [{ success: true, messages: [data.message], hasMore: false }],
                pageParams: [],
              })
            }
          }
        }
      }

      if (!tempId) {
        queryClient.invalidateQueries({ queryKey: ['messages', convId] })
      }
    })

    socket.on('message:deleted', (data) => {
      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', data.conversationId],
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: page.messages.map((m) =>
                m.id === data.messageId ? { ...m, deletedAt: data.deletedAt } : m,
              ),
            })),
          }
        },
      )
    })

    socket.on('messages:read', (data) => {
      queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        ['messages', data.conversationId],
        (old) => {
          if (!old) return old
          const readSet = data.messageIds ? new Set(data.messageIds) : null
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: page.messages.map((m) =>
                (readSet ? readSet.has(m.id) : m.status === 'SENT')
                  ? { ...m, status: 'READ' as const, readAt: data.readAt }
                  : m,
              ),
            })),
          }
        },
      )
    })

    socket.on('conversation:updated', (data) => {
      // Update admin conversations list
      const existing = queryClient.getQueryData<{ pages: Array<{ conversations: Array<{ id: string }> }> }>(['conversations'])
      const wasFound = existing?.pages.some(page => page.conversations.some(c => c.id === data.conversationId))

      if (!wasFound && existing) {
        // Brand-new conversation (first message from a new user) — refetch so it appears in the list
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
      }

      queryClient.setQueryData<{ pages: Array<{ success: boolean; conversations: Array<{ id: string; lastMessageAt: number | null | undefined; lastMessage?: Message | null; unreadCount: number;[key: string]: unknown }>; hasMore: boolean }>; pageParams: unknown[] }>(
        ['conversations'],
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              conversations: page.conversations.map((c) =>
                c.id === data.conversationId
                  ? {
                    ...c,
                    lastMessageAt: data.lastMessageAt,
                    lastMessage: data.lastMessage,
                    ...(data.unreadCount !== undefined && { unreadCount: data.unreadCount }),
                    ...(data.adminUnreadCount !== undefined && { adminUnreadCount: data.adminUnreadCount }),
                  }
                  : c,
              ),
            })),
          }
        },
      )
      // Update user's own conversation cache (unreadCount driven by admin-side event)
      queryClient.setQueryData<{ success: boolean; conversation: { id: string; unreadCount: number; lastMessageAt: number | null | undefined;[key: string]: unknown } | null }>(
        ['conversation'],
        (old) => {
          if (!old?.conversation || old.conversation.id !== data.conversationId) return old
          return {
            ...old,
            conversation: {
              ...old.conversation,
              lastMessageAt: data.lastMessageAt,
              ...(data.unreadCount !== undefined && { unreadCount: data.unreadCount }),
            },
          }
        },
      )
    })

    socket.on('user:status_changed', (data) => {
      const u = useAuthStore.getState().user
      if (u) {
        setUser({ ...u, status: data.status })
      }
      if (data.status === 'SUSPENDED') {
        toast.error('Your account has been suspended.')
      } else if (data.status === 'APPROVED') {
        toast.success('Your account has been approved!')
      }
    })

    socket.on('user:media_permission_changed', (data) => {
      const u = useAuthStore.getState().user
      if (u) {
        setUser({ ...u, mediaPermission: data.mediaPermission })
      }
    })

    socket.on('admin:user_registered', () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast.info('New user registered!')
    })

    socket.on('preferences:updated', (data) => {
      const u = useAuthStore.getState().user
      if (u) {
        setUser({ ...u, emailNotifyOnMessage: data.emailNotifyOnMessage })
      }
    })

    socket.on('announcement:new', (data) => {
      if (data.announcement) {
        queryClient.setQueriesData<{ success: boolean; announcements: unknown[] }>(
          { queryKey: ['announcements'] },
          (old) => {
            if (!old) return old
            return { ...old, announcements: [data.announcement, ...old.announcements] }
          },
        )
      } else {
        queryClient.invalidateQueries({ queryKey: ['announcements'] })
      }
      if (data.announcement?.title) {
        toast.info(`📢 ${data.announcement.title}`)
      }
    })

    socket.on('announcement:updated', (data) => {
      if (!data.announcement) {
        queryClient.invalidateQueries({ queryKey: ['announcements'] })
        return
      }
      const ann = data.announcement
      const currentUser = useAuthStore.getState().user
      const isAdmin = currentUser?.role === 'ADMIN' || currentUser?.role === 'SUPER_ADMIN'

      queryClient.setQueriesData<{ success: boolean; announcements: unknown[]; hasMore: boolean }>(
        { queryKey: ['announcements'] },
        (old) => {
          if (!old) return old
          if (isAdmin) {
            // Admins: update the item in-place (includeInactive queries will show it anyway)
            return {
              ...old,
              announcements: old.announcements.map((a) => {
                const announcement = a as { id: string }
                return announcement.id === ann.id ? ann : a
              }),
            }
          }
          // Non-admin users: remove the item if it's now inactive or expired
          const now = Date.now()
          const visible =
            ann.isActive &&
            (!ann.expiresAt || new Date(ann.expiresAt).getTime() > now) &&
            (!ann.targetRoles || (ann.targetRoles as string[]).includes(currentUser?.role ?? ''))
          return {
            ...old,
            announcements: visible
              ? old.announcements.map((a) => {
                const announcement = a as { id: string }
                return announcement.id === ann.id ? ann : a
              })
              : old.announcements.filter((a) => (a as { id: string }).id !== ann.id),
          }
        },
      )
      // Also update the single-announcement detail cache if open
      queryClient.setQueryData<{ success: boolean; announcement: unknown }>(
        ['announcement', ann.id],
        (old) => old ? { ...old, announcement: ann } : old,
      )
    })

    socket.on('message:reaction', (data) => {
      const updatePage = (old: { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] } | undefined) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: page.messages.map((m) => {
              if (m.id !== data.messageId) return m
              const reactions = m.reactions ? [...m.reactions] : []
              if (data.action === 'remove') {
                const r = data.reaction as { userId: string; emoji: string }
                return { ...m, reactions: reactions.filter((x) => !(x.userId === r.userId && x.emoji === r.emoji)) }
              }
              const newR = data.reaction as import('@/lib/schemas').MessageReaction
              return { ...m, reactions: reactions.some((x) => x.id === newR.id) ? reactions : [...reactions, newR] }
            }),
          })),
        }
      }
      queryClient.setQueriesData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
        { queryKey: ['messages'] },
        updatePage,
      )
    })

    socket.on('cache:invalidate', (data) => {
      data.keys.forEach((key) => {
        queryClient.invalidateQueries({ queryKey: [key] })
      })
    })

    return () => {
      socket.removeAllListeners()
      disconnectSocket()
    }
  }, [isAuthenticated, userId, queryClient, reset, setUser])

  return getSocket()
}
