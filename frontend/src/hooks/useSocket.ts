import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/authStore'
import { connectSocket, disconnectSocket, getSocket } from '@/lib/socket'
import type { Message } from '@/lib/schemas'
import { auth as authApi } from '@/lib/api'
import { toast } from '@/components/ui/sonner'
import { audio } from '@/lib/audio'

export function useSocketConnection() {
  const user = useAuthStore((s) => s.user)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const reset = useAuthStore((s) => s.reset)
  const setUser = useAuthStore((s) => s.setUser)
  const queryClient = useQueryClient()

  const userId = user?.id

  // Stable refs for callbacks — avoids adding them to the effect dep array
  // which would force a reconnect/re-register every time the store reference changes
  const resetRef = useRef(reset)
  const setUserRef = useRef(setUser)
  useEffect(() => { resetRef.current = reset }, [reset])
  useEffect(() => { setUserRef.current = setUser }, [setUser])

  useEffect(() => {
    if (!isAuthenticated || !userId) {
      disconnectSocket()
      return
    }

    const socket = connectSocket()

    socket.on('connect_error', async (err) => {
      // PENDING users get NOT_APPROVED from socket auth.  They should not be
      // attempting to connect in the first place (login() now guards this), but
      // handle it defensively: stop reconnecting silently — no toast, no logout.
      if (err.message === 'NOT_APPROVED') {
        socket.disconnect()
        return
      }

      if (
        err.message === 'TOKEN_EXPIRED' ||
        err.message === 'INVALID_TOKEN' ||
        err.message === 'AUTH_FAILED' ||
        // NO_TOKEN: cookie missing from handshake (race on page load / hard refresh)
        // SESSION_INVALID: session was revoked between socket connects
        // TOKEN_STALE: role/status changed since last token issue
        err.message === 'NO_TOKEN' ||
        err.message === 'SESSION_INVALID' ||
        err.message === 'TOKEN_STALE'
      ) {
        try {
          // Pause Socket.IO's automatic reconnection while we refresh
          socket.disconnect()

          // SECURITY FIX: No token passed - read from httpOnly cookie
          const refreshRes = await authApi.refresh()
          setUserRef.current(refreshRes.user)

          // Token is now updated in local storage and authStore state
          // Reconnect the socket (which will now use the new token via our dynamic cb)
          socket.connect()
        } catch (refreshErr) {
          // If refresh fails, the session is truly dead
          toast.error('Session expired. Please login again.')
          resetRef.current()
        }
      }
    })

    socket.on('auth_error', () => {
      audio.playError()
      toast.error('Session expired. Please login again.')
      resetRef.current()
    })

    socket.on('session:revoked', (data) => {
      audio.playError()
      toast.error(data.reason || 'Session has been revoked')
      resetRef.current()
    })

    socket.on('force_logout', (data) => {
      audio.playError()
      toast.error(data.reason || 'You have been logged out')
      resetRef.current()
    })

    socket.on('message:new', (data) => {
      const msg = data.message
      const currentUser = useAuthStore.getState().user

      // Sound and intelligent Notification logic
      if (currentUser && msg.senderId !== currentUser.id) {
        const isUserOnChatPage = currentUser.role === 'USER' && window.location.pathname.includes('/chat')
        const isAdminOnChatPage = currentUser.role !== 'USER' && window.location.pathname === '/admin'
        const isOnChatPage = isUserOnChatPage || isAdminOnChatPage

        const isFocusingThisChat = document.hasFocus() && isOnChatPage && (
          currentUser.role === 'USER' ||
          localStorage.getItem('admin-selected-conversation') === msg.conversationId
        )

        if (isFocusingThisChat) {
          // Soft interaction sound - actively looking at this exact thread
          audio.playPop()
        } else if (isOnChatPage) {
          // On the chat page but looking elsewhere (or unfocused). No toast to prevent clutter,
          // because the sidebar will naturally show the new unread badge. Just play the sound.
          audio.playDing()
        } else {
          // Completely off the chat page (e.g., Settings, Users list)
          // Background/unfocused sound + clickable Toast
          audio.playDing()
          toast(msg.sender?.name || 'New Message', {
            description: msg.content ? (msg.content.length > 50 ? msg.content.slice(0, 50) + '...' : msg.content) : 'Sent an attachment',
            action: {
              label: 'View',
              onClick: () => {
                if (currentUser.role === 'USER') {
                  window.location.href = '/home/chat'
                } else {
                  localStorage.setItem('admin-selected-conversation', msg.conversationId)
                  window.location.href = '/admin'
                }
              }
            }
          })
        }
      }

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
              { ...firstPage, messages: [msg, ...firstPage.messages] },
              ...old.pages.slice(1),
            ],
          }
        },
      )
    })

    socket.on('message:sent', (data) => {
      // Soft outgoing confirmation sound
      audio.playPop()

      const convId = data.message.conversationId
      const tempId = data.tempId

      // Dedup: after replacing temp, remove any other entry with the same real id
      // (message:new can arrive before message:sent and pre-add the real message)
      const dedup = (msgs: Message[]) => {
        const seen = new Set<string>()
        return msgs.filter(m => { if (seen.has(m.id)) return false; seen.add(m.id); return true })
      }

      const replaceTemp = (old: { pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] } | undefined) => {
        if (!old) return { updated: undefined, found: false }
        let found = false
        const updated = {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            messages: dedup(page.messages.map((m) => {
              if (m.id === tempId) {
                found = true
                // Server confirmed receipt — stays SENT until recipient reads
                return { ...m, ...data.message, status: 'SENT' as const }
              }
              return m
            })),
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
                    ? { ...page, messages: dedup([data.message, ...page.messages]) }
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
        } else {
          // Safety net: tempId not found in either cache — this happens when a background
          // HTTP refetch (triggered by staleTime:0 when useMessages activates) returned
          // before the socket message was saved, wiping the optimistic entry.
          // Inject the confirmed real message directly so it's never lost from the UI.
          queryClient.setQueryData<{ pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>; pageParams: unknown[] }>(
            ['messages', convId],
            (old) => {
              const alreadyExists = old?.pages.some((p) => p.messages.some((m) => m.id === data.message.id))
              if (alreadyExists) return old
              if (!old || old.pages.length === 0) {
                return { pages: [{ success: true, messages: [data.message], hasMore: false }], pageParams: [undefined] }
              }
              const firstPage = old.pages[0]
              return {
                ...old,
                pages: [
                  { ...firstPage, messages: dedup([data.message, ...firstPage.messages]) },
                  ...old.pages.slice(1),
                ],
              }
            }
          )
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
          // Mark all SENT messages as READ when recipient reads.
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: page.messages.map((m) =>
                m.status === 'SENT'
                  ? { ...m, status: 'READ' as const, readAt: data.readAt }
                  : m,
              ),
            })),
          }
        },
      )
    })

    socket.on('conversation:updated', (data) => {
      // Check if this conversation exists in ANY conversations cache variant
      // (archived:false, archived:true, etc.) using partial key match
      const allConvCaches = queryClient.getQueriesData<{ pages: Array<{ conversations: Array<{ id: string }> }> }>(
        { queryKey: ['conversations'] }
      )
      const wasFound = allConvCaches.some(([, cacheData]) =>
        cacheData?.pages?.some(page => page.conversations?.some(c => c.id === data.conversationId))
      )

      if (!wasFound) {
        // Brand-new conversation appearing for the first time — refetch all variants
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
      }

      // Update ALL conversations cache variants (archived:false, archived:true, etc.)
      queryClient.setQueriesData<{ pages: Array<{ success: boolean; conversations: Array<{ id: string; lastMessageAt: number | null | undefined; lastMessage?: Message | null; unreadCount: number;[key: string]: unknown }>; hasMore: boolean }>; pageParams: unknown[] }>(
        { queryKey: ['conversations'] },
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
                    ...(data.lastMessageAt !== undefined && { lastMessageAt: data.lastMessageAt }),
                    ...(data.lastMessage !== undefined && { lastMessage: data.lastMessage }),
                    ...(data.unreadCount !== undefined && { unreadCount: data.unreadCount }),
                    ...(data.adminUnreadCount !== undefined && { adminUnreadCount: data.adminUnreadCount }),
                    // FIX: also propagate waitingSince (clears waiting badge when admin replies)
                    // and assignedAdminId (updates assignment without page refresh)
                    ...(data.waitingSince !== undefined && { waitingSince: data.waitingSince }),
                    ...(data.assignedAdminId !== undefined && { assignedAdminId: data.assignedAdminId }),
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
      useAuthStore.setState((state) => {
        if (!state.user) return state
        return { user: { ...state.user, status: data.status } }
      })

      if (data.status === 'SUSPENDED') {
        audio.playError()
        toast.error('Your account has been suspended.')
      } else if (data.status === 'APPROVED') {
        audio.playSuccess()
        toast.success('Your account has been approved!')
        // Registration reports are converted to userReports on approval.
        // Invalidate so the Reports page shows them immediately whether or
        // not it is currently mounted (user_report:new handles the mounted case).
        queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      }
    })

    socket.on('user_report:new', () => {
      audio.playDing()
      // Fire toast immediately regardless of whether UserReportsPage is mounted
      toast.info('A report has been created from your registration.')
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
    })

    socket.on('user:media_permission_changed', (data) => {
      const u = useAuthStore.getState().user
      if (u) {
        setUserRef.current({ ...u, mediaPermission: data.mediaPermission })
      }
    })

    socket.on('user:updated', (data) => {
      const u = useAuthStore.getState().user
      if (u && u.id === data.id) {
        setUserRef.current({
          ...u,
          ...(data.name !== undefined && { name: data.name }),
          ...(data.email !== undefined && { email: data.email }),
        })
      }
    })

    socket.on('admin:user_registered', () => {
      audio.playDing()
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      toast.info('New user registered!')
    })

    socket.on('preferences:updated', (data) => {
      const u = useAuthStore.getState().user
      if (u) {
        setUserRef.current({ ...u, emailNotifyOnMessage: data.emailNotifyOnMessage })
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
        audio.playAnnouncement()
        toast.info(`📢 ${data.announcement.title}`)
      }
    })

    socket.on('announcement:deleted', (data: { announcementId: string }) => {
      queryClient.setQueriesData<{ success: boolean; announcements: unknown[] }>(
        { queryKey: ['announcements'] },
        (old) => {
          if (!old) return old
          return {
            ...old,
            announcements: (old.announcements as Array<{ id: string }>).filter(a => a.id !== data.announcementId),
          }
        },
      )
      queryClient.removeQueries({ queryKey: ['announcement', data.announcementId] })
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
  }, [isAuthenticated, userId, queryClient])

  return getSocket()
}
