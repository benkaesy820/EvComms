import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/authStore'
import { connectSocket, disconnectSocket, getSocket, getActiveFocusedConversation } from '@/lib/socket'
import type { Message } from '@/lib/schemas'
import { auth as authApi, getAuthToken } from '@/lib/api'
import { toast } from '@/components/ui/sonner'
import { audio } from '@/lib/audio'
import { showOsNotification } from '@/lib/notify'
import { prependMessage, softDeleteMessage, markMessagesRead, applyReaction } from '@/lib/messageCache'
import type { MessagesCache } from '@/lib/messageCache'


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

    // After page reload, Zustand rehydrates isAuthenticated from localStorage
    // but memoryToken is null (JS memory wiped). The socket auth callback reads
    // getAuthToken() which returns null → "No token provided" error.
    // Skip socket connection until the token is available.
    const token = getAuthToken()
    if (!token) return

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
          audio.playError()
          toast.error('Session expired. Please login again.', { id: 'session-expired' })
          resetRef.current()
        }
      }
    })

    socket.on('auth_error', () => {
      audio.playError()
      // Use a stable toast id so this never stacks with the connect_error path above
      toast.error('Session expired. Please login again.', { id: 'session-expired' })
      resetRef.current()
    })

    // On reconnect, invalidate all caches that could have missed events
    // while the socket was disconnected. This is the safety net that
    // guarantees no stale data survives a network blip.
    socket.on('connect', () => {
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      queryClient.invalidateQueries({ queryKey: ['announcements'] })
      queryClient.invalidateQueries({ queryKey: ['announcements', 'public'] })
      queryClient.invalidateQueries({ queryKey: ['internal', 'unread'] })
      queryClient.invalidateQueries({ queryKey: ['dm', 'unread'] })
      queryClient.invalidateQueries({ queryKey: ['dm', 'conversations'] })
      queryClient.invalidateQueries({ queryKey: ['appConfig'] })
    })

    socket.on('force_logout', (data) => {
      audio.playError()
      toast.error(data.reason || 'You have been logged out')
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      resetRef.current()
    })

    socket.on('session:created', () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    })

    socket.on('session:revoked', () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    })

    socket.on('session:expired', () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    })

    socket.on('message:new', (data) => {
      const msg = data.message
      const currentUser = useAuthStore.getState().user

      // ── Sound & Toast decision matrix ────────────────────────────────────────
      // This is the SINGLE place that decides sound + toast for incoming messages.
      // Page-level handlers (ChatPage, ConversationsPage) only update their caches.
      //
      // Scenarios:
      //   1. Actively viewing this exact chat (tab focused, on chat page/admin conv) → playPop only
      //   2. On the chat/admin page but not focused on this thread → playDing only (sidebar badge shows)
      //   3. Completely elsewhere (Settings, Users, etc.) → playDing + toast with "View" action
      if (currentUser && msg.senderId !== currentUser.id) {
        const isUserOnChatPage = currentUser.role === 'USER' && window.location.pathname.includes('/chat')
        const isAdminOnAdminPage = currentUser.role !== 'USER' && window.location.pathname.startsWith('/admin')
        const isOnChatPage = isUserOnChatPage || isAdminOnAdminPage

        const isFocusingThisChat = document.hasFocus() && isOnChatPage && (
          currentUser.role === 'USER' ||
          getActiveFocusedConversation() === msg.conversationId
        )

        const preview = msg.content
          ? (msg.content.length > 80 ? msg.content.slice(0, 80) + '…' : msg.content)
          : 'Sent an attachment'
        const senderName = msg.sender?.name || 'New Message'
        const targetUrl = currentUser.role === 'USER' ? '/home/chat' : '/admin'

        if (isFocusingThisChat) {
          // Scenario 1: user is actively watching this exact thread → soft pop
          audio.playPop()
        } else if (isOnChatPage) {
          // Scenario 2: tab visible but different thread → ding, no toast
          audio.playDing()
          // OS banner covers the case where the window is visible but they're
          // looking at a different monitor / app (document.hidden check inside)
          showOsNotification(senderName, preview, `conv:${msg.conversationId}`, targetUrl)
        } else {
          // Scenario 3: completely elsewhere → ding + toast + OS banner
          audio.playDing()
          toast(senderName, {
            description: preview,
            action: {
              label: 'View',
              onClick: () => {
                if (currentUser.role !== 'USER') {
                  localStorage.setItem('admin-selected-conversation', msg.conversationId)
                }
                window.location.href = targetUrl
              }
            }
          })
          showOsNotification(senderName, preview, `conv:${msg.conversationId}`, targetUrl)
        }
      }

      // ── Cache updates ────────────────────────────────────────────────────────
      // NOTE: ChatPage registers its OWN message:new handler that also updates
      // ['messages', conversationId]. To avoid double-prepending when ChatPage is
      // mounted, we skip the messages cache update here — ChatPage's local handler
      // covers it. We ONLY update the lightweight ['conversation'] unread-count cache
      // here, which ChatPage does NOT update on message:new.
      if (currentUser?.role === 'USER' && msg.senderId !== currentUser.id) {
        // Only bump the unread badge when the user is NOT actively looking at the chat.
        // When focused, useVisibilityMarkRead fires and the server resets unreadCount to 0.
        const isActivelyViewing = window.location.pathname.includes('/chat') && document.hasFocus()
        if (!isActivelyViewing) {
          queryClient.setQueryData<{ success: boolean; conversation: { unreadCount: number; lastMessageAt: number | null;[key: string]: unknown } | null }>(['conversation'],
            (old) => {
              if (!old?.conversation) return old
              return { ...old, conversation: { ...old.conversation, unreadCount: (old.conversation.unreadCount ?? 0) + 1, lastMessageAt: Date.now() } }
            }
          )
        }
      }

      // For pages where ChatPage is NOT mounted (e.g. admin on a different admin sub-page),
      // we still need to keep the messages cache fresh so navigating to the chat feels instant.
      // We only write if the cache already exists (i.e. the user visited that conversation
      // previously in this session). prependMessage deduplicates internally.
      const existingCache = queryClient.getQueryData<MessagesCache>(['messages', msg.conversationId])
      if (existingCache && existingCache.pages.length > 0) {
        queryClient.setQueryData<MessagesCache>(
          ['messages', msg.conversationId],
          old => prependMessage(old, msg),
        )
      }
    })

    socket.on('message:sent', (data) => {
      // Outgoing confirmation pop — only for messages we sent ourselves.
      // message:sent is targeted at the emitting socket so this should always
      // be true, but guard explicitly to prevent accidental double-pops if the
      // server ever broadcasts to multiple sockets.
      const currentUser = useAuthStore.getState().user
      if (currentUser && data.message.senderId === currentUser.id) {
        audio.playPop()
      }

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
      queryClient.setQueryData<MessagesCache>(
        ['messages', data.conversationId],
        old => softDeleteMessage(old, data.messageId, data.deletedAt),
      )
    })

    socket.on('messages:read', (data) => {
      queryClient.setQueryData<MessagesCache>(
        ['messages', data.conversationId],
        old => markMessagesRead(old, data.readAt),
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

    socket.on('conversation:subsidiary_changed', (data) => {
      queryClient.setQueriesData<{ pages: Array<{ success: boolean; conversations: Array<{ id: string; subsidiaryId: string | null;[key: string]: unknown }>; hasMore: boolean }>; pageParams: unknown[] }>(
        { queryKey: ['conversations'] },
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              conversations: page.conversations.map((c) =>
                c.id === data.conversationId
                  ? { ...c, subsidiaryId: data.subsidiaryId }
                  : c,
              ),
            })),
          }
        },
      )
      
      const currentUser = useAuthStore.getState().user
      // Only toast admins who are currently viewing/assigned to this chat but didn't make the change.
      if (currentUser && currentUser.role !== 'USER' && data.changedBy !== currentUser.id) {
        const isTracking = localStorage.getItem('admin-selected-conversation') === data.conversationId
        if (isTracking) {
          toast.info('Conversation category was updated by another administrator.')
        }
      }
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
      const u = useAuthStore.getState().user
      if (!u) return
      if (u.role === 'USER') {
        // Inform the user their registration created a report
        audio.playDing()
        toast.info('A report has been created from your registration.')
        queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      } else {
        // Admin: play sound, show toast with view action, bump badge
        audio.playDing()
        toast.info('New user report submitted', {
          action: {
            label: 'View',
            onClick: () => { window.location.href = '/admin/user-reports' }
          }
        })
        // Optimistically increment badge then sync from server
        queryClient.setQueriesData<{ reports: unknown[]; hasMore: boolean; pendingCount: number }>(
          { queryKey: ['admin', 'user-reports'] },
          (old) => old ? { ...old, pendingCount: old.pendingCount + 1 } : old,
        )
        queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
      }
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
      // Invalidate all user-related caches — covers admin lists, user detail,
      // and any page that displays user info.
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', data.id] })
    })

    socket.on('admin:user_registered', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      audio.playDing()
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      // Also refresh the separate pending-users list used by the admin dashboard
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'pending'] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      toast.info('New user registered!', { duration: 6000 })
    })

    // ── Fix 4: conversation:new + conversation:assigned in global hook ─────────
    // ConversationsPage also handles these for fine-grained list mutations, but
    // we MUST also handle them here so the conversations cache stays fresh when
    // an admin is on any other admin page (Users, Reports, Settings, etc.).
    socket.on('conversation:new', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'queue'] })
    })

    socket.on('conversation:assigned', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
    })

    // These MUST live in the global hook (not in ConversationsPage) so admins
    // receive the toast and push-fallback no matter which admin page they are on.
    socket.on('conversation:assigned_to_you', (data: { conversationId: string; userName: string }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      audio.playDing()
      toast.success(`Assigned to ${data.userName}.`, {
        duration: 6000,
        icon: '👤',
        action: {
          label: 'View',
          onClick: () => {
            localStorage.setItem('admin-selected-conversation', data.conversationId)
            window.location.href = '/admin'
          },
        },
      })
      // Keep conversations list fresh for every admin page that renders it
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
    })

    socket.on('conversation:unassigned', (data: { conversationId: string; oldAdminId: string; reason: string }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      // Only alert the admin who was actually unassigned; SUPER_ADMIN is informed via conversation:removed
      if (data.oldAdminId !== u.id) return
      audio.playDing()
      toast.warning('You have been unassigned from a conversation.', { duration: 5000 })
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
    })

    socket.on('conversation:removed', (data: { conversationId: string; userName: string }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      // SUPER_ADMIN: only invalidate caches — conversation:unassigned already toasted the affected admin.
      // Regular ADMIN: show the named toast (they don't receive conversation:unassigned for others' convs).
      if (u.role === 'SUPER_ADMIN') {
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
        queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      } else {
        audio.playDing()
        toast.warning(`You have been unassigned from ${data.userName}'s conversation.`, { duration: 5000 })
        queryClient.invalidateQueries({ queryKey: ['conversations'] })
        queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      }
    })

    // ── Fix 6: user_report:resolved global handler ────────────────────────────
    // Previously only handled in page-level components; cache never cleared when
    // those pages were not mounted.
    socket.on('user_report:resolved', () => {
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
    })

    // ── Fix 7: email + storage circuit breaker alerts for super admins ─────────
    // These events are emitted by the backend but were never handled on the frontend.
    socket.on('email:circuit_opened', (data: { provider: string; state: string; failures: number; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      audio.playError()
      toast.error(`Email circuit breaker opened (${data.provider})`, {
        description: `${data.failures} failures detected. Emails are temporarily paused.`,
        duration: 0, // persist until dismissed
      })
    })

    // Fired when the email circuit breaker recovers (backend parity with storage:circuit_closed).
    // The backend doesn't emit this yet — handler is wired so it works the moment it does.
    socket.on('email:circuit_closed', (data: { provider: string; state: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.success(`Email restored (${data.provider})`, {
        description: 'Circuit breaker closed — emails are flowing normally again.',
        duration: 8000,
      })
    })

    socket.on('email:circuit_recovery', (data: { provider: string; state: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.info(`Email circuit recovering (${data.provider})`, {
        description: 'Half-open state — testing delivery before fully restoring.',
        duration: 6000,
      })
    })

    socket.on('email:send_failed', (data: { provider: string; recipient: string; error: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.warning(`Email delivery failed (${data.provider})`, {
        description: `To: ${data.recipient} — ${data.error}`,
        duration: 8000,
      })
    })

    socket.on('database:circuit_opened', (data: { state: string; failures: number; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      audio.playError()
      toast.error('Database circuit breaker opened', {
        description: `${data.failures} failures. Some features may be degraded.`,
        duration: 0,
      })
    })

    socket.on('storage:circuit_opened', (data: { state: string; failures: number; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      audio.playError()
      toast.error('File storage circuit breaker opened', {
        description: `${data.failures} failures detected. File uploads may be unavailable.`,
        duration: 0,
      })
    })

    socket.on('storage:circuit_closed', (_data: { state: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.success('File storage recovered', { description: 'Circuit breaker closed — uploads are available again.', duration: 6000 })
    })

    socket.on('storage:circuit_recovery', (_data: { state: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.info('File storage recovering', { description: 'Circuit breaker in half-open state — testing recovery.', duration: 6000 })
    })

    // ── Media cleanup events — background job status visible to all admins ──────
    socket.on('cleanup:error', (data: { error: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      audio.playError()
      toast.error('Media cleanup job failed', {
        description: data.error || 'Background media cleanup encountered an error.',
        duration: 0, // persist until dismissed
      })
    })

    socket.on('cleanup:media_completed', (data: { cleanedCount: number; failedCount: number; totalProcessed: number; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      if (data.failedCount > 0) {
        toast.warning(`Media cleanup: ${data.cleanedCount} removed, ${data.failedCount} failed`, {
          description: `${data.totalProcessed} files processed.`,
          duration: 8000,
        })
      }
      // Silent success — no toast when everything cleans up fine; only alert on failures
    })

    socket.on('cleanup:media_failed', (_data: { mediaId: string; error: string; timestamp: number }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      toast.warning('Media file deletion failed', {
        description: `Could not remove a stale file. Check storage logs.`,
        duration: 6000,
      })
    })

    // ── Fix: admin:reassignment_failures — notify admins of bulk-reassign failures ──
    socket.on('admin:reassignment_failures', (data: { count: number; reason: string }) => {
      const u = useAuthStore.getState().user
      if (!u || (u.role !== 'SUPER_ADMIN' && u.role !== 'ADMIN')) return
      audio.playError()
      toast.error(`${data.count} conversation${data.count !== 1 ? 's' : ''} could not be reassigned`, {
        description: data.reason || 'Some conversations were left unassigned.',
        duration: 0, // persist until dismissed
      })
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
    })

    // ── Fix #6: global conversation:archived — notify USER even when off ChatPage ──
    // ChatPage's local handler covers the case when it is mounted. When the user
    // is elsewhere (e.g. Settings, HomePage), the local handler is gone and they'd
    // get no feedback at all that their chat was closed by support.
    socket.on('conversation:archived', (data: { conversationId: string; archivedBy: string; closingNote?: string | null }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role !== 'USER') return
      // Only alert if we're NOT already on ChatPage (ChatPage handles it locally)
      if (!window.location.pathname.includes('/chat')) {
        audio.playError()
        toast.info('Your conversation has been closed by the support team.', {
          duration: 8000,
          description: data.closingNote ? `Note: ${data.closingNote}` : undefined,
          action: {
            label: 'View',
            onClick: () => { window.location.href = '/home/chat' },
          },
        })
      }
      // Always invalidate so ChatPage/HomePage unread badge stays accurate
      queryClient.invalidateQueries({ queryKey: ['conversation'] })
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
      // Keep the public (unauthenticated) cache in sync too
      queryClient.invalidateQueries({ queryKey: ['announcements', 'public'] })
      if (data.announcement?.title) {
        audio.playAnnouncement()
        toast.info(data.announcement.title)
        showOsNotification(
          data.announcement.title,
          'Tap to read the full announcement.',
          `announcement:${data.announcement.id}`,
          '/home/announcements'
        )
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
      queryClient.invalidateQueries({ queryKey: ['announcements', 'public'] })
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
      // Keep public cache in sync (field shapes differ, so invalidate rather than patch)
      queryClient.invalidateQueries({ queryKey: ['announcements', 'public'] })
    })

    // ── Fix: announcement:vote:updated — global handler so vote counts update
    // everywhere, not just on the announcements page. useAnnouncementSocket handles
    // the detail view; this covers list pages and any other mounted consumer.
    socket.on('announcement:vote:updated', (data: { announcementId: string; upvoteCount: number; downvoteCount: number }) => {
      const patch = (a: { id: string; upvoteCount: number; downvoteCount: number }) =>
        a.id === data.announcementId ? { ...a, upvoteCount: data.upvoteCount, downvoteCount: data.downvoteCount } : a
      queryClient.setQueriesData<{ success: boolean; announcements: Array<{ id: string; upvoteCount: number; downvoteCount: number }> }>(
        { queryKey: ['announcements'] },
        (old) => old ? { ...old, announcements: old.announcements.map(patch) } : old,
      )
    })

    socket.on('message:reaction', (data) => {
      queryClient.setQueriesData<MessagesCache>(
        { queryKey: ['messages'] },
        old => applyReaction(old, data.messageId, data.reaction, data.action),
      )
    })

    socket.on('cache:invalidate', (data) => {
      data.keys.forEach((key) => {
        queryClient.invalidateQueries({ queryKey: [key] })
      })
    })

    // ── Global: stats:invalidate — keep sidebar badges fresh everywhere ───────
    // AdminLayout also listens but only when /admin is mounted; this ensures
    // the badge updates when an admin is on any non-admin page too.
    socket.on('stats:invalidate', () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      // Pending-users list on the admin dashboard and admins roster also change
      // when a user is approved/rejected/suspended — keep them fresh.
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'pending'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
    })

    // ── Global: internal:message — toast/sound when not on team-chat page ─────
    // Previously only in AdminLayout, so admins on the landing page or other
    // pages missed these notifications entirely.
    socket.on('internal:message', (data: { message: { senderId: string; content?: string | null } }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (data.message.senderId === u.id) return
      queryClient.invalidateQueries({ queryKey: ['internal', 'unread'] })
      if (!window.location.pathname.startsWith('/admin/internal')) {
        audio.playDing()
        toast.info('New team message', {
          description: data.message.content
            ? (data.message.content.length > 60 ? data.message.content.slice(0, 60) + '...' : data.message.content)
            : 'New message in team chat',
          action: {
            label: 'View',
            onClick: () => { window.location.href = '/admin/internal' }
          }
        })
      }
    })

    // ── Global: dm:message — toast/sound when not on DM page ─────────────────
    socket.on('dm:message', (data: { message: { senderId: string; content?: string | null }; senderName?: string }) => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (data.message.senderId === u.id) return
      queryClient.invalidateQueries({ queryKey: ['dm', 'unread'] })
      queryClient.invalidateQueries({ queryKey: ['dm', 'conversations'] })
      if (!window.location.pathname.startsWith('/admin/dm')) {
        audio.playDing()
        toast.info(data.senderName ? `DM from ${data.senderName}` : 'New direct message', {
          description: data.message.content
            ? (data.message.content.length > 60 ? data.message.content.slice(0, 60) + '...' : data.message.content)
            : 'You have a new direct message',
          action: {
            label: 'View',
            onClick: () => { window.location.href = `/admin/dm?partner=${data.message.senderId}` }
          }
        })
      }
    })

    // ── Global: internal chat mutations — keep cache clean when page is unmounted ──
    // useInternalMessages() registers these same handlers, but only while
    // InternalChatPage is mounted.  When the page is NOT open, deletions/reactions/
    // clears would leave the cache stale.  Here we invalidate so the next navigation
    // to /admin/internal always fetches fresh data.
    socket.on('internal:message:deleted', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (!window.location.pathname.startsWith('/admin/internal')) {
        queryClient.invalidateQueries({ queryKey: ['internal-messages'] })
      }
    })

    socket.on('internal:messages:bulk_deleted', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (!window.location.pathname.startsWith('/admin/internal')) {
        queryClient.invalidateQueries({ queryKey: ['internal-messages'] })
      }
    })

    socket.on('internal:chat:cleared', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (!window.location.pathname.startsWith('/admin/internal')) {
        // Wipe cache entirely so navigating to team chat shows an empty, correct state
        queryClient.setQueryData(['internal-messages'], {
          pages: [{ success: true, messages: [], hasMore: false }],
          pageParams: [undefined],
        })
      }
    })

    socket.on('internal:message:reaction', () => {
      const u = useAuthStore.getState().user
      if (!u || u.role === 'USER') return
      if (!window.location.pathname.startsWith('/admin/internal')) {
        queryClient.invalidateQueries({ queryKey: ['internal-messages'] })
      }
    })

    return () => {
      socket.removeAllListeners()
      disconnectSocket()
    }
  }, [isAuthenticated, userId, queryClient])

  return getSocket()
}
