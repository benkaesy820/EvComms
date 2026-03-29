import { io, type Socket } from 'socket.io-client'
import { getAuthToken } from '@/lib/api'
import type { Message, Role, Status, Announcement, Conversation, MessageReaction, InternalMessage } from '@/lib/schemas'

interface ServerToClientEvents {
  authenticated: (data: { userId: string; role: Role; status: Status }) => void
  auth_error: (data: { message: string }) => void

  'message:new': (data: { message: Message }) => void
  'message:sent': (data: { tempId: string; message: Message }) => void
  'message:deleted': (data: { messageId: string; conversationId: string; deletedBy: string; deletedAt: number }) => void
  'messages:read': (data: { conversationId: string; readBy: string; readAt: number }) => void
  // DM read receipts (WhatsApp 1:1 rules)
  'dm:read': (data: { partnerId: string; readAt: number }) => void
  // Internal group read receipts (WhatsApp group rules: all read = blue)
  'internal:read_receipt': (data: { userId: string; readAt: number }) => void
  'message:reaction': (data: { messageId: string; reaction: MessageReaction | { userId: string; emoji: string }; action: 'add' | 'remove' }) => void

  'conversation:updated': (data: { conversationId: string; userId?: string; unreadCount?: number; adminUnreadCount?: number; lastMessageAt?: number; lastMessage?: Message; assignedAdminId?: string | null; waitingSince?: number | null; subsidiaryId?: string | null }) => void
  'conversation:assigned': (data: { conversationId: string; assignedAdminId: string | null; assignedAdminName?: string; assignedAdminRole?: string; oldAdminId?: string | null }) => void
  'conversation:unassigned': (data: { conversationId: string; oldAdminId: string; reason: string }) => void
  'conversation:removed': (data: { conversationId: string; userName: string }) => void
  'conversation:assigned_to_you': (data: { conversationId: string; userName: string }) => void
  'conversation:archived': (data: { conversationId: string; archivedBy: string }) => void
  'conversation:unarchived': (data: { conversationId: string; unarchivedBy: string }) => void
  'conversation:new': (data: { conversation: Conversation }) => void
  'conversation:subsidiary_changed': (data: { conversationId: string; subsidiaryId: string | null; changedBy: string }) => void
  'conversation:reopened': (data: { conversationId: string; unarchivedBy?: string }) => void
  'stats:invalidate': () => void

  'internal:message': (data: { message: InternalMessage }) => void
  'internal:message:sent': (data: { tempId?: string; message: InternalMessage }) => void
  'internal:message:deleted': (data: { id: string }) => void
  'internal:messages:bulk_deleted': (data: { ids: string[] }) => void
  'internal:chat:cleared': (data: { scope: string }) => void
  'internal:typing': (data: { userId: string; userName: string; isTyping: boolean }) => void
  'internal:message:reaction': (data: { type: 'add' | 'remove'; reaction: { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } } }) => void

  'typing:start': (data: { conversationId: string; userId: string; userName: string }) => void
  'typing:stop': (data: { conversationId: string; userId: string; userName: string }) => void
  'dm:typing': (data: { userId: string; userName: string; isTyping: boolean }) => void
  'presence:update': (data: { userId: string; status: string; lastSeen: number }) => void
  'presence:snapshot': (data: { onlineUserIds: string[] }) => void

  'user:status_changed': (data: { userId: string; status: Status; reason?: string; changedAt: number }) => void
  'user:media_permission_changed': (data: { mediaPermission: boolean }) => void
  'user:updated': (data: { id: string; name?: string; email?: string; phone?: string }) => void
  'user:online': (data: { userId: string; userName: string; status: 'online' }) => void
  'user:offline': (data: { userId: string; userName: string; status: 'offline'; lastSeenAt: number }) => void

  'session:revoked': (data: { sessionId: string; reason: string; revokedAt: number }) => void
  force_logout: (data: { reason: string }) => void

  'admin:user_registered': (data: { user: { id: string; email: string; name: string; status: Status; createdAt: number; hasReport?: boolean; reportId?: string | null; reportSubject?: string } }) => void

  'report:reviewed': (data: { userId: string; reportIds: string[]; reviewedBy: string; reviewedAt: number; autoReviewed: boolean }) => void

  'user_report:new': (data: { reportId: string; userId: string; subject: string; createdAt: number }) => void
  'user_report:resolved': (data: { reportId: string }) => void

  'preferences:updated': (data: { emailNotifyOnMessage: boolean }) => void
  'announcement:new': (data: { announcement: Announcement }) => void
  'announcement:updated': (data: { announcement: Announcement | null }) => void
  'announcement:deleted': (data: { announcementId: string }) => void
  'cache:invalidate': (data: { keys: string[] }) => void
  'dm:message': (data: { message: import('@/lib/schemas').DirectMessage; tempId?: string }) => void
  'dm:message:deleted': (data: { messageId: string }) => void
  'dm:message:reaction': (data: { adminId: string; messageId: string; type: 'add' | 'remove'; reaction: { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } } }) => void
  pong: () => void

  // Announcement real-time events
  'announcement:comment:new': (data: { announcementId: string; comment: { id: string; content: string; createdAt: Date; user: { id: string; name: string; role: string } } }) => void
  'announcement:comment:deleted': (data: { announcementId: string; commentId: string }) => void
  'announcement:reaction:updated': (data: { announcementId: string; userId: string; emoji: string }) => void
  'announcement:reaction:added': (data: { announcementId: string; userId: string; emoji: string }) => void
  'announcement:reaction:removed': (data: { announcementId: string; userId: string }) => void
  'announcement:vote:updated': (data: { announcementId: string; upvoteCount: number; downvoteCount: number }) => void

  // Email provider admin events
  'email:circuit_opened': (data: { provider: string; state: string; failures: number; timestamp: number }) => void
  'email:send_failed': (data: { provider: string; recipient: string; error: string; timestamp: number }) => void

}

interface ClientToServerEvents {
  authenticate: (data: { token: string }) => void
  'message:send': (data: { conversationId: string; type: string; content?: string; mediaId?: string; tempId?: string; replyToId?: string; announcementId?: string }) => void
  'internal:message:send': (data: { type?: string; content?: string; mediaId?: string; tempId?: string }) => void
  'internal:mark_read': () => void     // tell server we've seen all internal messages
  'dm:mark_read': (data: { partnerId: string }) => void  // tell server we've read this DM thread
  'internal:typing': (data: { isTyping: boolean }) => void
  'messages:mark_read': (data: { conversationId: string }) => void
  'message:react': (data: { messageId: string; emoji: string }) => void
  'message:unreact': (data: { messageId: string; emoji: string }) => void
  'typing:start': (data: { conversationId: string }) => void
  'typing:stop': (data: { conversationId: string }) => void
  'dm:typing': (data: { partnerId: string; isTyping: boolean }) => void
  'presence:update': (data: { status: string }) => void
  'presence:get': () => void
  ping: () => void
}

export type AppSocket = Socket<ServerToClientEvents, ClientToServerEvents>

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || ''

let socket: AppSocket | null = null

export function getSocket(): AppSocket | null {
  return socket
}

export function connectSocket(): AppSocket {
  // socket.active is true while connecting OR connected — prevents a new io() call
  // from interrupting a handshake in progress (which causes "WebSocket closed before established")
  if (socket?.active) {
    return socket
  }

  socket = io(SOCKET_URL, {
    auth: (cb) => cb({ token: typeof getAuthToken === 'function' ? getAuthToken() : undefined }),
    transports: ['websocket', 'polling'],
    withCredentials: true,
    upgrade: true,
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 10000,
    reconnectionAttempts: Infinity,
    timeout: 8000,
  }) as AppSocket

  return socket
}

export function disconnectSocket(): void {
  if (socket) {
    socket.removeAllListeners()
    socket.disconnect()
    socket = null
  }
}

export type { ServerToClientEvents, ClientToServerEvents, Conversation }
