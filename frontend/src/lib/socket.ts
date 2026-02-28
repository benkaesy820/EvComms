import { io, type Socket } from 'socket.io-client'
import type { Message, Role, Status, Announcement, Conversation, MessageReaction, InternalMessage } from '@/lib/schemas'

interface ServerToClientEvents {
  authenticated: (data: { userId: string; role: Role; status: Status }) => void
  auth_error: (data: { message: string }) => void

  'message:new': (data: { message: Message }) => void
  'message:sent': (data: { tempId: string; message: Message }) => void
  'message:deleted': (data: { messageId: string; conversationId: string; deletedBy: string; deletedAt: number }) => void
  'messages:read': (data: { conversationId: string; messageIds: string[]; readBy: string; readAt: number }) => void
  'message:reaction': (data: { messageId: string; reaction: MessageReaction | { userId: string; emoji: string }; action: 'add' | 'remove' }) => void

  'conversation:updated': (data: { conversationId: string; userId?: string; unreadCount?: number; adminUnreadCount?: number; lastMessageAt?: number; lastMessage?: Message; assignedAdminId?: string | null }) => void
  'conversation:assigned': (data: { conversationId: string; assignedAdminId: string | null; oldAdminId?: string | null }) => void
  'conversation:removed': (data: { conversationId: string; userName: string }) => void
  'conversation:assigned_to_you': (data: { conversationId: string; userName: string }) => void

  'internal:message': (data: { message: InternalMessage }) => void
  'internal:message:sent': (data: { tempId?: string; message: InternalMessage }) => void
  'internal:message:deleted': (data: { id: string }) => void
  'internal:chat:cleared': (data: { scope: string }) => void
  'internal:typing': (data: { userId: string; userName: string; isTyping: boolean }) => void
  'internal:message:reaction': (data: { type: 'add' | 'remove'; reaction: { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } } }) => void

  'typing:start': (data: { conversationId: string; userId: string; userName: string }) => void
  'typing:stop': (data: { conversationId: string; userId: string; userName: string }) => void
  'dm:typing': (data: { userId: string; userName: string; isTyping: boolean }) => void
  'presence:update': (data: { userId: string; status: string; lastSeen: number }) => void

  'user:status_changed': (data: { userId: string; status: Status; reason?: string; changedAt: number }) => void
  'user:media_permission_changed': (data: { mediaPermission: boolean }) => void
  'user:online': (data: { userId: string; userName: string; status: 'online' }) => void
  'user:offline': (data: { userId: string; userName: string; status: 'offline'; lastSeenAt: number }) => void

  'session:revoked': (data: { sessionId: string; reason: string; revokedAt: number }) => void

  'admin:user_registered': (data: { user: { id: string; email: string; name: string; status: Status; createdAt: number } }) => void

  'preferences:updated': (data: { emailNotifyOnMessage: boolean }) => void
  'announcement:new': (data: { announcement: Announcement }) => void
  'announcement:updated': (data: { announcement: Announcement | null }) => void
  'cache:invalidate': (data: { keys: string[] }) => void
  'dm:message': (data: { message: import('@/lib/schemas').DirectMessage; tempId?: string }) => void
  'dm:message:deleted': (data: { messageId: string }) => void
  'dm:message:reaction': (data: { adminId: string; messageId: string; type: 'add' | 'remove'; reaction: { id?: string; messageId: string; userId: string; emoji: string; user?: { name: string } } }) => void
  pong: () => void
}

interface ClientToServerEvents {
  authenticate: (data: { token: string }) => void
  'message:send': (data: { conversationId: string; type: string; content?: string; mediaId?: string; tempId?: string; replyToId?: string; announcementId?: string }) => void
  'internal:message:send': (data: { type?: string; content?: string; mediaId?: string; tempId?: string }) => void
  'internal:typing': (data: { isTyping: boolean }) => void
  'messages:mark_read': (data: { conversationId: string }) => void
  'message:react': (data: { messageId: string; emoji: string }) => void
  'message:unreact': (data: { messageId: string; emoji: string }) => void
  'typing:start': (data: { conversationId: string }) => void
  'typing:stop': (data: { conversationId: string }) => void
  'dm:typing': (data: { partnerId: string; isTyping: boolean }) => void
  'presence:update': (data: { status: string }) => void
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
