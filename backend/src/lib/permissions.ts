import type { User, Conversation } from '../db/schema.js'
import { getConfig } from './config.js'

export function canUploadMedia(user: Pick<User, 'status' | 'role'> & { mediaPermission?: boolean }): boolean {
  if (user.role === 'ADMIN' || user.role === 'SUPER_ADMIN') return true
  return user.status === 'APPROVED' && (user.mediaPermission ?? false) === true
}

interface DeletableMessage {
  senderId: string
  createdAt: Date | number | null
}

export function canDeleteMessage(
  user: Pick<User, 'id' | 'role'>,
  message: DeletableMessage,
  scope: 'me' | 'all' = 'all'
): boolean {
  const config = getConfig()

  // "Delete for Me" is always allowed for participants
  // (Route-level checks ensure the user is actually part of the conversation)
  if (scope === 'me') {
    return true
  }

  // "Delete for Everyone" logic
  if (user.role === 'SUPER_ADMIN') {
    return true // Super Admins can hard delete or soft delete anything anytime
  }

  // ADMIN can soft-delete any message in their assigned conversations
  // (Route-level checks in messageRoutes ensure they have conversation access)
  if (user.role === 'ADMIN') {
    return true
  }

  // Regular users: check the messageDelete feature flag first
  if (config.features.messageDelete === false) {
    return false
  }

  // Enforce the time limit for regular users
  const timeLimitMs = (config.features.messageDeleteTimeLimitSeconds ?? 300) * 1000
  const createdAt = message.createdAt instanceof Date
    ? message.createdAt.getTime()
    : (typeof message.createdAt === 'number' ? message.createdAt : 0)

  if (Date.now() - createdAt > timeLimitMs) {
    return false
  }

  // User can only delete their own messages
  return message.senderId === user.id
}

export function canAccessConversation(
  user: Pick<User, 'id' | 'role'>,
  conversation: Pick<Conversation, 'userId' | 'assignedAdminId'>
): boolean {
  // SUPER_ADMIN can access all conversations
  if (user.role === 'SUPER_ADMIN') return true
  // Regular ADMIN can only access conversations assigned to them
  if (user.role === 'ADMIN') return conversation.assignedAdminId === user.id
  // Users can only access their own conversation
  return conversation.userId === user.id
}

export function isAdmin(user: Pick<User, 'role'>): boolean {
  return user.role === 'ADMIN' || user.role === 'SUPER_ADMIN'
}
