import { z } from 'zod'

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required').max(100, 'Password is too long'),
})

const passwordSchema = z.string()
  .min(8, 'At least 8 characters')
  .max(100, 'Must be 100 characters or less')
  .regex(/[a-z]/, 'Must include lowercase letter')
  .regex(/[A-Z]/, 'Must include uppercase letter')
  .regex(/\d/, 'Must include number')
  .regex(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/, 'Must include special character')
  .refine((v) => !/\s/.test(v), 'Cannot contain spaces')

export const registerSchema = z.object({
  email: z.string().email('Invalid email address').max(255),
  password: passwordSchema,
  name: z.string().min(2, 'At least 2 characters').max(100),
  phone: z.string().max(20).optional(),
})

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, 'Required'),
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, 'Required'),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
})

export const resetPasswordSchema = z
  .object({
    token: z.string().min(1, 'Token is required'),
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, 'Required'),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })

export type Role = 'SUPER_ADMIN' | 'ADMIN' | 'USER'
export type Status = 'PENDING' | 'APPROVED' | 'REJECTED' | 'SUSPENDED'
export type MessageType = 'TEXT' | 'IMAGE' | 'VIDEO' | 'DOCUMENT'
export type MessageStatus = 'SENT' | 'READ' | 'FAILED'

export interface User {
  id: string
  email: string
  name: string
  phone?: string | null
  role: Role
  status: Status
  mediaPermission: boolean
  emailNotifyOnMessage: boolean
  createdAt: number
  lastSeenAt?: number | null
}

export interface Session {
  id: string
  deviceInfo: {
    browser: string
    os: string
    device: string
  }
  ipAddress: string
  createdAt: number
  lastActiveAt: number
  isCurrent: boolean
}

export interface Media {
  id: string
  type: MessageType
  cdnUrl: string
  filename: string
  size: number
  mimeType: string
  metadata?: {
    duration?: number
    width?: number
    height?: number
    thumbnail?: string
    [key: string]: unknown
  }
}

export interface MessageReaction {
  id: string
  messageId: string
  userId: string
  emoji: string
  user?: {
    id: string
    name: string
  }
}

export interface Message {
  id: string
  conversationId: string
  senderId: string
  sender: {
    id: string
    name: string
    role: Role
  }
  type: MessageType
  content: string | null
  status: MessageStatus
  readAt: number | string | null
  deletedAt: number | string | null
  createdAt: number | string
  media: Media | null
  reactions?: MessageReaction[]
  replyToId?: string | null
  replyTo?: {
    id: string
    content: string | null
    type: MessageType
    sender: { name: string }
    deletedAt?: number | string | null
  } | null
  announcementId?: string | null
  linkedAnnouncement?: {
    id: string
    title: string
    type: AnnouncementType
    template: AnnouncementTemplate
  } | null
}

export interface Conversation {
  id: string
  userId: string
  user?: {
    id: string
    name: string
    email: string
    status: Status
  }
  assignedAdminId?: string | null
  assignedAdmin?: { id: string; name: string; role: Role } | null
  unreadCount: number
  adminUnreadCount?: number
  lastMessageAt: number | null
  lastMessage?: Message | null
  createdAt: number
}

export interface InternalMessage {
  id: string
  senderId: string
  sender: { id: string; name: string; role: Role }
  type: MessageType
  content: string | null
  media: Media | null
  replyToId?: string | null
  replyTo?: (Omit<InternalMessage, 'replyTo'>) | null
  reactions?: { id?: string; userId: string; emoji: string; user?: { name: string } }[]
  createdAt: number | string
}

export interface DirectMessage {
  id: string
  senderId: string
  recipientId: string
  sender: { id: string; name: string; role: Role }
  type: MessageType
  content: string | null
  media: Media | null
  replyToId?: string | null
  replyTo?: Omit<DirectMessage, 'replyTo'> | null
  reactions?: { id?: string; userId: string; emoji: string; user?: { name: string } }[]
  deletedAt: number | null
  createdAt: number | string
}

export interface AuditLog {
  id: string
  userId: string
  action: string
  entityType: string
  entityId: string
  details: string | null
  user?: { name: string; email: string }
  createdAt: number
}

export interface StatusHistoryEntry {
  id: string
  userId: string
  oldStatus: Status
  newStatus: Status
  reason: string | null
  changedBy: string
  changedByUser?: { name: string; role: Role }
  createdAt: number
}

export type AnnouncementType = 'INFO' | 'WARNING' | 'IMPORTANT'
export type AnnouncementTemplate = 'DEFAULT' | 'BANNER' | 'CARD' | 'MINIMAL'

export interface Announcement {
  id: string
  title: string
  content: string
  type: AnnouncementType
  template: AnnouncementTemplate
  mediaAttachment?: Media | null
  targetRoles: Role[] | null
  author?: { id: string; name: string; role: Role }
  upvoteCount: number
  downvoteCount: number
  userVote: 'UP' | 'DOWN' | null
  isActive: boolean
  createdBy: string
  createdAt: number | string
  expiresAt: number | string | null
  reactions?: Array<{ id: string; emoji: string; userId: string }> | null
  userReaction?: { id: string; emoji: string; userId: string } | null
}

export interface AnnouncementReaction {
  id: string
  announcementId: string
  userId: string
  emoji: string
  createdAt: number | string
}

export interface AnnouncementComment {
  id: string
  content: string
  createdAt: number | string | Date
  user: { id: string; name: string; role: Role }
}

export interface Subsidiary {
  id: string
  name: string
  description?: string
  url?: string
  industry?: string
  founded?: string
}

// ── API Response Types ────────────────────────────────

export interface ApiError {
  error: string
  message?: string
  statusCode?: number
}

export interface PaginatedResponse<T> {
  success: boolean
  data: T[]
  hasMore: boolean
}

// ── Message Send Schema ───────────────────────────────

export const sendMessageSchema = z.object({
  type: z.enum(['TEXT', 'IMAGE', 'VIDEO', 'DOCUMENT']),
  content: z.string().max(100000).optional(),
  mediaId: z.string().optional(),
})

export type LoginInput = z.infer<typeof loginSchema>
export type RegisterInput = z.infer<typeof registerSchema>
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>
export type SendMessageInput = z.infer<typeof sendMessageSchema>
