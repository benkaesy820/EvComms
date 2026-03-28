import { z } from 'zod'

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required').max(128, 'Password is too long'),
})

// Deduplicated list of common weak passwords
const COMMON_PASSWORDS = new Set([
  'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
  'master', 'hello', 'sunshine', 'princess', 'football', 'baseball', 'iloveyou',
  'trustno1', 'abc123', 'password1', '12345678', '123456789', 'adobe123', 'admin123',
  'letmein1', 'photoshop', 'bailey', 'shadow', 'whatever', 'starwars', 'freedom',
  'qazwsx', '654321', '555555', '3rjs1la7qe', 'michelle', 'jessica', 'pepper',
  'zaq12wsx', 'ashley', 'michael', 'ginger', 'tigger', 'matthew', 'amanda',
  'mustang', 'harley', 'chocolate', 'chelsea', 'america', 'thunder', 'patrick',
  'minecraft', 'yankees', 'dallas', 'orioles', 'canada', 'hunter', 'oliver',
  'richard', 'morgan', 'merlin', 'butter', 'cookie', 'falcon', 'ferrari', 'boston',
  'ranger', 'thomas', 'raiders', 'purple', 'andrea', 'bandit', 'heather', 'rachel',
  'qwer1234', 'maggie', 'pretty', 'buster', 'soccer', 'hockey', 'killer', 'george',
  'sexy', 'andrew', 'william', 'robert', 'joshua', 'taylor', 'brian', 'hannah',
  'daniel', 'love', 'nicole', 'biteme', 'babygirl', 'barbara', 'danielle',
  'wrangler', 'xxxxxx', 'lovers', 'nicholas', 'midnight', 'flower'
])

const commonPasswordsRegex = new RegExp(
  `^(${Array.from(COMMON_PASSWORDS).join('|')})$`,
  'i'
)

const COMMON_PATTERNS = [
  /(.+)\1{2,}/, // Repeated characters (3+ times)
  /^(.)\1+$/, // All same character
  commonPasswordsRegex,
]

const passwordSchema = z.string()
  .min(12, 'At least 12 characters')
  .max(128, 'Must be 128 characters or less')
  .regex(/[a-z]/, 'Must include lowercase letter')
  .regex(/[A-Z]/, 'Must include uppercase letter')
  .regex(/\d/, 'Must include number')
  .regex(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/, 'Must include special character')
  .refine((v) => !/\s/.test(v), 'Cannot contain spaces')
  .refine(v => !COMMON_PATTERNS.some(p => p.test(v)), 'Password contains common patterns or repeated characters (e.g. 111, aaa)')
  .refine(v => !/012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm/i.test(v), 'Cannot contain sequential characters (e.g. 123, abc)')

export const registerSchema = z.object({
  email: z.string().email('Invalid email address').max(255),
  password: passwordSchema,
  name: z.string().min(2, 'At least 2 characters').max(100),
  phone: z.string().min(1, 'Phone number is required').transform(str => {
    let cleaned = str.replace(/[\s\-()]/g, '')
    if (cleaned.startsWith('+233')) cleaned = cleaned.substring(1)
    if (cleaned.startsWith('0')) cleaned = '233' + cleaned.substring(1)
    return cleaned
  }).refine(str => /^233[0-9]{9}$/.test(str), {
    message: 'Must be a valid Ghanaian number (e.g. 05...)'
  }),
  reportSubject: z.string().min(1, 'Subject is required').max(200).optional(),
  reportDescription: z.string().min(1, 'Description is required').max(2000).optional(),
}).refine(
  (data) => {
    // If either report field is provided, both must be provided
    const hasSubject = !!data.reportSubject?.trim()
    const hasDescription = !!data.reportDescription?.trim()
    return hasSubject === hasDescription
  },
  {
    message: 'Both subject and description are required when submitting a report',
    path: ['reportDescription'],
  }
)

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
export type MessageType = 'TEXT' | 'IMAGE' | 'DOCUMENT'
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
  /** JSON-encoded string array of subsidiary IDs this admin handles. null = generalist. */
  subsidiaryIds?: string | null
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
  subsidiaryId?: string | null
  subsidiary?: Subsidiary | null
  registrationReportId?: string | null
  registrationReport?: {
    id: string
    subject: string
    description: string
    status: 'PENDING' | 'REVIEWED'
    createdAt: number
  } | null
  unreadCount: number
  adminUnreadCount?: number
  lastMessageAt: number | null
  lastMessage?: Message | null
  createdAt: number
  archivedAt?: number | null
  waitingSince?: number | null
  lastAdminReplyAt?: number | null
}

export interface InternalMessage {
  id: string
  senderId: string
  sender: { id: string; name: string; role: Role }
  type: MessageType
  content: string | null
  media: Media | null
  status?: MessageStatus
  readBy?: string[]   // userIds who have seen this message (for group blue-tick)
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
  status?: MessageStatus  // SENT (single ✓) → READ (double blue ✓✓)
  readBy?: string[]       // partner's id when they read it
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
  previousStatus?: Status
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
  type: z.enum(['TEXT', 'IMAGE', 'DOCUMENT']),
  content: z.string().max(100000).optional(),
  mediaId: z.string().optional(),
})

export type LoginInput = z.infer<typeof loginSchema>
export type RegisterInput = z.infer<typeof registerSchema>
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>
export type SendMessageInput = z.infer<typeof sendMessageSchema>
