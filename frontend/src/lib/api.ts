import type {
  User,
  Session,
  Conversation,
  Message,
  AuditLog,
  StatusHistoryEntry,
  Media,
  Announcement,
  AnnouncementComment,
  AnnouncementType,
  InternalMessage,
  DirectMessage,
  Subsidiary,
  LoginInput,
  RegisterInput,
  ChangePasswordInput,
  Status,
} from '@/lib/schemas'
import ImageKit from 'imagekit-javascript'

const API_URL = import.meta.env.VITE_API_URL || ''

function buildQs(params: Record<string, string | number | boolean | undefined | null>): string {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

let memoryCsrfToken: string | null = null

function getCsrfToken(): string | null {
  if (memoryCsrfToken) return memoryCsrfToken
  const lsCsrf = localStorage.getItem('csrfToken')
  if (lsCsrf) return lsCsrf

  const match = document.cookie.match(/(?:^|;\s*)_csrf=([^;]*)/)
    ?? document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : null
}

let isRefreshing = false
let refreshWaiters: Array<(success: boolean) => void> = []

async function tryRefreshToken(): Promise<boolean> {
  if (isRefreshing) {
    return new Promise((resolve) => { refreshWaiters.push(resolve) })
  }
  isRefreshing = true
  try {
    const rToken = localStorage.getItem('refreshToken')
    const res = await fetch(`${API_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: rToken || undefined }),
      credentials: 'include',
    })

    if (!res.ok) {
      throw new Error('Refresh failed')
    }

    // Parse to ensure we capture the new tokens into localStorage
    const data = await res.json()
    if (data.token) localStorage.setItem('token', data.token)
    if (data.refreshToken) localStorage.setItem('refreshToken', data.refreshToken)
    if (data.csrfToken) {
      memoryCsrfToken = data.csrfToken
      localStorage.setItem('csrfToken', data.csrfToken)
    }

    refreshWaiters.forEach((cb) => cb(true))
    return true
  } catch {
    localStorage.removeItem('token')
    localStorage.removeItem('refreshToken')
    localStorage.removeItem('csrfToken')
    refreshWaiters.forEach((cb) => cb(false))
    return false
  } finally {
    isRefreshing = false
    refreshWaiters = []
  }
}

async function requestOnce(
  path: string,
  options: RequestInit,
): Promise<Response> {
  const url = `${API_URL}/api${path}`
  const method = (options.method ?? 'GET').toUpperCase()
  const hasBody = options.body !== undefined && options.body !== null
  const headers: Record<string, string> = {
    ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers as Record<string, string>),
  }

  const token = localStorage.getItem('token')
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const csrf = getCsrfToken()
    if (csrf) headers['x-csrf-token'] = csrf
  }
  return fetch(url, { ...options, credentials: 'include', headers })
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const isAuthPath = path.startsWith('/auth/')
  let res = await requestOnce(path, options)

  // Wait! Do not refresh on login status checks (me endpoint) 
  // because that creates an infinite loop if the user is truly logged out
  if (res.status === 401 && !isAuthPath && path !== '/me') {
    const success = await tryRefreshToken()
    if (success) {
      res = await requestOnce(path, options)
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    const errMsg = typeof body.error === 'string'
      ? body.error
      : body.error?.message || body.message || 'Request failed'
    throw new ApiError(errMsg, res.status)
  }

  if (res.status === 204) return undefined as T

  const data = await res.json()
  if (data && typeof data === 'object') {
    if ('csrfToken' in data && typeof data.csrfToken === 'string') {
      memoryCsrfToken = data.csrfToken
      localStorage.setItem('csrfToken', data.csrfToken)
    }
    if ('token' in data && typeof data.token === 'string') {
      localStorage.setItem('token', data.token)
    }
    if ('refreshToken' in data && typeof data.refreshToken === 'string') {
      localStorage.setItem('refreshToken', data.refreshToken)
    }
  }

  if (path === '/auth/logout') {
    localStorage.removeItem('token')
    localStorage.removeItem('refreshToken')
    localStorage.removeItem('csrfToken')
  }
  return data
}

function get<T>(path: string) {
  return request<T>(path)
}

function post<T>(path: string, body?: unknown) {
  return request<T>(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  })
}

function patch<T>(path: string, body?: unknown) {
  return request<T>(path, {
    method: 'PATCH',
    body: body ? JSON.stringify(body) : undefined,
  })
}

function del<T>(path: string) {
  return request<T>(path, { method: 'DELETE' })
}

export const auth = {
  login: (data: LoginInput) =>
    post<{
      success: boolean
      token: string
      csrfToken: string
      refreshToken: string
      user: User
      session: { id: string; expiresAt: number }
    }>('/auth/login', data),

  register: (data: RegisterInput) =>
    post<{ success: boolean; message: string; user: User }>('/auth/register', data),

  logout: () => post<{ success: boolean }>('/auth/logout'),

  me: () => get<{ success: boolean; user: User }>('/auth/me'),

  sessions: () => get<{ success: boolean; sessions: Session[] }>('/auth/sessions'),

  revokeSession: (sessionId: string) =>
    del<{ success: boolean }>(`/auth/sessions/${sessionId}`),

  revokeAllSessions: () =>
    post<{ success: boolean }>('/auth/sessions/revoke-all'),

  refresh: (refreshToken: string) =>
    post<{
      success: boolean
      token: string
      csrfToken: string
      refreshToken: string
      user: User
    }>('/auth/refresh', { refreshToken }),

  changePassword: (data: ChangePasswordInput) =>
    post<{ success: boolean; message: string; token: string; csrfToken: string; refreshToken: string }>('/auth/password/change', {
      currentPassword: data.currentPassword,
      newPassword: data.newPassword,
    }),

  forgotPassword: (email: string) =>
    post<{ success: boolean; message: string }>('/auth/password/forgot', { email }),

  resetPassword: (token: string, newPassword: string) =>
    post<{ success: boolean; message: string }>('/auth/password/reset', {
      token,
      newPassword,
    }),
}

export const conversations = {
  get: () =>
    get<{ success: boolean; conversation: Conversation | null }>('/conversations'),

  create: () =>
    post<{ success: boolean; conversation: Conversation }>('/conversations'),

  getOne: (id: string) =>
    get<{ success: boolean; conversation: Conversation }>(`/conversations/${id}`),

  getAdmin: (params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; conversations: Conversation[]; hasMore: boolean }>(
      `/conversations${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),

  messages: (conversationId: string, params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; messages: Message[]; hasMore: boolean }>(
      `/conversations/${conversationId}/messages${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),

  sendMessage: (conversationId: string, data: { type: string; content?: string; mediaId?: string; replyToId?: string; announcementId?: string }) =>
    post<{ success: boolean; message: Message }>(
      `/conversations/${conversationId}/messages`,
      data,
    ),

  markRead: (conversationId: string) =>
    patch<{ success: boolean; readCount: number }>(
      `/conversations/${conversationId}/mark-read`,
    ),

  assign: (conversationId: string, adminId: string | null) =>
    patch<{ success: boolean }>(`/conversations/${conversationId}/assign`, { adminId }),

  forUser: (userId: string) =>
    post<{ success: boolean; conversation: { id: string } }>('/conversations/for-user', { userId }),

  deleteMessage: (messageId: string, permanent?: boolean, scope: 'me' | 'all' = 'all') =>
    del<{ success: boolean }>(`/messages/${messageId}?scope=${scope}${permanent ? '&permanent=true' : ''}`),

  addReaction: (messageId: string, emoji: string) =>
    post<{ success: boolean; reaction: { id: string; messageId: string; userId: string; emoji: string } }>(
      `/messages/${messageId}/reactions`,
      { emoji },
    ),

  removeReaction: (messageId: string, emoji: string) =>
    del<{ success: boolean }>(`/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`),
}

export const adminUsers = {
  list: (params?: { status?: Status; role?: string; search?: string; before?: string; limit?: number }) =>
    get<{ success: boolean; users: User[]; hasMore: boolean }>(
      `/admin/users${buildQs({ status: params?.status, role: params?.role, search: params?.search, before: params?.before, limit: params?.limit })}`,
    ),

  getUser: (userId: string) =>
    get<{ success: boolean; user: User }>(`/admin/users/${userId}`),

  updateStatus: (userId: string, data: { status: Status; reason?: string }) =>
    patch<{ success: boolean; user: User }>(`/admin/users/${userId}/status`, data),

  updateMediaPermission: (userId: string, data: { mediaPermission: boolean }) =>
    patch<{ success: boolean; user: User }>(
      `/admin/users/${userId}/media-permission`,
      data,
    ),

  statusHistory: (userId: string, params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; history: StatusHistoryEntry[]; hasMore: boolean }>(
      `/admin/users/${userId}/status-history${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),

  resetPassword: (userId: string) =>
    post<{ success: boolean; message: string }>(`/admin/users/${userId}/reset-password`),

  auditLogs: (params?: { action?: string; entityType?: string; userId?: string; before?: string; limit?: number }) =>
    get<{ success: boolean; logs: AuditLog[]; hasMore: boolean }>(
      `/admin/audit-logs${buildQs({ action: params?.action, entityType: params?.entityType, userId: params?.userId, before: params?.before, limit: params?.limit })}`,
    ),
}

export const adminAdmins = {
  list: () =>
    get<{ success: boolean; admins: User[]; superAdmins: User[]; hasMoreAdmins: boolean; hasMoreSuperAdmins: boolean }>('/admin/admins'),

  create: (data: { email: string; password: string; name: string }) =>
    post<{ success: boolean; admin: User }>('/admin/admins', data),

  updateRole: (userId: string, data: { role: 'ADMIN' | 'USER' | 'SUPER_ADMIN' }) =>
    patch<{ success: boolean }>(`/admin/admins/${userId}/role`, data),

  suspend: (userId: string) =>
    patch<{ success: boolean; message: string }>(`/admin/admins/${userId}/suspend`, {}),

  reactivate: (userId: string) =>
    patch<{ success: boolean; message: string }>(`/admin/admins/${userId}/reactivate`, {}),
}

export const media = {
  getUploadUrl: (data: { type: string; size: number; mimeType: string; filename: string; hash: string }) =>
    post<{
      success: boolean
      token?: string
      expire?: number
      signature?: string
      urlEndpoint?: string
      uploadUrl?: string
      mediaId: string
      expiresIn: number
      provider: 'R2' | 'IMAGEKIT'
    }>('/media/upload-url', data),

  confirm: (mediaId: string) =>
    post<{ success: boolean; media: Media }>('/media/confirm', { mediaId }),

  upload: async (
    file: File | Blob,
    mediaType: string,
    filename: string,
    onProgress?: (pct: number) => void
  ): Promise<{ success: boolean; media: Media }> => {
    try {
      if (onProgress) onProgress(2) // Started parsing

      // Calculate SHA-256 hash of the file for 100% efficient deduplication on the backend
      const arrayBuffer = await file.arrayBuffer()
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

      if (onProgress) onProgress(5) // Started upload flow

      if (mediaType !== 'VIDEO' && mediaType !== 'IMAGE') {
        return new Promise((resolve, reject) => {
          const normalizedMime = (file.type || 'application/octet-stream').split(';')[0].trim()
          const csrf = getCsrfToken()

          const xhr = new XMLHttpRequest()
          xhr.open('POST', `${API_URL}/api/media/upload`)
          xhr.setRequestHeader('Content-Type', normalizedMime)
          xhr.setRequestHeader('X-Media-Type', mediaType)
          xhr.setRequestHeader('X-Filename', encodeURIComponent(filename))
          xhr.setRequestHeader('X-File-Hash', fileHash)
          if (csrf) xhr.setRequestHeader('x-csrf-token', csrf)

          if (onProgress) {
            onProgress(0)
            xhr.upload.onprogress = (e) => {
              if (e.lengthComputable && e.total > 0) {
                onProgress(Math.round((e.loaded / e.total) * 100))
              } else if (e.loaded > 0) {
                // heuristic for unknown total size
                onProgress(Math.min(95, Math.round(e.loaded / 1024 / 1024)))
              }
            }
            xhr.upload.onloadstart = () => onProgress(1)
            xhr.upload.onloadend = () => onProgress(100)
          }

          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              try { resolve(JSON.parse(xhr.responseText)) } catch { reject(new ApiError('Invalid response', xhr.status)) }
            } else {
              try {
                const data = JSON.parse(xhr.responseText)
                reject(new ApiError(data?.error?.message || 'Upload failed', xhr.status))
              } catch { reject(new ApiError('Upload failed', xhr.status)) }
            }
          }
          xhr.onerror = () => reject(new ApiError('Network error', 0))
          xhr.send(file)
        })
      }

      // VIDEO and IMAGE Path (ImageKit)
      const authRes = await media.getUploadUrl({
        type: mediaType,
        size: file.size,
        mimeType: file.type || 'application/octet-stream',
        filename,
        hash: fileHash
      })

      // If the backend already has this file, it will return the existing media record
      // to completely bypass the upload (100% efficiency)
      if (authRes.success && (authRes as any).media) {
        if (onProgress) onProgress(100)
        return { success: true, media: (authRes as any).media }
      }

      if (!authRes.success || authRes.provider !== 'IMAGEKIT' || !authRes.token || !authRes.signature || !authRes.expire || !authRes.urlEndpoint) {
        throw new ApiError('Failed to get upload authorization', 500)
      }

      if (onProgress) onProgress(15)

      // Initialize ImageKit with the required public info and the specific endpoint
      const ik = new ImageKit({
        publicKey: 'public_Rj7hIaMSgfUH2PjolXWSuTNHWH0=', // Has to be provided, even though Auth provides signature.
        urlEndpoint: authRes.urlEndpoint,
      })

      const folderStr = `/${mediaType.toLowerCase()}`
      const extension = filename.split('.').pop() || 'bin'
      const targetFileName = `${authRes.mediaId}.${extension}`

      return await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest()
        // we use the imagekit upload method which underneath uses xhr so we can hook into progress

        ik.upload({
          file: file,
          fileName: targetFileName,
          folder: folderStr,
          useUniqueFileName: false,
          token: authRes.token!,
          signature: authRes.signature!,
          expire: authRes.expire!,
          xhr: xhr
        }, function (err, _result) { // Added underscore to fix unused variable lint warning
          if (err) {
            reject(new ApiError(err.message || 'ImageKit upload failed', 500))
            return
          }

          if (onProgress) onProgress(90) // Upload done, confirming...

          media.confirm(authRes.mediaId)
            .then(confirmRes => {
              if (onProgress) onProgress(100)
              resolve(confirmRes)
            })
            .catch(confirmErr => {
              reject(confirmErr)
            })
        })

        // Hook up progress event if possible
        if (onProgress) {
          xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable && e.total > 0) {
              // Map 15% -> 90% range for actual file upload
              const pct = 15 + Math.round((e.loaded / e.total) * 75)
              onProgress(pct)
            }
          })
        }
      })
    } catch (err: any) {
      throw err instanceof ApiError ? err : new ApiError(err?.message || 'Upload failed', 500)
    }
  },

  delete: (mediaId: string) =>
    del<{ success: boolean }>(`/media/${mediaId}`),
}

export const preferences = {
  updateEmailNotifications: (enabled: boolean) =>
    patch<{ success: boolean }>('/preferences/email-notifications', {
      emailNotifyOnMessage: enabled,
    }),
}

export const adminStats = {
  get: () =>
    get<{
      success: boolean
      stats: {
        users: { total: number; pending: number; approved: number; rejected: number; suspended: number }
        conversations: number
        messages: number
        activeSessions: number
        activeAnnouncements: number
      }
    }>('/admin/stats'),
}

export const announcementsApi = {
  list: (params?: { before?: string; limit?: number; includeInactive?: boolean }) =>
    get<{ success: boolean; announcements: Announcement[]; hasMore: boolean }>(
      `/announcements${buildQs({ before: params?.before, limit: params?.limit, ...(params?.includeInactive ? { includeInactive: 'true' } : {}) })}`,
    ),

  get: (id: string) =>
    get<{ success: boolean; announcement: Announcement }>(`/announcements/${id}`),

  create: (data: {
    title: string
    content: string
    type?: AnnouncementType
    template?: 'DEFAULT' | 'BANNER' | 'CARD' | 'MINIMAL'
    mediaId?: string
    targetRoles?: string[]
    expiresAt?: string
  }) => post<{ success: boolean; announcement: Announcement }>('/announcements', data),

  update: (id: string, data: {
    title?: string
    content?: string
    type?: AnnouncementType
    template?: 'DEFAULT' | 'BANNER' | 'CARD' | 'MINIMAL'
    mediaId?: string | null
    targetRoles?: string[] | null
    expiresAt?: string | null
    isActive?: boolean
  }) => patch<{ success: boolean; announcement: Announcement }>(`/announcements/${id}`, data),

  vote: (id: string, vote: 'UP' | 'DOWN') =>
    post<{ success: boolean; vote: 'UP' | 'DOWN' | null }>(`/announcements/${id}/vote`, { vote }),

  removeVote: (id: string) =>
    del<{ success: boolean; vote: null }>(`/announcements/${id}/vote`),

  // Reactions (single emoji per user, upsert)
  react: (id: string, emoji: string) =>
    post<{ success: boolean; reaction: { id: string; emoji: string; userId: string } | null }>(`/announcements/${id}/reaction`, { emoji }),

  removeReaction: (id: string) =>
    del<{ success: boolean; reaction: null }>(`/announcements/${id}/reaction`),

  // Comments
  listComments: (id: string, params?: { limit?: number; before?: string }) =>
    get<{ success: boolean; comments: AnnouncementComment[]; hasMore: boolean }>(
      `/announcements/${id}/comments${buildQs({ limit: params?.limit, before: params?.before })}`
    ),

  addComment: (id: string, content: string) =>
    post<{ success: boolean; comment: AnnouncementComment }>(`/announcements/${id}/comments`, { content }),

  deleteComment: (announcementId: string, commentId: string) =>
    del<{ success: boolean; deleted: boolean }>(`/announcements/${announcementId}/comments/${commentId}`),

  remove: (id: string) =>
    del<{ success: boolean }>(`/announcements/${id}`),
}

export interface AppConfig {
  brand: {
    siteName: string
    tagline: string
    company: string
    supportEmail: string
    logoUrl?: string
    primaryColor?: string
  }
  features: {
    userRegistration: boolean
    mediaUpload: boolean
    messageDelete: boolean
    messageDeleteTimeLimit: number
  }
  limits: {
    message: {
      textMaxLength: number
      teamTextMaxLength?: number
      perMinute?: number
      perHour?: number
    }
    media: {
      maxSizeImage: number
      maxSizeVideo: number
      maxSizeDocument: number
      perDay?: number
    }
  }
  rateLimit?: {
    login?: { maxAttempts: number; windowMinutes: number; lockoutMinutes: number }
    api?: { requestsPerMinute: number }
  }
  session?: { maxDevices: number; accessTokenDays: number }
  allowedMimeTypes: Record<string, string[]>
  subsidiaries: Subsidiary[]
}

export const adminInternal = {
  list: (params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; messages: InternalMessage[]; hasMore: boolean }>(
      `/admin/internal${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),

  send: (data: { type?: string; content?: string; mediaId?: string; replyToId?: string }) =>
    post<{ success: boolean; message: InternalMessage }>('/admin/internal', data),

  delete: (id: string, scope: 'me' | 'all' = 'me') =>
    del<{ success: boolean; scope: string }>(`/admin/internal/${id}?scope=${scope}`),

  clear: () =>
    del<{ success: boolean }>('/admin/internal/clear'),

  react: (id: string, emoji: string) =>
    post<{ success: boolean; reaction: { id: string; emoji: string; userId: string; user?: { name: string } } }>(`/admin/internal/${id}/reaction`, { emoji }),

  removeReaction: (id: string, emoji: string) =>
    del<{ success: boolean }>(`/admin/internal/${id}/reaction/${encodeURIComponent(emoji)}`),
}

export type DMConversation = {
  partner: { id: string; name: string; role: string }
  lastMessage: { id: string; content: string | null; type: string; senderId: string; createdAt: number }
}

export const adminDM = {
  listConversations: () =>
    get<{ success: boolean; conversations: DMConversation[] }>('/admin/dm/conversations'),

  list: (adminId: string, params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; messages: DirectMessage[]; hasMore: boolean; partner: { id: string; name: string; role: string } }>(
      `/admin/dm/${adminId}${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),
  send: (adminId: string, data: { content?: string; type?: string; mediaId?: string; tempId?: string; replyToId?: string }) =>
    post<{ success: boolean; message: DirectMessage; tempId?: string }>(`/admin/dm/${adminId}`, data),
  deleteMessage: (messageId: string, scope: 'me' | 'all' = 'all') =>
    del<{ success: boolean }>(`/admin/dm/message/${messageId}?scope=${scope}`),
  react: (adminId: string, messageId: string, emoji: string) =>
    post<{ success: boolean; reaction: { id: string; emoji: string; userId: string; user?: { name: string } } }>(`/admin/dm/${adminId}/${messageId}/reaction`, { emoji }),
  removeReaction: (adminId: string, messageId: string, emoji: string) =>
    del<{ success: boolean }>(`/admin/dm/${adminId}/${messageId}/reaction/${encodeURIComponent(emoji)}`),
}

export const appConfig = {
  get: () => get<{ success: boolean } & AppConfig>('/config'),
  updateBrand: (brand: AppConfig['brand']) => patch<{ success: boolean; brand: AppConfig['brand'] }>('/config/brand', brand),
  updateFeatures: (features: AppConfig['features']) => patch<{ success: boolean; features: AppConfig['features'] }>('/config/features', features),
  updateLimits: (limits: {
    message?: { textMaxLength: number; teamTextMaxLength?: number; perMinute?: number; perHour?: number }
    media?: { maxSizeImage: number; maxSizeVideo: number; maxSizeDocument: number; perDay?: number }
  }) => patch<{ success: boolean; limits: AppConfig['limits'] }>('/config/limits', limits),

  updateSecurity: (body: {
    rateLimit?: { login?: { maxAttempts: number; windowMinutes: number; lockoutMinutes: number }; api?: { requestsPerMinute: number } }
    session?: { maxDevices: number; accessTokenDays: number }
  }) => patch<{ success: boolean }>('/config/security', body),

  updateSubsidiaries: (subsidiaries: Subsidiary[]) =>
    patch<{ success: boolean; subsidiaries: Subsidiary[] }>('/config/subsidiaries', subsidiaries),
}

export type SearchResults = {
  users: Array<{ id: string; name: string; email: string; role: string; status: string; createdAt: number }>
  conversations: Array<{ id: string; lastMessageAt: number | null; unreadCount: number; adminUnreadCount: number; assignedAdminId: string | null; user: { id: string; name: string; email: string; status: string } }>
  announcements: Array<{ id: string; title: string; type: string; isActive: number; createdAt: number }>
  messages: Array<{ id: string; conversationId: string; content: string | null; createdAt: number; sender: { id: string; name: string; role: string } }>
}

export const adminSearch = {
  search: (q: string, type: 'all' | 'users' | 'conversations' | 'announcements' | 'messages' = 'all', limit = 5) =>
    get<{ success: boolean } & SearchResults>(`/admin/search${buildQs({ q, type, limit })}`),
}

export { ApiError }
