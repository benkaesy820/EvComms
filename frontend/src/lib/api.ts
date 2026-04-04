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

export const API_URL = import.meta.env.VITE_API_URL || ''

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

// SECURITY FIX: Tokens now stored in httpOnly cookies only, not localStorage
// This prevents XSS attacks from stealing tokens
let memoryToken: string | null = null
let memoryCsrfToken: string | null = null

// DEPRECATED: localStorage token storage removed for security
// Tokens are now stored in httpOnly secure cookies by the backend
export function getAuthToken(): string | null {
  // Return memory token if available (for the current session)
  return memoryToken
}

function setAuthToken(token: string | null) {
  // Store in memory only - httpOnly cookie handles persistence
  memoryToken = token
}

// Refresh token is delivered via httpOnly cookie by the backend.
// No client-side storage needed — the browser sends it automatically with credentials: 'include'.

function getCsrfToken(): string | null {
  if (memoryCsrfToken) return memoryCsrfToken
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
    const res = await fetch(`${API_URL}/api/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    })
    if (!res.ok) {
      if (res.status === 401) {
        const waiters = refreshWaiters
        refreshWaiters = []
        isRefreshing = false
        waiters.forEach((cb) => cb(false))
        return false
      }
      // Transient server error — tell waiters to retry with existing token
      const waiters = refreshWaiters
      refreshWaiters = []
      isRefreshing = false
      waiters.forEach((cb) => cb(true))
      throw new Error(`Refresh failed with ${res.status}`)
    }
    const data = await res.json().catch(() => ({}))
    if (data.token) {
      setAuthToken(data.token)
    }
    if (data.csrfToken) {
      memoryCsrfToken = data.csrfToken
    }
    const waiters = refreshWaiters
    refreshWaiters = []
    isRefreshing = false
    waiters.forEach((cb) => cb(true))
    return true
  } catch (err) {
    const isTransient = err instanceof Error && (err.message.startsWith('Refresh failed with') || err.message === 'Failed to fetch' || err.message === 'NetworkError' || err.message === 'Network request failed')
    const waiters = refreshWaiters
    refreshWaiters = []
    isRefreshing = false
    if (isTransient) {
      // Server/network error — tell waiters the refresh "succeeded" so they
      // retry their original request with the existing (still-valid) token.
      waiters.forEach((cb) => cb(true))
      throw err
    }
    waiters.forEach((cb) => cb(false))
    return false
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
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const csrf = getCsrfToken()
    if (csrf) headers['x-csrf-token'] = csrf
  }
  const token = getAuthToken()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return fetch(url, { ...options, credentials: 'include', headers })
}

// Tracks consecutive network-level failures (not HTTP errors).
// After 3 in a row, we assume the user has connectivity issues.
let consecutiveNetworkFailures = 0
let networkWarningShown = false

function isNetworkError(err: unknown): boolean {
  if (err instanceof TypeError) {
    const msg = err.message.toLowerCase()
    return msg.includes('fetch') || msg.includes('network') || msg.includes('load')
  }
  return false
}

function handleNetworkFailure() {
  consecutiveNetworkFailures++
  if (consecutiveNetworkFailures >= 3 && !networkWarningShown) {
    networkWarningShown = true
    // Dispatch a custom event so the UI can show a banner/toast
    window.dispatchEvent(new CustomEvent('network:degraded'))
  }
}

function handleNetworkSuccess() {
  if (consecutiveNetworkFailures >= 3 && networkWarningShown) {
    networkWarningShown = false
    window.dispatchEvent(new CustomEvent('network:restored'))
  }
  consecutiveNetworkFailures = 0
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const isAuthPath = path.startsWith('/auth/')
  let res: Response
  try {
    res = await requestOnce(path, options)
    handleNetworkSuccess()
  } catch (err) {
    handleNetworkFailure()
    throw err
  }

  // Wait! Do not refresh on login status checks (me endpoint) 
  // because that creates an infinite loop if the user is truly logged out
  if (res.status === 401 && !isAuthPath && path !== '/me') {
    try {
      const success = await tryRefreshToken()
      if (success) {
        res = await requestOnce(path, options)
      } else {
        window.dispatchEvent(new CustomEvent('auth:expired'))
      }
    } catch {
      // Transient error during refresh (5xx, network) — do NOT log out.
      // Let the original 401 propagate; the token may still be valid.
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
    }
    if ('token' in data && typeof data.token === 'string' && isAuthPath && (path === '/auth/login' || path === '/auth/refresh' || path === '/auth/password/change')) {
      setAuthToken(data.token)
    }
    if ('refreshToken' in data && typeof data.refreshToken === 'string' && isAuthPath && (path === '/auth/login' || path === '/auth/refresh' || path === '/auth/password/change')) {
      // Refresh token is stored in httpOnly cookie by the backend — no client-side storage needed.
    }
    if (isAuthPath && (path === '/auth/logout' || path === '/auth/sessions/revoke-all')) {
      setAuthToken(null)
    }
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

  // SECURITY FIX: Refresh token read from httpOnly cookie automatically
  // No longer sent in request body to prevent token exposure
  refresh: () =>
    post<{
      success: boolean
      token: string
      csrfToken: string
      refreshToken: string
      user: User
    }>('/auth/refresh'),

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

  create: (subsidiaryId?: string) =>
    post<{ success: boolean; conversation: Conversation }>('/conversations', subsidiaryId ? { subsidiaryId } : undefined),

  updateSubsidiary: (conversationId: string, subsidiaryId: string | null) =>
    patch<{ success: boolean }>(`/conversations/${conversationId}/subsidiary`, { subsidiaryId }),

  getOne: (id: string) =>
    get<{ success: boolean; conversation: Conversation }>(`/conversations/${id}`),

  getAdmin: (params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; conversations: Conversation[]; hasMore: boolean; nextCursor?: string }>(
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
    post<{ success: boolean; readCount: number }>(
      `/conversations/${conversationId}/mark-read`,
      {},
    ),

  assign: (conversationId: string, adminId: string | null) =>
    patch<{ success: boolean }>(`/conversations/${conversationId}/assign`, { adminId }),

  forUser: (userId: string, reportId?: string) =>
    post<{ success: boolean; conversation: { id: string } }>('/conversations/for-user', { userId, reportId }),

  // Archive/Unarchive
  archive: (conversationId: string, closingNote?: string) =>
    patch<{ archived: boolean }>(`/conversations/${conversationId}/archive`, { closingNote }),

  unarchive: (conversationId: string) =>
    patch<{ unarchived: boolean }>(`/conversations/${conversationId}/unarchive`),

  reopen: (conversationId: string) =>
    post<{ reopened: boolean }>(`/conversations/${conversationId}/reopen`),

  // List archived conversations (admin only, with ?archived=true)
  getArchived: (params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; conversations: Conversation[]; hasMore: boolean; nextCursor?: string }>(
      `/conversations${buildQs({ before: params?.before, limit: params?.limit, archived: 'true' })}`,
    ),

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

  revokeSessions: (userId: string) =>
    post<{ success: boolean; message: string }>(`/admin/users/${userId}/revoke-sessions`),

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

  triggerMediaCleanup: () =>
    post<{ success: boolean; message: string; results: { cleanedCount: number; failedCount: number; totalProcessed: number } }>('/admin/cleanup/media'),
}

export const adminAdmins = {
  list: () =>
    get<{ success: boolean; admins: User[]; superAdmins: User[]; hasMoreAdmins: boolean; hasMoreSuperAdmins: boolean }>('/admin/admins'),

  create: (data: { email: string; password: string; name: string }) =>
    post<{ success: boolean; admin: User }>('/admin/admins', data),

  updateRole: (userId: string, data: { role: 'ADMIN' | 'USER' }) =>
    patch<{ success: boolean; message: string }>(`/admin/admins/${userId}/role`, data),

  suspend: (userId: string) =>
    patch<{ success: boolean; message: string }>(`/admin/admins/${userId}/suspend`, {}),

  reactivate: (userId: string) =>
    patch<{ success: boolean; message: string }>(`/admin/admins/${userId}/reactivate`, {}),

  updateSubsidiaries: (userId: string, subsidiaryIds: string[]) =>
    patch<{ success: boolean; subsidiaryIds: string[] }>(`/admin/admins/${userId}/subsidiaries`, { subsidiaryIds }),
}

export const media = {
  getUploadUrl: (data: { type: string; size: number; mimeType: string; filename: string; hash: string; context?: string }) =>
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
      media?: Media
      imagekitPublicKey?: string
    }>('/media/upload-url', data),

  confirm: (mediaId: string) =>
    post<{ success: boolean; media: Media }>('/media/confirm', { mediaId }),

  confirmWithMeta: (mediaId: string, actualSize?: number, actualMimeType?: string, cdnUrl?: string) =>
    post<{ success: boolean; media: Media }>('/media/confirm', {
      mediaId,
      ...(actualSize !== undefined && { actualSize }),
      ...(actualMimeType !== undefined && { actualMimeType }),
      ...(cdnUrl !== undefined && { cdnUrl }),
    }),

  upload: async (
    file: File | Blob,
    mediaType: string,
    filename: string,
    onProgress?: (pct: number) => void,
    context?: string
  ): Promise<{ success: boolean; media: Media }> => {
    try {
      if (onProgress) onProgress(2) // Started parsing

      // Calculate SHA-256 hash of the file for 100% efficient deduplication on the backend
      const arrayBuffer = await file.arrayBuffer()
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

      if (onProgress) onProgress(5) // Started upload flow

      if (mediaType !== 'IMAGE') {
        return new Promise((resolve, reject) => {
          const normalizedMime = (file.type || 'application/octet-stream').split(';')[0].trim()
          const csrf = getCsrfToken()

          const xhr = new XMLHttpRequest()
          xhr.open('POST', `${API_URL}/api/media/upload`)
          xhr.setRequestHeader('Content-Type', normalizedMime)
          xhr.setRequestHeader('X-Media-Type', mediaType)
          xhr.setRequestHeader('X-Filename', encodeURIComponent(filename))
          xhr.setRequestHeader('X-File-Hash', fileHash)
          if (context) xhr.setRequestHeader('X-Upload-Context', context)
          if (csrf) xhr.setRequestHeader('x-csrf-token', csrf)
          const token = getAuthToken()
          if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)

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

      // IMAGE Path (ImageKit)
      const authRes = await media.getUploadUrl({
        type: mediaType,
        size: file.size,
        mimeType: file.type || 'application/octet-stream',
        filename,
        hash: fileHash,
        ...(context && { context })
      })

      // If the backend already has this file, it will return the existing media record
      // to completely bypass the upload (100% efficiency)
      if (authRes.success && authRes.media) {
        if (onProgress) onProgress(100)
        return { success: true, media: authRes.media }
      }

      if (!authRes.success || authRes.provider !== 'IMAGEKIT' || !authRes.token || !authRes.signature || !authRes.expire || !authRes.urlEndpoint) {
        throw new ApiError('Failed to get upload authorization', 500)
      }

      if (onProgress) onProgress(15)

      // Resolve the ImageKit public key: prefer value from config response (set at server from IMAGEKIT_PUBLIC_KEY env),
      // fall back to the value returned in the auth response so it is never hardcoded in source.
      const ikPublicKey = authRes.imagekitPublicKey ?? ''

      const folderStr = `/${mediaType.toLowerCase()}`
      const extension = filename.split('.').pop() || 'bin'
      const targetFileName = `${authRes.mediaId}.${extension}`

      // Use direct XHR multipart upload to ImageKit's upload endpoint.
      // The imagekit-javascript SDK v4 dropped callback support and the `xhr`
      // parameter, which caused silent failures for all VIDEO/IMAGE uploads.
      // Direct XHR gives us full control over progress events and timeout.
      return await new Promise((resolve, reject) => {
        const form = new FormData()
        form.append('file', file)
        form.append('fileName', targetFileName)
        form.append('folder', folderStr)
        form.append('useUniqueFileName', 'false')
        form.append('token', authRes.token!)
        form.append('signature', authRes.signature!)
        form.append('expire', String(authRes.expire!))
        form.append('publicKey', ikPublicKey)

        const xhr = new XMLHttpRequest()
        xhr.open('POST', 'https://upload.imagekit.io/api/v1/files/upload')
        xhr.timeout = 60000 // 1 min timeout

        xhr.ontimeout = () => reject(new ApiError('Upload timed out', 408))
        xhr.onerror = () => reject(new ApiError('ImageKit upload failed due to network error', 500))

        if (onProgress) {
          xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable && e.total > 0) {
              // Map 15% → 88% range for actual file upload
              const pct = 15 + Math.round((e.loaded / e.total) * 73)
              onProgress(pct)
            }
          })
        }

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            if (onProgress) onProgress(90) // Upload done, confirming...
            // Parse ImageKit response to get the actual CDN URL and file metadata
            let actualSize: number | undefined
            let actualMimeType: string | undefined
            let cdnUrl: string | undefined
            try {
              const ikResponse = JSON.parse(xhr.responseText)
              if (ikResponse?.size) actualSize = ikResponse.size
              if (ikResponse?.mime) actualMimeType = ikResponse.mime
              // Use the URL ImageKit returns — it includes the correct folder path
              if (ikResponse?.url) cdnUrl = ikResponse.url
            } catch { /* ignore parse error */ }
            media.confirmWithMeta(authRes.mediaId, actualSize, actualMimeType, cdnUrl)
              .then(confirmRes => {
                if (onProgress) onProgress(100)
                resolve(confirmRes)
              })
              .catch(reject)
          } else {
            let msg = 'ImageKit upload failed'
            try {
              const body = JSON.parse(xhr.responseText)
              if (body?.message) msg = body.message
            } catch { /* ignore parse error */ }
            reject(new ApiError(`${msg} (${xhr.status})`, xhr.status))
          }
        }

        xhr.send(form)
      })
    } catch (err: unknown) {
      throw err instanceof ApiError ? err : new ApiError((err as Error)?.message || 'Upload failed', 500)
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

export const users = {
  getProfile: () =>
    get<{ success: boolean; user: User }>('/users/me'),

  updateProfile: (data: { name?: string; email?: string; phone?: string | null }) =>
    patch<{ success: boolean; message: string; updates: string[] }>('/users/me', data),

  getMedia: (params?: { status?: string; limit?: number; before?: string }) =>
    get<{
      success: boolean
      media: Array<Media & { messageId: string | null; uploadedAt: number; status: string }>
      hasMore: boolean
      nextCursor?: string
    }>(`/users/me/media${buildQs({ status: params?.status, limit: params?.limit, before: params?.before })}`),

  deleteMedia: (mediaId: string) =>
    del<{ success: boolean; deleted: boolean }>(`/users/me/media/${mediaId}`),
}

export const adminStats = {
  get: () =>
    get<{
      success: boolean
      stats: {
        scope?: string
        users: { total: number; pending: number; approved: number; rejected: number; suspended: number }
        conversations: number | { assigned: number; waiting: number }
        messages: number
        activeSessions: number
        activeAnnouncements: number
      }
    }>('/admin/stats'),
}

export interface QueueAdminWorkload {
  adminId: string
  name: string
  role: 'ADMIN' | 'SUPER_ADMIN'
  activeCount: number
  isOnline: boolean
}

export interface QueueWaitingItem {
  conversationId: string
  userId: string
  userName: string
  assignedAdminId: string | null
  assignedAdminName: string | null
  waitingSince: number | null
  waitMs: number
}

export interface QueueIdleItem {
  conversationId: string
  userId: string
  userName: string
  assignedAdminId: string | null
  assignedAdminName: string | null
  lastAdminReplyAt: number | null
  idleMs: number
}

export interface QueueData {
  unassignedCount: number
  unassigned: { id: string; userId: string; createdAt: number; waitingSince: number | null; user: { id: string; name: string; email: string } | null }[]
  waiting: QueueWaitingItem[]
  idle: QueueIdleItem[]
  adminWorkloads: QueueAdminWorkload[]
  config: { maxConversationsPerAdmin: number; idleThresholdHours: number }
}

export const adminQueue = {
  get: () => get<{ success: boolean; queue: QueueData }>('/admin/queue'),
}


export const announcementsApi = {
  list: (params?: { before?: string; limit?: number; includeInactive?: boolean }) =>
    get<{ success: boolean; announcements: Announcement[]; hasMore: boolean }>(
      `/announcements${buildQs({ before: params?.before, limit: params?.limit, ...(params?.includeInactive ? { includeInactive: 'true' } : {}) })}`,
    ),

  // Public endpoint for unauthenticated users
  listPublic: (params?: { before?: string; limit?: number }) =>
    get<{ success: boolean; announcements: Announcement[]; hasMore: boolean }>(
      `/announcements/public${buildQs({ before: params?.before, limit: params?.limit })}`,
    ),

  get: (id: string) =>
    get<{ success: boolean; announcement: Announcement }>(`/announcements/${id}`),

  getPublic: (id: string) =>
    get<{ success: boolean; announcement: Announcement }>(`/announcements/${id}/public`),

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

export const userReportsApi = {
  // User endpoints
  create: (data: {
    subject: string
    description: string
    mediaId?: string
  }) => post<{ success: boolean; reportId: string; message: string }>('/user-reports', data),

  list: (params?: { before?: string; limit?: number; status?: 'PENDING' | 'RESOLVED' | 'ALL' }) =>
    get<{ success: boolean; reports: Array<{
      id: string
      userId: string
      subject: string
      description: string
      status: 'PENDING' | 'RESOLVED'
      createdAt: number
      media?: {
        id: string
        type: 'IMAGE' | 'DOCUMENT'
        cdnUrl: string
        filename: string
        size: number
      }
    }>; hasMore: boolean }>(
      `/user-reports${buildQs({ before: params?.before, limit: params?.limit, status: params?.status })}`,
    ),

  get: (id: string) =>
    get<{ success: boolean; report: {
      id: string
      userId: string
      subject: string
      description: string
      status: 'PENDING' | 'RESOLVED'
      createdAt: number
      media?: {
        id: string
        type: 'IMAGE' | 'DOCUMENT'
        cdnUrl: string
        filename: string
        size: number
        mimeType: string
      }
    } }>(`/user-reports/${id}`),

  // Admin endpoints
  adminList: (params?: { before?: string; limit?: number; status?: 'PENDING' | 'RESOLVED' | 'ALL' }) =>
    get<{ success: boolean; reports: Array<{
      id: string
      userId: string
      subject: string
      description: string
      status: 'PENDING' | 'RESOLVED'
      createdAt: number
      user: {
        id: string
        name: string
        email: string
        status: string
      }
      media?: {
        id: string
        type: 'IMAGE' | 'DOCUMENT'
        cdnUrl: string
        filename: string
        size: number
      }
    }>; hasMore: boolean; pendingCount: number }>(
      `/admin/user-reports${buildQs({ before: params?.before, limit: params?.limit, status: params?.status })}`,
    ),

  adminGet: (id: string) =>
    get<{ success: boolean; report: {
      id: string
      userId: string
      subject: string
      description: string
      status: 'PENDING' | 'RESOLVED'
      createdAt: number
      user: {
        id: string
        name: string
        email: string
        phone: string | null
        status: string
      }
      media?: {
        id: string
        type: 'IMAGE' | 'DOCUMENT'
        cdnUrl: string
        filename: string
        size: number
        mimeType: string
      }
    } }>(`/admin/user-reports/${id}`),

  resolve: (id: string) =>
    patch<{ success: boolean; resolved: boolean }>(`/admin/user-reports/${id}`, {}),
}

export interface AppConfig {
  brand: {
    siteName: string
    tagline: string
    company: string
    supportEmail: string
    logoUrl?: string
    statResponseTime?: string
    statUptime?: string
    statAvailability?: string
  }
  features: {
    userRegistration: boolean
    mediaUpload: boolean
    messageDelete?: boolean
    messageDeleteTimeLimitSeconds?: number
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
      maxSizeDocument: number
      perDay?: number
    }
    upload?: {
      presignedUrlTTL?: number
    }
  }
  rateLimit?: {
    login?: { maxAttempts: number; windowMinutes: number; lockoutMinutes: number }
    api?: { requestsPerMinute: number }
  }
  session?: { maxDevices: number; accessTokenDays: number }
  allowedMimeTypes: Record<string, string[]>
  subsidiaries: Subsidiary[]
  imagekitPublicKey?: string | null
  storefront?: {
    landing?: {
      heroHeadline?: string
      heroSubheadline?: string
      ctaPrimary?: string
      ctaSecondary?: string
      showHowItWorks?: boolean
      showFeatures?: boolean
      showStats?: boolean
    }
    contact?: {
      responseTime?: string
      officeHours?: string
      address?: string
      phone?: string
      showLiveChat?: boolean
    }
    faq?: Array<{ id: string; question: string; answer: string }>
    social?: {
      twitter?: string
      linkedin?: string
      instagram?: string
      facebook?: string
      youtube?: string
    }
    legal?: {
      termsLastUpdated?: string
      privacyLastUpdated?: string
      companyLegalName?: string
      registrationNumber?: string
      vatNumber?: string
    }
  } | null
  storage?: {
    imagekitPublicKey?: string | null
    imagekitUrlEndpoint?: string | null
  }
  assignment?: {
    maxConversationsPerAdmin: number
    superAdminThreshold: number
    preferOnlineAdmins: boolean
  }
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

  getUnreadCount: () =>
    get<{ success: boolean; unreadCount: number }>('/admin/internal/unread'),

  markAsRead: () =>
    post<{ success: boolean }>('/admin/internal/read', {}),

  // FIX #18: Bulk delete via single backend transaction
  bulkDelete: (ids: string[], scope: 'me' | 'all' = 'me') =>
    post<{ success: boolean; succeeded: number; failed: number; failedIds: string[] }>('/admin/internal/bulk-delete', { ids, scope }),
}

export type DMConversation = {
  partner: { id: string; name: string; role: string }
  lastMessage: { id: string; content: string | null; type: string; senderId: string; createdAt: number }
  unreadCount: number
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
  getUnreadCount: () =>
    get<{ success: boolean; unreadCount: number }>('/admin/dm/unread'),
  markAsRead: (adminId: string) =>
    post<{ success: boolean }>(`/admin/dm/${adminId}/read`, {}),
  bulkDelete: (adminId: string, ids: string[], scope: 'me' | 'all' = 'me') =>
    post<{ success: boolean; succeeded: number; failed: number; failedIds: string[] }>(`/admin/dm/${adminId}/bulk-delete`, { ids, scope }),
  clear: (adminId: string) =>
    del<{ success: boolean }>(`/admin/dm/${adminId}/clear`),
}

export const appConfig = {
  get: () => get<{ success: boolean } & AppConfig>('/config'),
  updateBrand: (brand: AppConfig['brand']) => patch<{ success: boolean; brand: AppConfig['brand'] }>('/config/brand', brand),
  updateFeatures: (features: AppConfig['features']) => patch<{ success: boolean; features: AppConfig['features'] }>('/config/features', features),
  updateLimits: (limits: {
    message?: { textMaxLength: number; teamTextMaxLength?: number; perMinute?: number; perHour?: number }
    media?: { maxSizeImage: number; maxSizeDocument: number; perDay?: number }
    upload?: { presignedUrlTTL?: number }
  }) => patch<{ success: boolean; limits: AppConfig['limits'] }>('/config/limits', limits),

  updateSecurity: (body: {
    rateLimit?: { login?: { maxAttempts: number; windowMinutes: number; lockoutMinutes: number }; api?: { requestsPerMinute: number } }
    session?: { maxDevices: number; accessTokenDays: number }
  }) => patch<{ success: boolean }>('/config/security', body),

  updateStorage: (body: {
    imagekitPublicKey?: string
    imagekitUrlEndpoint?: string
  }) => patch<{ success: boolean; storage: AppConfig['storage'] }>('/config/storage', body),

  updateSubsidiaries: (subsidiaries: Subsidiary[]) =>
    patch<{ success: boolean; subsidiaries: Subsidiary[] }>('/config/subsidiaries', subsidiaries),

  updateAssignment: (data: { maxConversationsPerAdmin?: number; superAdminThreshold?: number; preferOnlineAdmins?: boolean }) =>
    patch<{ success: boolean; assignment: AppConfig['assignment'] }>('/config/assignment', data),

  updateStorefront: (data: NonNullable<AppConfig['storefront']>) =>
    patch<{ success: boolean; storefront: AppConfig['storefront'] }>('/config/storefront', data),
}

export type SearchResults = {
  users: Array<{ id: string; name: string; email: string; role: string; status: string; createdAt: number }>
  conversations: Array<{ id: string; lastMessageAt: number | null; unreadCount: number; adminUnreadCount: number; assignedAdminId: string | null; user: { id: string; name: string; email: string; status: string } }>
  announcements: Array<{ id: string; title: string; type: string; isActive: number; createdAt: number }>
  messages: Array<{ id: string; conversationId: string; content: string | null; createdAt: number; sender: { id: string; name: string; role: string } }>
  registrationReports: Array<{ id: string; subject: string; description: string; status: string; createdAt: number; userId: string; user: { id: string; name: string; email: string } }>
  userReports: Array<{ id: string; subject: string; description: string; status: string; createdAt: number; userId: string; user: { id: string; name: string; email: string } }>
}

export type SearchType = 'all' | 'users' | 'conversations' | 'announcements' | 'messages' | 'reports'

export const adminSearch = {
  search: (q: string, type: SearchType = 'all', limit = 5) =>
    get<{ success: boolean } & SearchResults>(`/admin/search${buildQs({ q, type, limit })}`),
}

export { ApiError }
export const notifications = {
  getVapidPublicKey: () =>
    get<{ success: boolean; publicKey: string }>('/notifications/vapid-public-key'),
  subscribe: (data: { endpoint: string; keys: { p256dh: string; auth: string } }) =>
    post<{ success: boolean }>('/notifications/subscribe', data),
  unsubscribe: (data: { endpoint: string }) =>
    request<{ success: boolean }>('/notifications/unsubscribe', { method: 'DELETE', body: JSON.stringify(data) }),
  testPush: () => post<{ success: boolean; message: string }>('/notifications/test-push'),
}
