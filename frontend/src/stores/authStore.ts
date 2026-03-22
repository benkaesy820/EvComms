import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '@/lib/schemas'
import { auth as authApi, ApiError } from '@/lib/api'
import { connectSocket, disconnectSocket } from '@/lib/socket'

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  isHydrated: boolean

  login: (email: string, password: string) => Promise<void>
  register: (data: { email: string; password: string; name: string; phone?: string; reportSubject?: string; reportDescription?: string; reportMediaId?: string }) => Promise<{ success: boolean; message: string; user: User }>
  logout: () => Promise<void>
  setUser: (user: User) => void
  setLoggedIn: (loggedIn: boolean) => void
  refreshUser: () => Promise<void>
  reset: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      isHydrated: false,

      login: async (email, password) => {
        set({ isLoading: true })
        try {
          const res = await authApi.login({ email, password })
          set({
            user: res.user,
            isAuthenticated: true,
            isLoading: false,
          })
          connectSocket()
          scheduleTokenRefresh()
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      register: async (data) => {
        set({ isLoading: true })
        try {
          const res = await authApi.register(data)
          set({ isLoading: false })
          return res // Return full response including token and user
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      logout: async () => {
        const userId = useAuthStore.getState().user?.id
        try {
          await authApi.logout()
        } catch {
          return
        } finally {
          // Clear persisted nudge-dismiss keys for this user so another user
          // logging in on the same browser gets a clean slate
          if (userId) {
            try {
              const prefix = `nudge-dismissed-at:${userId}:`
              Object.keys(localStorage)
                .filter(k => k.startsWith(prefix))
                .forEach(k => localStorage.removeItem(k))
            } catch { /* localStorage unavailable */ }
          }
          disconnectSocket()
          set({ user: null, isAuthenticated: false })
          if (refreshTimer) {
            clearTimeout(refreshTimer)
            refreshTimer = null
          }
        }
      },

      setUser: (user) => set({ user }),

      setLoggedIn: (loggedIn) => {
        set({ isAuthenticated: loggedIn })
      },

      refreshUser: async () => {
        try {
          const res = await authApi.me()
          set({ user: res.user, isAuthenticated: true })
          scheduleTokenRefresh()
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) {
            // Attempt an explicit token refresh since /me doesn't auto-refresh via interceptor
            try {
              // SECURITY FIX: No token passed - read from httpOnly cookie
              const refreshRes = await authApi.refresh()
              // If successful, the interceptor saves the new token and we update state
              set({ user: refreshRes.user, isAuthenticated: true })
              connectSocket()
              scheduleTokenRefresh()
            } catch (refreshErr) {
              // Refresh failed (or refresh token expired too), wipe state fully
              disconnectSocket()
              set({ user: null, isAuthenticated: false })
            }
          } else {
            // Other errors (like 500 or network offline) don't necessarily mean we're logged out
            // We just fail the refresh silently or let it retry, preserving state.
          }
        }
      },

      reset: () => {
        const userId = useAuthStore.getState().user?.id
        if (userId) {
          try {
            const prefix = `nudge-dismissed-at:${userId}:`
            Object.keys(localStorage)
              .filter(k => k.startsWith(prefix))
              .forEach(k => localStorage.removeItem(k))
          } catch { /* localStorage unavailable */ }
        }
        disconnectSocket()
        set({ user: null, isAuthenticated: false, isLoading: false })
        if (refreshTimer) {
          clearTimeout(refreshTimer)
          refreshTimer = null
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
      onRehydrateStorage: () => () => {
        // Mark hydration complete so RootRoute can stop showing the loader.
        // setTimeout defers past the `const useAuthStore = create(...)` assignment —
        // Zustand v5 fires this callback synchronously during create(), so
        // `useAuthStore` is still undefined at the point of the call without the defer.
        setTimeout(() => useAuthStore.setState({ isHydrated: true }), 0)
      },
    },
  ),
)

// Proactive Token Refresh Timer (for 15-minute tokens)
// Refreshes 60-90 seconds before expiry to prevent 401s
let refreshTimer: ReturnType<typeof setTimeout> | null = null

// SECURITY FIX: No longer relies on localStorage for token expiry
// Uses fixed interval based on known JWT expiry (15 minutes)
// This prevents tampering with expiry times
const TOKEN_REFRESH_INTERVAL_MS = 13 * 60 * 1000 // Refresh every 13 minutes (for 15 min tokens)

function scheduleTokenRefresh() {
  if (refreshTimer) {
    clearTimeout(refreshTimer)
    refreshTimer = null
  }
  
  // SECURITY FIX: Use fixed interval instead of parsing JWT from localStorage
  // This prevents users from tampering with expiry times
  refreshTimer = setTimeout(() => {
    useAuthStore.getState().refreshUser()
  }, TOKEN_REFRESH_INTERVAL_MS)
}



// Native Cross-Tab Auth Synchronization
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key === 'auth-storage' && event.newValue) {
      try {
        const parsed = JSON.parse(event.newValue)
        const newAuthState = parsed?.state
        const currentAuthState = useAuthStore.getState()

        // Tab B sees Tab A logged in -> Hydrate and connect socket
        if (newAuthState?.isAuthenticated && !currentAuthState.isAuthenticated) {
          currentAuthState.refreshUser()
        }
        // Tab B sees Tab A logged out -> Teardown and lock UI
        else if (!newAuthState?.isAuthenticated && currentAuthState.isAuthenticated) {
          currentAuthState.reset()
        }
      } catch (e) {
        // Ignore parse errors safely
      }
    }
  })
}
