import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '@/lib/schemas'
import { auth as authApi, ApiError } from '@/lib/api'
import { connectSocket, disconnectSocket } from '@/lib/socket'

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean

  login: (email: string, password: string) => Promise<void>
  register: (data: { email: string; password: string; name: string; phone?: string }) => Promise<string>
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
          return res.message
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      logout: async () => {
        try {
          await authApi.logout()
        } catch {
          return
        } finally {
          disconnectSocket()
          set({ user: null, isAuthenticated: false })
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
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) {
            disconnectSocket()
            set({ user: null, isAuthenticated: false })
          }
        }
      },

      reset: () => {
        disconnectSocket()
        set({ user: null, isAuthenticated: false, isLoading: false })
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
      onRehydrateStorage: () => () => {
        // App.tsx handles actual validation
      },
    },
  ),
)
