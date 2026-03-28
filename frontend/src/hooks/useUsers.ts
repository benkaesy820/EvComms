import { useQuery, useMutation, useQueryClient, useInfiniteQuery, type InfiniteData } from '@tanstack/react-query'
import { adminUsers, adminAdmins, auth } from '@/lib/api'
import type { Status, User } from '@/lib/schemas'
import { toast } from '@/components/ui/sonner'
import { getSocket } from '@/lib/socket'
import { useEffect } from 'react'

export function useAdminUsers(params?: {
  status?: Status
  role?: string
  search?: string
}) {
  const queryClient = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const handleUserRegistered = (data: { user: { id: string; email: string; name: string; status: Status; createdAt: number } }) => {
      // Add the new user to the top of the first page
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: User[]; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          // Only add if it doesn't already exist to prevent dupes
          const exists = old.pages.some(p => p.users.some(u => u.id === data.user.id))
          if (exists) return old

          const newUser: User = {
            ...data.user,
            role: 'USER',
            mediaPermission: false,
            emailNotifyOnMessage: true,
          }

          return {
            ...old,
            pages: old.pages.map((p, i) => i === 0 ? { ...p, users: [newUser, ...p.users] } : p)
          }
        }
      )
    }

  const handleStatusChanged = (data: { userId: string; status: Status; reason?: string }) => {
      // If a user was approved, their registration reports changed — invalidate so badge updates
      if (data.status === 'APPROVED') {
        queryClient.invalidateQueries({ queryKey: ['reports'] })
      }
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: User[]; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          if (!Array.isArray((old.pages[0] as { users?: unknown })?.users)) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              users: p.users.map((u) => u.id === data.userId ? { ...u, status: data.status } : u)
            }))
          }
        }
      )
      
      // Update conversations cache so the chat UI sidebar and headers reflect the new status
      queryClient.setQueriesData<InfiniteData<{ success: boolean; conversations: Array<{ id: string; user?: { id: string; status: string;[key: string]: unknown };[key: string]: unknown }>; hasMore: boolean }>>(
        { queryKey: ['conversations'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          if (!Array.isArray((old.pages[0] as { conversations?: unknown })?.conversations)) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              conversations: p.conversations.map((c) =>
                c.user?.id === data.userId ? { ...c, user: { ...c.user, status: data.status } } : c
              ),
            })),
          }
        }
      )
      
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', data.userId] })
    }

    const handleAssignmentChange = () => {
      // Whenever conversations are assigned or removed globally, invalidate the user cache
      // This seamlessly pops the user into/out of the normal admin's User Management page.
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
    }

    socket.on('admin:user_registered', handleUserRegistered)
    socket.on('user:status_changed', handleStatusChanged)
    socket.on('conversation:assigned', handleAssignmentChange)
    socket.on('conversation:assigned_to_you', handleAssignmentChange)
    socket.on('conversation:removed', handleAssignmentChange)

    return () => {
      socket.off('admin:user_registered', handleUserRegistered)
      socket.off('user:status_changed', handleStatusChanged)
      socket.off('conversation:assigned', handleAssignmentChange)
      socket.off('conversation:assigned_to_you', handleAssignmentChange)
      socket.off('conversation:removed', handleAssignmentChange)
    }
  }, [queryClient])

  return useInfiniteQuery({
    queryKey: ['admin', 'users', params],
    queryFn: ({ pageParam }) =>
      adminUsers.list({ ...params, before: pageParam, limit: 30 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      if (!lastPage.hasMore || lastPage.users.length === 0) return undefined
      return lastPage.users[lastPage.users.length - 1].id
    },
    staleTime: 0,
  })
}

export function useAdminUserDetail(userId: string | undefined) {
  return useQuery({
    queryKey: ['admin', 'user', userId],
    queryFn: () => adminUsers.getUser(userId!),
    enabled: !!userId,
    staleTime: 0,
  })
}

export function useUpdateUserStatus() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ userId, status, reason }: { userId: string; status: Status; reason?: string }) =>
      adminUsers.updateStatus(userId, { status, reason }),
    onSuccess: (_data, variables) => {
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: Array<{ id: string; status: string;[key: string]: unknown }>; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          if (!Array.isArray((old.pages[0] as { users?: unknown })?.users)) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              users: page.users.map((u) =>
                u.id === variables.userId ? { ...u, status: variables.status } : u
              ),
            })),
          }
        },
      )
      
      // Update conversations cache so the chat UI sidebar and headers reflect the new status immediately
      queryClient.setQueriesData<InfiniteData<{ success: boolean; conversations: Array<{ id: string; user?: { id: string; status: string;[key: string]: unknown };[key: string]: unknown }>; hasMore: boolean }>>(
        { queryKey: ['conversations'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          if (!Array.isArray((old.pages[0] as { conversations?: unknown })?.conversations)) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              conversations: page.conversations.map((c) =>
                c.user?.id === variables.userId ? { ...c, user: { ...c.user, status: variables.status } } : c
              ),
            })),
          }
        },
      )
      
      // Also refresh the individual user detail if it's cached
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', variables.userId] })
      toast.success('User status updated')
    },
    onError: (err, variables) => {
      // Even on error, invalidate cache so the UI reflects actual DB state.
      // A Turso ECONNRESET can cause a false 500 while the status actually
      // committed — refetching shows ground truth within one cycle.
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', variables.userId] })
      toast.error(err instanceof Error ? err.message : 'Failed to update status')
    },
  })
}

export function useUpdateMediaPermission() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ userId, mediaPermission }: { userId: string; mediaPermission: boolean }) =>
      adminUsers.updateMediaPermission(userId, { mediaPermission }),
    onSuccess: (_data, variables) => {
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: Array<{ id: string; mediaPermission?: boolean;[key: string]: unknown }>; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old || !('pages' in old)) return old
          if (!Array.isArray((old.pages[0] as { users?: unknown })?.users)) return old
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              users: page.users.map((u) =>
                u.id === variables.userId ? { ...u, mediaPermission: variables.mediaPermission } : u
              ),
            })),
          }
        },
      )
      toast.success('Media permission updated')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to update permission')
    },
  })
}

export function useStatusHistory(userId: string | undefined) {
  return useInfiniteQuery({
    queryKey: ['admin', 'users', userId, 'status-history'],
    queryFn: ({ pageParam }) =>
      adminUsers.statusHistory(userId!, { before: pageParam, limit: 20 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      if (!lastPage.hasMore || lastPage.history.length === 0) return undefined
      return lastPage.history[lastPage.history.length - 1].id
    },
    enabled: !!userId,
  })
}

export function useAuditLogs(params?: {
  action?: string
  entityType?: string
  userId?: string
}) {
  const queryClient = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const handleCacheInvalidate = (data: { keys: string[] }) => {
      if (data.keys.some(k => k.includes('audit'))) {
        queryClient.invalidateQueries({ queryKey: ['admin', 'audit-logs'] })
      }
    }

    socket.on('cache:invalidate', handleCacheInvalidate)
    return () => {
      socket.off('cache:invalidate', handleCacheInvalidate)
    }
  }, [queryClient])

  return useInfiniteQuery({
    queryKey: ['admin', 'audit-logs', params],
    queryFn: ({ pageParam }) =>
      adminUsers.auditLogs({ ...params, before: pageParam, limit: 30 }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => {
      if (!lastPage.hasMore || lastPage.logs.length === 0) return undefined
      return lastPage.logs[lastPage.logs.length - 1].id
    },
    staleTime: 0,
  })
}

export function useAdminList() {
  return useQuery({
    queryKey: ['admin', 'admins'],
    queryFn: async () => {
      const res = await adminAdmins.list()
      return { ...res, allAdmins: [...(res.superAdmins ?? []), ...res.admins] }
    },
    staleTime: 30_000, // refresh every 30s so workload counts stay reasonably current
  })
}

export function useCreateAdmin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: { email: string; password: string; name: string }) =>
      adminAdmins.create(data),
    onSuccess: (res) => {
      queryClient.setQueryData<{ success: boolean; admins: User[]; superAdmins: User[]; allAdmins: User[]; hasMoreAdmins: boolean; hasMoreSuperAdmins: boolean }>(
        ['admin', 'admins'],
        (old) => {
          if (!old) return old
          const newAdmin = res.admin
          return {
            ...old,
            admins: [newAdmin, ...old.admins],
            allAdmins: [newAdmin, ...old.allAdmins],
          }
        }
      )
      toast.success('Admin created')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to create admin')
    },
  })
}

export function useInitiatePasswordReset() {
  return useMutation({
    mutationFn: (user: User) => auth.forgotPassword(user.email),
    onSuccess: (_data, user) => {
      toast.success(`Password reset email sent to ${user.email}`)
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to send reset email')
    },
  })
}

export function useRevokeSessions() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (userId: string) => adminUsers.revokeSessions(userId),
    onSuccess: (_data, userId) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', userId] })
      toast.success('All user sessions revoked successfully')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke sessions')
    },
  })
}

export function useUpdateAdminRole() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: 'ADMIN' | 'USER' }) =>
      adminAdmins.updateRole(userId, { role }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'user', variables.userId] })
      toast.success(`Admin role updated to ${variables.role}`)
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to update admin role')
    },
  })
}

export function useTriggerMediaCleanup() {
  return useMutation({
    mutationFn: () => adminUsers.triggerMediaCleanup(),
    onSuccess: (data) => {
      toast.success(`Media cleanup completed: ${data.results.cleanedCount} cleaned, ${data.results.failedCount} failed`)
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to trigger media cleanup')
    },
  })
}
