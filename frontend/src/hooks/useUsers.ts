import { useQuery, useMutation, useQueryClient, useInfiniteQuery, type InfiniteData } from '@tanstack/react-query'
import { adminUsers, adminAdmins, auth } from '@/lib/api'
import type { Status, User } from '@/lib/schemas'
import { toast } from 'sonner'
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
          if (!old) return old
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
      queryClient.setQueriesData<InfiniteData<{ success: boolean; users: User[]; hasMore: boolean }>>(
        { queryKey: ['admin', 'users'] },
        (old) => {
          if (!old) return old
          return {
            ...old,
            pages: old.pages.map((p) => ({
              ...p,
              users: p.users.map((u) => u.id === data.userId ? { ...u, status: data.status } : u)
            }))
          }
        }
      )
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', data.userId] })
    }

    socket.on('admin:user_registered', handleUserRegistered)
    socket.on('user:status_changed', handleStatusChanged)

    return () => {
      socket.off('admin:user_registered', handleUserRegistered)
      socket.off('user:status_changed', handleStatusChanged)
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
    staleTime: 60_000,
  })
}

export function useAdminUserDetail(userId: string | undefined) {
  return useQuery({
    queryKey: ['admin', 'users', userId],
    queryFn: () => adminUsers.getUser(userId!),
    enabled: !!userId,
    staleTime: 60_000,
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
          if (!old) return old
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
      // Also refresh the individual user detail if it's cached
      queryClient.invalidateQueries({ queryKey: ['admin', 'users', variables.userId] })
      toast.success('User status updated')
    },
    onError: (err) => {
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
          if (!old) return old
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
    staleTime: 30_000,
  })
}

export function useAdminList() {
  return useQuery({
    queryKey: ['admin', 'admins'],
    queryFn: async () => {
      const res = await adminAdmins.list()
      return { ...res, allAdmins: [...(res.superAdmins ?? []), ...res.admins] }
    },
    staleTime: 60_000,
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
