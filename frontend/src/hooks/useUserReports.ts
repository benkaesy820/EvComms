import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { userReportsApi, media as mediaApi } from '@/lib/api'
import { toast } from '@/components/ui/sonner'

export interface UserReport {
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
}

export function useUserReports(params?: { status?: 'PENDING' | 'RESOLVED' | 'ALL'; limit?: number }) {
  return useQuery({
    queryKey: ['user-reports', params],
    queryFn: () => userReportsApi.list(params),
    staleTime: 0,
  })
}

export function useCreateUserReport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: { subject: string; description: string; mediaId?: string }) =>
      userReportsApi.create(data),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      toast.success(res.message || 'Report submitted successfully')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to submit report')
    },
  })
}


export function useUserReport(id: string | undefined) {
  return useQuery({
    queryKey: ['user-report', id],
    queryFn: () => userReportsApi.get(id!),
    enabled: !!id,
    staleTime: 0,
  })
}

export function useAdminUserReport(id: string | undefined) {
  return useQuery({
    queryKey: ['admin', 'user-report', id],
    queryFn: () => userReportsApi.adminGet(id!),
    enabled: !!id,
    staleTime: 0,
  })
}

export function useAdminUserReports(params?: { status?: 'PENDING' | 'RESOLVED' | 'ALL'; limit?: number }) {
  return useQuery({
    queryKey: ['admin', 'user-reports', params],
    queryFn: () => userReportsApi.adminList(params),
    staleTime: 0,
  })
}

export function useResolveUserReport() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => userReportsApi.resolve(id),
    onMutate: async (id: string) => {
      // Optimistically flip status AND decrement pendingCount in admin cache
      const flipAdminStatus = (old: { reports: Array<{ id: string; status: string }>; pendingCount: number } | undefined) => {
        if (!old) return old
        const wasPending = old.reports.find(r => r.id === id)?.status === 'PENDING'
        return {
          ...old,
          reports: old.reports.map(r => r.id === id ? { ...r, status: 'RESOLVED' } : r),
          pendingCount: wasPending ? Math.max(0, old.pendingCount - 1) : old.pendingCount,
        }
      }
      // Flip status only (no pendingCount) in user cache
      const flipUserStatus = (old: { reports: Array<{ id: string; status: string }> } | undefined) =>
        old ? { ...old, reports: old.reports.map(r => r.id === id ? { ...r, status: 'RESOLVED' } : r) } : old
      queryClient.setQueriesData({ queryKey: ['admin', 'user-reports'] }, flipAdminStatus)
      queryClient.setQueriesData({ queryKey: ['user-reports'] }, flipUserStatus)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      toast.success('Report resolved')
    },
    onError: (err) => {
      // Roll back on error
      queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      toast.error(err instanceof Error ? err.message : 'Failed to resolve report')
    },
  })
}

export function useUploadMedia() {
  return useMutation({
    mutationFn: async ({ file, type, onProgress, context }: { file: File; type: 'IMAGE' | 'DOCUMENT'; onProgress?: (progress: number) => void; context?: string }) => {
      return mediaApi.upload(file, type, file.name, onProgress, context)
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to upload file')
    },
  })
}
