import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { toast } from '@/components/ui/sonner'
import { getSocket } from '@/lib/socket'

// Thin fetch wrappers scoped to reports endpoints
const API = import.meta.env.VITE_API_URL || ''
async function reportsGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API}/api${path}`, { credentials: 'include' })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json()
}
async function reportsPatch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}/api${path}`, {
    method: 'PATCH',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json()
}

export interface RegistrationReport {
    id: string
    userId: string
    subject: string
    description: string
    status: 'PENDING' | 'REVIEWED'
    createdAt: number
    user: {
        id: string
        name: string
        email: string
        phone?: string | null
        status: string
        createdAt: number
    }
    media?: {
        id: string
        type: 'IMAGE' | 'DOCUMENT'
        cdnUrl: string | null
        filename: string
        size: number
        mimeType: string
    } | null
}

interface ReportsResponse {
    success: boolean
    reports: RegistrationReport[]
    hasMore: boolean
    pendingCount: number
}

interface SingleReportResponse {
    success: boolean
    report: RegistrationReport
    hasConversation: boolean
}

export function useReports(status: 'PENDING' | 'REVIEWED' | 'ALL' = 'ALL') {
    return useQuery({
        queryKey: ['reports', status],
        queryFn: () =>
            reportsGet<ReportsResponse>(`/admin/reports${status !== 'ALL' ? `?status=${status}` : ''}`),
        staleTime: 0,
    })
}

export function useInfiniteReports(status: 'PENDING' | 'REVIEWED' | 'ALL' = 'ALL') {
    return useInfiniteQuery({
        queryKey: ['reports', 'infinite', status],
        queryFn: ({ pageParam }) => {
            const params = new URLSearchParams()
            if (status !== 'ALL') params.set('status', status)
            if (pageParam) params.set('before', pageParam)
            const qs = params.toString()
            return reportsGet<ReportsResponse>(`/admin/reports${qs ? `?${qs}` : ''}`)
        },
        initialPageParam: undefined as string | undefined,
        getNextPageParam: (lastPage) => {
            if (!lastPage.hasMore || !lastPage.reports.length) return undefined
            return lastPage.reports[lastPage.reports.length - 1].id
        },
        staleTime: 0,
    })
}

export function useReport(id: string | undefined) {
    return useQuery({
        queryKey: ['report', id],
        queryFn: () => reportsGet<SingleReportResponse>(`/admin/reports/${id}`),
        enabled: !!id,
    })
}

export function usePendingReportCount() {
    const { data } = useReports('PENDING')
    return data?.pendingCount ?? 0
}

export function useMarkReportReviewed() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => reportsPatch<{ success: boolean; reviewed: boolean }>(`/admin/reports/${id}`, {}),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      qc.invalidateQueries({ queryKey: ['report', id] })
      toast.success('Report marked as reviewed')
    },
    onError: () => toast.error('Failed to update report'),
  })
}

/**
 * Hook to listen for real-time report status updates from other admins.
 * When another admin approves a user (marking their reports as reviewed),
 * this will update the local cache immediately.
 */
export function useReportStatusListener() {
  const qc = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const onReportReviewed = (data: { userId: string; reportIds: string[]; reviewedBy: string; reviewedAt: number; autoReviewed: boolean }) => {
      // Optimistically update flat query caches (useReports)
      for (const filterKey of ['PENDING', 'ALL', 'REVIEWED'] as const) {
        qc.setQueryData<ReportsResponse>(['reports', filterKey], (old) => {
          if (!old) return old
          const isRemovedFromPending = filterKey === 'PENDING'
          return {
            ...old,
            reports: isRemovedFromPending
              ? old.reports.filter((r) => !data.reportIds.includes(r.id))
              : old.reports.map((r) => data.reportIds.includes(r.id) ? { ...r, status: 'REVIEWED' as const } : r),
            pendingCount: Math.max(0, old.pendingCount - data.reportIds.length),
          }
        })
      }

      // Also patch infinite query caches (useInfiniteReports used by ReportsPage).
      // Without this the pending-count badge and card list on ReportsPage don't
      // update optimistically — they'd wait for the background invalidation refetch.
      for (const filterKey of ['PENDING', 'ALL', 'REVIEWED'] as const) {
        qc.setQueryData<{ pages: ReportsResponse[]; pageParams: unknown[] }>(
          ['reports', 'infinite', filterKey],
          (old) => {
            if (!old) return old
            const isRemovedFromPending = filterKey === 'PENDING'
            return {
              ...old,
              pages: old.pages.map((page) => ({
                ...page,
                reports: isRemovedFromPending
                  ? page.reports.filter((r) => !data.reportIds.includes(r.id))
                  : page.reports.map((r) => data.reportIds.includes(r.id) ? { ...r, status: 'REVIEWED' as const } : r),
                pendingCount: Math.max(0, page.pendingCount - data.reportIds.length),
              })),
            }
          }
        )
      }

      // Invalidate all report queries to trigger refetch
      qc.invalidateQueries({ queryKey: ['reports'] })

      // Update individual report cache entries
      data.reportIds.forEach((reportId) => {
        qc.setQueryData<SingleReportResponse>(['report', reportId], (old) => {
          if (!old) return old
          return {
            ...old,
            report: { ...old.report, status: 'REVIEWED' },
          }
        })
      })

      // Show toast notification
      if (data.autoReviewed) {
        toast.success(`User approved and report auto-reviewed`)
      } else {
        toast.success('Report marked as reviewed by another admin')
      }
    }

    socket.on('report:reviewed', onReportReviewed)
    return () => { socket.off('report:reviewed', onReportReviewed) }
  }, [qc])
}
