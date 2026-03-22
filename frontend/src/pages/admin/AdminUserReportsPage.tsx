import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FileWarning, Clock, RefreshCw, CheckCircle2, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn, formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/empty-state'
import { useAdminUserReports } from '@/hooks/useUserReports'
import { getSocket } from '@/lib/socket'
import { useQueryClient } from '@tanstack/react-query'

interface ReportWithUser {
  id: string
  userId: string
  subject: string
  description: string
  status: 'PENDING' | 'RESOLVED'
  createdAt: number
  user: { id: string; name: string; email: string; status: string }
  media?: { id: string; type: 'IMAGE' | 'DOCUMENT'; cdnUrl: string; filename: string; size: number }
}

function ReportCard({ report, onClick }: { report: ReportWithUser; onClick: () => void }) {
  const isPending = report.status === 'PENDING'

  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-xl border bg-card hover:bg-accent/40 hover:border-primary/30 hover:shadow-sm transition-all group cursor-pointer"
    >
      <div className="p-4">
        <div className="flex items-start gap-3">
          <div className={cn('h-2 w-2 rounded-full shrink-0 mt-2', isPending ? 'bg-amber-500' : 'bg-green-500')} />

          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-semibold text-sm truncate group-hover:text-primary transition-colors">
                {report.subject}
              </h3>
              <Badge
                variant="outline"
                className={cn(
                  'shrink-0 text-[10px] font-medium',
                  isPending
                    ? 'border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-400'
                    : 'border-green-300 text-green-600 bg-green-50 dark:bg-green-900/20 dark:text-green-400'
                )}
              >
                {isPending ? 'Pending' : 'Resolved'}
              </Badge>
            </div>

            <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{report.description}</p>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1">
                  <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-primary/10 text-[8px] font-bold text-primary">
                    {report.user.name.charAt(0).toUpperCase()}
                  </span>
                  {report.user.name}
                </span>
                <span>·</span>
                <span>{formatRelativeTime(report.createdAt)}</span>
              </div>
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
            </div>
          </div>
        </div>
      </div>
    </button>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="rounded-xl border p-4 space-y-2">
          <div className="flex justify-between"><Skeleton className="h-4 w-48" /><Skeleton className="h-5 w-16" /></div>
          <Skeleton className="h-3 w-full" />
        </div>
      ))}
    </div>
  )
}

export function AdminUserReportsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { data, isLoading } = useAdminUserReports()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const invalidate = () => queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })
    const onResolved = (payload: { reportId: string }) => {
      queryClient.setQueryData<{ reports: Array<{ id: string; status: string }> }>(
        ['admin', 'user-reports', undefined],
        (old) => old ? { ...old, reports: old.reports.map(r => r.id === payload.reportId ? { ...r, status: 'RESOLVED' } : r) } : old
      )
      invalidate()
    }
    socket.on('user_report:new', invalidate)
    socket.on('user_report:resolved', onResolved)
    return () => { socket.off('user_report:new', invalidate); socket.off('user_report:resolved', onResolved) }
  }, [queryClient])

  const reports = data?.reports ?? []
  const pendingCount = data?.pendingCount ?? 0

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="p-4 border-b flex items-center justify-between">
          <Skeleton className="h-6 w-40" /><Skeleton className="h-9 w-24" />
        </div>
        <CardSkeleton />
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 sm:p-4 border-b space-y-4 shrink-0">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <FileWarning className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">User Reports</h2>
              <p className="text-[11px] text-muted-foreground">{reports.length} total · {pendingCount} pending</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {pendingCount > 0 && (
              <Badge variant="outline" className="gap-1.5 border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-400 text-[10px]">
                <Clock className="h-3 w-3" /> {pendingCount} pending
              </Badge>
            )}
            <Button variant="outline" size="sm" className="gap-1.5" onClick={() => queryClient.invalidateQueries({ queryKey: ['admin', 'user-reports'] })}>
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </Button>
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-3 sm:p-4 space-y-3">
          {reports.length === 0 ? (
            <EmptyState icon={FileWarning} title="No reports" subtitle="User reports will appear here" />
          ) : (
            reports.map(report => (
              <ReportCard
                key={report.id}
                report={report as ReportWithUser}
                onClick={() => navigate(`/admin/user-reports/${report.id}`)}
              />
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
