import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import {
  FileWarning, CheckCircle2, Clock, RefreshCw, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { useInfiniteReports } from '@/hooks/useReports'
import type { RegistrationReport } from '@/hooks/useReports'
import { useAuthStore } from '@/stores/authStore'
import { Skeleton } from '@/components/ui/skeleton'

function parseTs(ts: number | string | null | undefined): Date {
  if (!ts) return new Date()
  const n = typeof ts === 'string' ? parseInt(ts, 10) : ts
  return new Date(n < 1e12 ? n * 1000 : n)
}

function ReportCard({ report, onClick }: { report: RegistrationReport; onClick: () => void }) {
  const isPending = report.status === 'PENDING'
  const userApproved = report.user.status === 'APPROVED'

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-xl border bg-card hover:bg-accent/40 hover:shadow-sm transition-all group cursor-pointer',
        isPending && 'border-amber-200 dark:border-amber-800/60 hover:border-amber-300'
      )}
    >
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Avatar */}
          <div className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-[11px] font-bold',
            userApproved
              ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
              : 'bg-muted text-muted-foreground'
          )}>
            {report.user.name.charAt(0).toUpperCase()}
          </div>

          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold truncate group-hover:text-primary transition-colors">
                {report.user.name}
              </span>
              <Badge
                variant="outline"
                className={cn(
                  'text-[10px] font-medium shrink-0',
                  isPending
                    ? 'border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-400'
                    : 'border-green-300 text-green-600 bg-green-50 dark:bg-green-900/20 dark:text-green-400'
                )}
              >
                {isPending ? 'Pending Review' : 'Reviewed'}
              </Badge>
              {!userApproved && (
                <Badge variant="secondary" className="text-[10px] shrink-0">
                  <Clock className="h-2.5 w-2.5 mr-1" />Not Approved
                </Badge>
              )}
            </div>

            <p className="text-xs text-muted-foreground truncate">{report.user.email}</p>

            <p className="text-xs text-foreground/80 font-medium truncate">"{report.subject}"</p>

            <div className="flex items-center justify-between pt-1">
              <span className="text-[10px] text-muted-foreground">
                {format(parseTs(report.createdAt), 'MMM d, yyyy')}
              </span>
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
    <div className="space-y-2">
      {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 w-full rounded-xl" />)}
    </div>
  )
}

export function ReportsPage() {
  const navigate = useNavigate()
  const user = useAuthStore(s => s.user)
  const [filter, setFilter] = useState<'ALL' | 'PENDING' | 'REVIEWED'>('PENDING')

  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useInfiniteReports(filter)

  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  if (!isAdmin) {
    return <div className="flex items-center justify-center h-full text-muted-foreground text-sm">Access restricted to Admins.</div>
  }

  const reports = data?.pages.flatMap(p => p.reports) ?? []
  const pendingCount = data?.pages[0]?.pendingCount ?? 0

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 border-b px-4 py-3 bg-background shrink-0">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/20">
          <FileWarning className="h-5 w-5 text-amber-600 dark:text-amber-400" />
        </div>
        <div className="flex-1 min-w-0">
          <h1 className="text-sm font-bold">Registration Reports</h1>
          <p className="text-[11px] text-muted-foreground">
            {pendingCount > 0 ? `${pendingCount} pending review` : 'All reports reviewed'}
          </p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border p-0.5">
          {(['PENDING', 'ALL', 'REVIEWED'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-2.5 py-1 text-xs rounded-md transition-colors',
                filter === f ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {f === 'ALL' ? 'All' : f === 'PENDING' ? 'Pending' : 'Reviewed'}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {isLoading ? <CardSkeleton /> : reports.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 py-20 text-muted-foreground">
            <CheckCircle2 className="h-10 w-10" />
            <p className="text-sm font-medium">No {filter !== 'ALL' ? filter.toLowerCase() : ''} reports</p>
          </div>
        ) : (
          reports.map(report => (
            <ReportCard
              key={report.id}
              report={report}
              onClick={() => navigate(`/admin/reports/${report.id}`)}
            />
          ))
        )}
      </div>

      {hasNextPage && (
        <div className="flex justify-center py-3 border-t shrink-0">
          <Button variant="ghost" size="sm" onClick={() => fetchNextPage()} disabled={isFetchingNextPage} className="gap-1.5 text-xs text-muted-foreground">
            {isFetchingNextPage && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
            {isFetchingNextPage ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  )
}
