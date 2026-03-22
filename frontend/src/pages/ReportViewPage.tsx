import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { format } from 'date-fns'
import {
  ArrowLeft, FileWarning, Clock, CheckCircle2,
  MessageSquare, Users2, FileText, FileImage, ExternalLink,
  Download, User, Mail, Phone, Shield, Calendar, Hash,
  AlertCircle, CheckCheck, Loader2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { useReport, useMarkReportReviewed } from '@/hooks/useReports'
import { useUserReport, useAdminUserReport, useResolveUserReport } from '@/hooks/useUserReports'
import { adminUsers, conversations as convApi } from '@/lib/api'
import { toast } from '@/components/ui/sonner'
import { useState } from 'react'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'

function parseTs(ts: number | string | null | undefined): Date {
  if (!ts) return new Date()
  const n = typeof ts === 'string' ? parseInt(ts, 10) : ts
  return new Date(n < 1e12 ? n * 1000 : n)
}

function StatusBadge({ status, type }: { status: string; type: 'reg' | 'user' }) {
  if (type === 'reg') {
    if (status === 'PENDING') return (
      <Badge className="gap-1.5 bg-amber-100 text-amber-700 border-amber-300 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-700 hover:bg-amber-100">
        <Clock className="h-3 w-3" /> Pending Review
      </Badge>
    )
    return (
      <Badge className="gap-1.5 bg-green-100 text-green-700 border-green-300 dark:bg-green-900/30 dark:text-green-400 dark:border-green-700 hover:bg-green-100">
        <CheckCheck className="h-3 w-3" /> Reviewed
      </Badge>
    )
  }
  if (status === 'PENDING') return (
    <Badge className="gap-1.5 bg-amber-100 text-amber-700 border-amber-300 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-700 hover:bg-amber-100">
      <Clock className="h-3 w-3" /> Pending
    </Badge>
  )
  return (
    <Badge className="gap-1.5 bg-green-100 text-green-700 border-green-300 dark:bg-green-900/30 dark:text-green-400 dark:border-green-700 hover:bg-green-100">
      <CheckCircle2 className="h-3 w-3" /> Resolved
    </Badge>
  )
}

function UserStatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; className: string }> = {
    APPROVED: { label: 'Approved', className: 'bg-green-100 text-green-700 border-green-300 dark:bg-green-900/30 dark:text-green-400' },
    PENDING: { label: 'Pending', className: 'bg-amber-100 text-amber-700 border-amber-300 dark:bg-amber-900/30 dark:text-amber-400' },
    SUSPENDED: { label: 'Suspended', className: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-400' },
    REJECTED: { label: 'Rejected', className: 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-400' },
  }
  const cfg = map[status] ?? { label: status, className: '' }
  return (
    <Badge variant="outline" className={cn('text-[10px] font-medium', cfg.className)}>
      {cfg.label}
    </Badge>
  )
}

function AttachmentCard({ media }: {
  media: { type: string; cdnUrl?: string | null; filename: string; size: number; mimeType?: string }
}) {
  const isImage = media.type === 'IMAGE'
  const hasUrl = !!media.cdnUrl

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      {isImage && hasUrl && (
        <div className="relative bg-muted/30 border-b">
          <img
            src={media.cdnUrl!}
            alt={media.filename}
            className="w-full max-h-64 object-contain"
          />
        </div>
      )}
      <a
        href={hasUrl ? media.cdnUrl! : undefined}
        target="_blank"
        rel="noopener noreferrer"
        className={cn(
          'flex items-center gap-3 p-4 transition-colors group',
          hasUrl ? 'hover:bg-muted/30 cursor-pointer' : 'cursor-default'
        )}
      >
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
          {isImage ? <FileImage className="h-5 w-5" /> : <FileText className="h-5 w-5" />}
        </div>
        <div className="flex-1 min-w-0">
          <p className={cn('text-sm font-medium truncate', hasUrl && 'group-hover:text-primary transition-colors')}>
            {media.filename}
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">
            {(media.size / 1024 / 1024).toFixed(2)} MB
            {media.mimeType && ` · ${media.mimeType.split('/')[1]?.toUpperCase() ?? media.type}`}
          </p>
        </div>
        {hasUrl
          ? <ExternalLink className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-primary transition-colors" />
          : <Download className="h-4 w-4 text-muted-foreground/40 shrink-0" />
        }
      </a>
    </div>
  )
}

function InfoRow({ icon: Icon, label, value, mono }: {
  icon: typeof User
  label: string
  value: string | null | undefined
  mono?: boolean
}) {
  if (!value) return null
  return (
    <div className="flex items-start gap-3 py-2.5">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className={cn('text-sm mt-0.5 break-all', mono && 'font-mono text-xs')}>{value}</p>
      </div>
    </div>
  )
}

function PageSkeleton() {
  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0">
        <Skeleton className="h-8 w-8 rounded-lg" />
        <Skeleton className="h-5 w-48" />
        <Skeleton className="h-5 w-20 ml-auto" />
      </div>
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 max-w-5xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <Skeleton className="h-8 w-3/4" />
            <Skeleton className="h-4 w-1/3" />
            <Skeleton className="h-40 w-full rounded-xl" />
            <Skeleton className="h-28 w-full rounded-xl" />
          </div>
          <div className="space-y-4">
            <Skeleton className="h-48 w-full rounded-xl" />
            <Skeleton className="h-32 w-full rounded-xl" />
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Registration Report View (Admin only) ─────────────────────────────────────

function RegistrationReportView({ id }: { id: string }) {
  const navigate = useNavigate()
  const user = useAuthStore(s => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'

  const { data, isLoading, isError } = useReport(id)
  const markReviewed = useMarkReportReviewed()
  const [approveDialog, setApproveDialog] = useState(false)
  const [isApproving, setIsApproving] = useState(false)
  const [creatingChat, setCreatingChat] = useState(false)

  if (isLoading) return <PageSkeleton />

  if (isError || !data?.report) {
    return (
      <div className="flex flex-col h-full items-center justify-center gap-4 text-muted-foreground p-8">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertCircle className="h-8 w-8 text-destructive/60" />
        </div>
        <div className="text-center">
          <p className="font-semibold text-foreground">Report not found</p>
          <p className="text-sm mt-1">It may have been deleted or you don't have access.</p>
        </div>
        <Button variant="outline" onClick={() => navigate(-1)} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Go Back
        </Button>
      </div>
    )
  }

  const { report, hasConversation } = data
  const userApproved = report.user.status === 'APPROVED'

  const handleApprove = async () => {
    setIsApproving(true)
    try {
      await adminUsers.updateStatus(report.user.id, { status: 'APPROVED' })
      setApproveDialog(false)
      toast.success(`${report.user.name} approved — they can now log in.`)
    } catch {
      toast.error('Failed to approve user — please try again.')
    } finally {
      setIsApproving(false)
    }
  }

  const handleCreateChat = async () => {
    setCreatingChat(true)
    try {
      const res = await convApi.forUser(report.user.id, report.id)
      if (res.success && res.conversation) {
        navigate(`/admin?conversationId=${res.conversation.id}`)
      }
    } catch {
      toast.error('Failed to create conversation')
    } finally {
      setCreatingChat(false)
    }
  }

  return (
    <>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0 bg-background">
        <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => navigate(-1)}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 shrink-0">
            <FileWarning className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
          </div>
          <span className="text-sm font-semibold truncate">Registration Report</span>
        </div>
        <StatusBadge status={report.status} type="reg" />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-4 sm:p-6 max-w-5xl mx-auto w-full">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* ── Left: Main content ── */}
            <div className="lg:col-span-2 space-y-5 order-2 lg:order-1">

              {/* Subject + Meta */}
              <div>
                <h1 className="text-xl font-bold leading-tight">"{report.subject}"</h1>
                <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Calendar className="h-3 w-3" />
                    Submitted {format(parseTs(report.createdAt), 'MMM d, yyyy · h:mm a')}
                  </span>
                  <span className="text-muted-foreground/40">·</span>
                  <span className="flex items-center gap-1 font-mono">
                    <Hash className="h-3 w-3" />
                    {report.id.slice(-8).toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Description */}
              <div className="rounded-xl border bg-card">
                <div className="px-4 py-3 border-b">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Description</p>
                </div>
                <div className="p-4">
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{report.description}</p>
                </div>
              </div>

              {/* Attachment */}
              {report.media && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Attachment</p>
                  <AttachmentCard media={report.media} />
                </div>
              )}
            </div>

            {/* ── Right: Sidebar ── */}
            <div className="space-y-4 order-1 lg:order-2">

              {/* Reporter card */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b flex items-center justify-between">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Applicant</p>
                  <UserStatusBadge status={report.user.status} />
                </div>
                <div className="px-4 py-2 divide-y divide-border/60">
                  <div className="flex items-center gap-3 py-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary font-bold text-sm">
                      {report.user.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{report.user.name}</p>
                      <p className="text-[10px] text-muted-foreground">Registered {format(parseTs(report.user.createdAt), 'MMM d, yyyy')}</p>
                    </div>
                  </div>
                  <InfoRow icon={Mail} label="Email" value={report.user.email} />
                  {report.user.phone && <InfoRow icon={Phone} label="Phone" value={report.user.phone} />}
                </div>
              </div>

              {/* Actions */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Actions</p>
                </div>
                <div className="p-3 space-y-2">
                  {!userApproved && (
                    <Button className="w-full gap-2 justify-start" onClick={() => setApproveDialog(true)}>
                      <CheckCircle2 className="h-4 w-4" />
                      Approve Applicant
                    </Button>
                  )}
                  {userApproved && (
                    <Button variant="outline" className="w-full gap-2 justify-start" disabled={creatingChat} onClick={handleCreateChat}>
                      {creatingChat
                        ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <MessageSquare className="h-4 w-4" />}
                      {hasConversation ? 'Open Chat' : 'Create Chat'}
                    </Button>
                  )}
                  {report.status === 'PENDING' && isSuperAdmin && (
                    <Button
                      variant="ghost"
                      className="w-full gap-2 justify-start text-muted-foreground"
                      disabled={markReviewed.isPending}
                      onClick={() => markReviewed.mutate(report.id)}
                    >
                      {markReviewed.isPending
                        ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <CheckCheck className="h-4 w-4" />}
                      Mark as Reviewed
                    </Button>
                  )}
                  <Separator />
                  <Button
                    variant="ghost"
                    className="w-full gap-2 justify-start text-muted-foreground text-xs"
                    onClick={() => navigate(`/admin/users?highlight=${report.user.id}`)}
                  >
                    <Users2 className="h-3.5 w-3.5" />
                    View in Users
                  </Button>
                </div>
              </div>

              {/* Meta */}
              <div className="rounded-xl border bg-card px-4 py-2 divide-y divide-border/60">
                <InfoRow icon={Hash} label="Report ID" value={report.id.slice(-8).toUpperCase()} mono />
                <InfoRow icon={Shield} label="Type" value="Registration Report" />
                <InfoRow icon={Calendar} label="Submitted" value={format(parseTs(report.createdAt), 'MMM d, yyyy · h:mm a')} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <AlertDialog open={approveDialog} onOpenChange={o => { if (!o && !isApproving) setApproveDialog(false) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Approve Registration</AlertDialogTitle>
            <AlertDialogDescription>
              This will approve <strong>{report.user.name}</strong>'s account and let them log in.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleApprove} disabled={isApproving}>
              {isApproving ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Approving…</> : 'Approve'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── Admin User Report View ────────────────────────────────────────────────────

function AdminUserReportView({ id }: { id: string }) {
  const navigate = useNavigate()
  const { data, isLoading, isError } = useAdminUserReport(id)
  const resolveReport = useResolveUserReport()
  const [resolveDialog, setResolveDialog] = useState(false)
  const [creatingChat, setCreatingChat] = useState(false)

  if (isLoading) return <PageSkeleton />

  if (isError || !data?.report) {
    return (
      <div className="flex flex-col h-full items-center justify-center gap-4 text-muted-foreground p-8">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertCircle className="h-8 w-8 text-destructive/60" />
        </div>
        <div className="text-center">
          <p className="font-semibold text-foreground">Report not found</p>
          <p className="text-sm mt-1">It may have been deleted or you don't have access.</p>
        </div>
        <Button variant="outline" onClick={() => navigate(-1)} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Go Back
        </Button>
      </div>
    )
  }

  const report = data.report
  const isPending = report.status === 'PENDING'

  const handleCreateChat = async () => {
    setCreatingChat(true)
    try {
      const res = await convApi.forUser(report.user.id)
      if (res.success && res.conversation) {
        navigate(`/admin?conversationId=${res.conversation.id}`)
      }
    } catch {
      toast.error('Failed to open conversation')
    } finally {
      setCreatingChat(false)
    }
  }

  return (
    <>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0 bg-background">
        <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => navigate(-1)}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 shrink-0">
            <FileWarning className="h-3.5 w-3.5 text-primary" />
          </div>
          <span className="text-sm font-semibold truncate">User Report</span>
        </div>
        <StatusBadge status={report.status} type="user" />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-4 sm:p-6 max-w-5xl mx-auto w-full">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* ── Left: Main content ── */}
            <div className="lg:col-span-2 space-y-5 order-2 lg:order-1">
              <div>
                <h1 className="text-xl font-bold leading-tight">{report.subject}</h1>
                <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Calendar className="h-3 w-3" />
                    {format(parseTs(report.createdAt), 'MMM d, yyyy · h:mm a')}
                  </span>
                  <span className="text-muted-foreground/40">·</span>
                  <span className="flex items-center gap-1 font-mono">
                    <Hash className="h-3 w-3" />
                    {report.id.slice(-8).toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="rounded-xl border bg-card">
                <div className="px-4 py-3 border-b">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Description</p>
                </div>
                <div className="p-4">
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{report.description}</p>
                </div>
              </div>

              {report.media && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Attachment</p>
                  <AttachmentCard media={report.media} />
                </div>
              )}
            </div>

            {/* ── Right: Sidebar ── */}
            <div className="space-y-4 order-1 lg:order-2">

              {/* Reporter card */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b flex items-center justify-between">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Submitted By</p>
                  <UserStatusBadge status={report.user.status} />
                </div>
                <div className="px-4 py-2 divide-y divide-border/60">
                  <div className="flex items-center gap-3 py-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary font-bold text-sm">
                      {report.user.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{report.user.name}</p>
                      <p className="text-[10px] text-muted-foreground truncate">{report.user.email}</p>
                    </div>
                  </div>
                  {report.user.phone && <InfoRow icon={Phone} label="Phone" value={report.user.phone} />}
                </div>
              </div>

              {/* Actions */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Actions</p>
                </div>
                <div className="p-3 space-y-2">
                  {isPending && (
                    <Button
                      className="w-full gap-2 justify-start bg-green-600 hover:bg-green-700 text-white"
                      onClick={() => setResolveDialog(true)}
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      Mark as Resolved
                    </Button>
                  )}
                  <Button variant="outline" className="w-full gap-2 justify-start" disabled={creatingChat} onClick={handleCreateChat}>
                    {creatingChat
                      ? <Loader2 className="h-4 w-4 animate-spin" />
                      : <MessageSquare className="h-4 w-4" />}
                    Open / Create Chat
                  </Button>
                  <Separator />
                  <Button
                    variant="ghost"
                    className="w-full gap-2 justify-start text-muted-foreground text-xs"
                    onClick={() => navigate(`/admin/users?highlight=${report.user.id}`)}
                  >
                    <Users2 className="h-3.5 w-3.5" />
                    View in Users
                  </Button>
                </div>
              </div>

              {/* Meta */}
              <div className="rounded-xl border bg-card px-4 py-2 divide-y divide-border/60">
                <InfoRow icon={Hash} label="Report ID" value={report.id.slice(-8).toUpperCase()} mono />
                <InfoRow icon={Shield} label="Type" value="User Report" />
                <InfoRow icon={Calendar} label="Submitted" value={format(parseTs(report.createdAt), 'MMM d, yyyy · h:mm a')} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <AlertDialog open={resolveDialog} onOpenChange={setResolveDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Mark as Resolved?</AlertDialogTitle>
            <AlertDialogDescription>
              This will mark the report as resolved. The user will be notified.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-green-600 hover:bg-green-700"
              onClick={async () => {
                await resolveReport.mutateAsync(report.id)
                setResolveDialog(false)
              }}
              disabled={resolveReport.isPending}
            >
              {resolveReport.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <CheckCircle2 className="h-4 w-4 mr-2" />}
              Mark Resolved
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── User's Own Report View ────────────────────────────────────────────────────

function UserReportView({ id }: { id: string }) {
  const navigate = useNavigate()
  const { data, isLoading, isError } = useUserReport(id)

  if (isLoading) return <PageSkeleton />

  if (isError || !data?.report) {
    return (
      <div className="flex flex-col h-full items-center justify-center gap-4 text-muted-foreground p-8">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertCircle className="h-8 w-8 text-destructive/60" />
        </div>
        <div className="text-center">
          <p className="font-semibold text-foreground">Report not found</p>
          <p className="text-sm mt-1">It may have been deleted or you don't have access.</p>
        </div>
        <Button variant="outline" onClick={() => navigate(-1)} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Go Back
        </Button>
      </div>
    )
  }

  const report = data.report
  const isPending = report.status === 'PENDING'

  return (
    <>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0 bg-background">
        <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => navigate(-1)}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 shrink-0">
            <FileWarning className="h-3.5 w-3.5 text-primary" />
          </div>
          <span className="text-sm font-semibold truncate">My Report</span>
        </div>
        <StatusBadge status={report.status} type="user" />
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        <div className="p-4 sm:p-6 max-w-3xl mx-auto w-full space-y-5">

          {/* Status Banner */}
          <div className={cn(
            'rounded-xl border p-4 flex items-start gap-3',
            isPending
              ? 'bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-800'
              : 'bg-green-50 border-green-200 dark:bg-green-950/30 dark:border-green-800'
          )}>
            {isPending
              ? <Clock className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              : <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400 shrink-0 mt-0.5" />
            }
            <div>
              <p className={cn(
                'text-sm font-semibold',
                isPending ? 'text-amber-700 dark:text-amber-400' : 'text-green-700 dark:text-green-400'
              )}>
                {isPending ? 'Under Review' : 'Report Resolved'}
              </p>
              <p className={cn(
                'text-xs mt-0.5',
                isPending ? 'text-amber-600/80 dark:text-amber-500' : 'text-green-600/80 dark:text-green-500'
              )}>
                {isPending
                  ? 'Our team has received your report and will respond shortly.'
                  : 'This report has been reviewed and resolved by our team.'}
              </p>
            </div>
          </div>

          {/* Subject + Meta */}
          <div>
            <h1 className="text-xl font-bold leading-tight">{report.subject}</h1>
            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Calendar className="h-3 w-3" />
                Submitted {format(parseTs(report.createdAt), 'MMM d, yyyy · h:mm a')}
              </span>
              <span className="text-muted-foreground/40">·</span>
              <span className="flex items-center gap-1 font-mono">
                <Hash className="h-3 w-3" />
                #{report.id.slice(-8).toUpperCase()}
              </span>
            </div>
          </div>

          {/* Description */}
          <div className="rounded-xl border bg-card">
            <div className="px-4 py-3 border-b">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Your Message</p>
            </div>
            <div className="p-4">
              <p className="text-sm leading-relaxed whitespace-pre-wrap">{report.description}</p>
            </div>
          </div>

          {/* Attachment */}
          {report.media && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Attached File</p>
              <AttachmentCard media={report.media} />
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ─── Router ────────────────────────────────────────────────────────────────────

export function ReportViewPage() {
  const { id } = useParams<{ id: string }>()
  const location = useLocation()

  if (!id) return null

  // Detect context from URL path
  if (location.pathname.startsWith('/admin/reports/')) {
    return <div className="flex flex-col h-full overflow-hidden"><RegistrationReportView id={id} /></div>
  }
  if (location.pathname.startsWith('/admin/user-reports/')) {
    return <div className="flex flex-col h-full overflow-hidden"><AdminUserReportView id={id} /></div>
  }
  // /home/reports/:id — user's own report
  return <div className="flex flex-col h-full overflow-hidden"><UserReportView id={id} /></div>
}
