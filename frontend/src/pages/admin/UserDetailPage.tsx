import { useNavigate, useParams } from 'react-router-dom'
import { format } from 'date-fns'
import {
  ArrowLeft, CheckCircle, XCircle, ShieldOff, Clock,
  Mail, Phone, Calendar, Eye, UserCog, MessageSquare, KeyRound,
  ScrollText, History, Info,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { cn, formatRelativeTime, getInitials, parseTimestamp } from '@/lib/utils'
import { useAdminUserDetail, useStatusHistory, useAuditLogs, useUpdateUserStatus, useInitiatePasswordReset } from '@/hooks/useUsers'
import { conversations as convApi } from '@/lib/api'
import { toast } from 'sonner'
import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { Status, User } from '@/lib/schemas'
import { LeafLogo } from '@/components/ui/LeafLogo'

const STATUS_CONFIG: Record<Status, { icon: typeof CheckCircle; color: string; bg: string; border: string; label: string; description: string }> = {
  PENDING: { icon: Clock, color: 'text-amber-700 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/15', border: 'border-amber-200 dark:border-amber-800', label: 'Pending', description: 'Awaiting approval' },
  APPROVED: { icon: CheckCircle, color: 'text-green-700 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/15', border: 'border-green-200 dark:border-green-800', label: 'Approved', description: 'Active account' },
  REJECTED: { icon: XCircle, color: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/15', border: 'border-red-200 dark:border-red-800', label: 'Rejected', description: 'Application declined' },
  SUSPENDED: { icon: ShieldOff, color: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/15', border: 'border-red-200 dark:border-red-800', label: 'Suspended', description: 'Account suspended' },
}

function StatusBadge({ status }: { status: Status }) {
  const config = STATUS_CONFIG[status]
  const Icon = config.icon
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className={cn('gap-1 text-[10px] font-semibold border', config.color, config.bg, config.border)}>
          <Icon className="h-3 w-3" />{config.label}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{config.description}</TooltipContent>
    </Tooltip>
  )
}

// ── Compact row — icon / label / value ──────────────────────────────────────
function InfoRow({ icon: Icon, label, children }: { icon: typeof Mail; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b last:border-0">
      <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
      <span className="text-xs text-muted-foreground w-24 shrink-0">{label}</span>
      <div className="flex-1 min-w-0 text-xs">{children}</div>
    </div>
  )
}

export function UserDetailPage() {
  const { userId } = useParams<{ userId: string }>()
  const navigate = useNavigate()
  const { data: detailData, isLoading } = useAdminUserDetail(userId)
  const { data: historyData } = useStatusHistory(userId)
  const { data: auditData, fetchNextPage: fetchMoreAudit, hasNextPage: auditHasMore, isFetchingNextPage: auditFetching } = useAuditLogs(userId ? { userId } : undefined)
  const updateStatus = useUpdateUserStatus()
  const resetPassword = useInitiatePasswordReset()
  const queryClient = useQueryClient()

  const [statusDialog, setStatusDialog] = useState(false)
  const [newStatus, setNewStatus] = useState<Status>('APPROVED')
  const [reason, setReason] = useState('')

  const user = detailData?.user ?? null
  const history = historyData?.pages.flatMap(p => p.history) ?? []
  const auditLogs = auditData?.pages.flatMap(p => p.logs) ?? []

  const openStatusDialog = (u: User, target?: Status) => {
    setNewStatus(target ?? (u.status === 'PENDING' ? 'APPROVED' : u.status))
    setReason('')
    setStatusDialog(true)
  }

  const handleStatusSubmit = () => {
    if (!user) return
    updateStatus.mutate({ userId: user.id, status: newStatus, reason: reason || undefined }, {
      onSuccess: () => setStatusDialog(false),
    })
  }

  const handleOpenChat = async () => {
    if (!userId) return
    try {
      const res = await convApi.forUser(userId)
      await queryClient.invalidateQueries({ queryKey: ['conversations'] })
      navigate(`/admin?conversationId=${res.conversation.id}`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Could not open conversation'
      toast.error(msg)
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-full flex-col">
        <div className="flex items-center gap-3 p-4 border-b">
          <Skeleton className="h-9 w-9 rounded-xl" />
          <Skeleton className="h-5 w-40" />
        </div>
        <div className="p-4 space-y-3">
          <Skeleton className="h-14 w-full rounded-xl" />
          <Skeleton className="h-32 w-full rounded-xl" />
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <div className="text-center space-y-2">
          <p className="text-sm font-medium">User not found</p>
          <Button variant="outline" size="sm" onClick={() => navigate('/admin/users')}>Back to Users</Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col overflow-hidden min-h-0 bg-muted/10">
      {/* Header */}
      <div className="flex items-center gap-3 px-6 py-4 border-b shrink-0 bg-background/95 backdrop-blur z-10">
        <Button variant="outline" size="icon" className="h-8 w-8 rounded-xl shadow-sm" onClick={() => navigate('/admin/users')}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-2 min-w-0">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
            <UserCog className="h-4 w-4 text-primary shrink-0" />
          </div>
          <span className="font-bold tracking-tight truncate">User Details</span>
          <span className="text-muted-foreground font-medium hidden sm:inline ml-1 truncate">/ {user.name}</span>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="p-4 md:p-6 lg:p-8 max-w-7xl mx-auto w-full pb-[calc(1rem+env(safe-area-inset-bottom)+4rem)] sm:pb-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

            {/* Left Column: Profile Card */}
            <div className="lg:col-span-4 xl:col-span-3 space-y-4 lg:sticky lg:top-8">
              <div className="rounded-2xl border bg-card/50 backdrop-blur overflow-hidden shadow-sm">
                <div className="p-5 border-b flex flex-col items-center text-center">
                  <div className={cn(
                    'flex h-20 w-20 shrink-0 items-center justify-center rounded-3xl text-2xl font-bold shadow-sm mb-4',
                    user.status === 'APPROVED' ? 'bg-primary/10 text-primary'
                      : user.status === 'PENDING' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
                        : 'bg-muted text-muted-foreground',
                  )}>
                    {getInitials(user.name)}
                  </div>
                  <h3 className="font-bold text-lg">{user.name}</h3>
                  <div className="mt-1 mb-4"><StatusBadge status={user.status} /></div>

                  <div className="w-full space-y-2 mt-2">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground bg-muted/30 p-2.5 rounded-xl">
                      <Mail className="h-4 w-4 shrink-0" /><span className="truncate">{user.email}</span>
                    </div>
                    {user.phone && (
                      <div className="flex items-center gap-2 text-sm text-muted-foreground bg-muted/30 p-2.5 rounded-xl">
                        <Phone className="h-4 w-4 shrink-0" /><span className="truncate">{user.phone}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="p-3 space-y-1.5 flex flex-col bg-muted/10">
                  <Button variant="outline" className="w-full justify-start gap-2 shadow-sm rounded-xl h-10" onClick={handleOpenChat}>
                    <MessageSquare className="h-4 w-4 text-primary" />Message User
                  </Button>

                  {user.status === 'PENDING' && (
                    <div className="grid grid-cols-2 gap-1.5">
                      <Button className="w-full gap-1.5 shadow-sm rounded-xl h-10" onClick={() => openStatusDialog(user, 'APPROVED')}>
                        <CheckCircle className="h-4 w-4" />Approve
                      </Button>
                      <Button variant="destructive" className="w-full gap-1.5 shadow-sm rounded-xl h-10" onClick={() => openStatusDialog(user, 'REJECTED')}>
                        <XCircle className="h-4 w-4" />Reject
                      </Button>
                    </div>
                  )}

                  {user.status === 'APPROVED' && (
                    <Button variant="outline" className="w-full justify-start gap-2 border-red-200 hover:bg-red-50 hover:text-red-700 dark:border-red-900/50 dark:hover:bg-red-900/20 text-red-600 rounded-xl h-10" onClick={() => openStatusDialog(user, 'SUSPENDED')}>
                      <ShieldOff className="h-4 w-4" />Suspend Account
                    </Button>
                  )}
                  {user.status !== 'APPROVED' && user.status !== 'PENDING' && (
                    <Button variant="outline" className="w-full justify-start gap-2 rounded-xl h-10" onClick={() => openStatusDialog(user, 'APPROVED')}>
                      <CheckCircle className="h-4 w-4" />Reactivate Account
                    </Button>
                  )}

                  <Separator className="my-1.5" />

                  <Button variant="ghost" className="w-full justify-start gap-2 text-muted-foreground rounded-xl h-9" onClick={() => openStatusDialog(user)}>
                    <UserCog className="h-4 w-4" />Change Status Manually
                  </Button>
                  <Button variant="ghost" className="w-full justify-start gap-2 text-muted-foreground rounded-xl h-9" disabled={resetPassword.isPending} onClick={() => resetPassword.mutate(user)}>
                    {resetPassword.isPending ? <LeafLogo className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                    Send Password Reset
                  </Button>
                </div>
              </div>
            </div>

            {/* Right Column: Detailed Info Tabs */}
            <div className="lg:col-span-8 xl:col-span-9">
              <Tabs defaultValue="overview" className="flex flex-col gap-6">
                <TabsList className="w-full justify-start rounded-xl border bg-card/50 backdrop-blur h-12 p-1.5 shadow-sm overflow-x-auto flex-nowrap [&::-webkit-scrollbar]:hidden">
                  <TabsTrigger value="overview" className="gap-1.5 rounded-lg px-3 flex-1 min-w-max data-[state=active]:bg-background data-[state=active]:shadow-sm">
                    <Info className="h-4 w-4 shrink-0" />
                    <span>Overview</span>
                  </TabsTrigger>
                  <TabsTrigger value="history" className="gap-1.5 rounded-lg px-3 flex-1 min-w-max data-[state=active]:bg-background data-[state=active]:shadow-sm">
                    <History className="h-4 w-4 shrink-0" />
                    <span>Status History</span>
                  </TabsTrigger>
                  <TabsTrigger value="audit" className="gap-1.5 rounded-lg px-3 flex-1 min-w-max data-[state=active]:bg-background data-[state=active]:shadow-sm">
                    <ScrollText className="h-4 w-4 shrink-0" />
                    <span>Activity Logs</span>
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-0">
                  <div className="rounded-2xl border bg-card/50 backdrop-blur overflow-hidden shadow-sm">
                    <div className="p-4 border-b bg-muted/5 font-semibold text-sm">System Information</div>
                    <div className="flex flex-col">
                      <InfoRow icon={UserCog} label="User ID">
                        <span className="font-mono text-[13px] truncate p-1 bg-muted/50 rounded">{user.id}</span>
                      </InfoRow>
                      <InfoRow icon={Info} label="Role">
                        <Badge variant="outline" className="text-[11px] font-medium tracking-wide">{user.role}</Badge>
                      </InfoRow>
                      <InfoRow icon={Calendar} label="Joined">
                        <span className="font-medium">{format(parseTimestamp(user.createdAt), 'MMMM d, yyyy')}</span>
                      </InfoRow>
                      {user.lastSeenAt && (
                        <InfoRow icon={Eye} label="Last Active">
                          <span className="font-medium">{formatRelativeTime(user.lastSeenAt)}</span>
                        </InfoRow>
                      )}
                    </div>
                  </div>

                  <div className="rounded-2xl border bg-card/50 backdrop-blur overflow-hidden shadow-sm mt-6">
                    <div className="p-4 border-b bg-muted/5 font-semibold text-sm">Permissions & Preferences</div>
                    <div className="flex flex-col">
                      <InfoRow icon={Mail} label="Media Uploads">
                        <Badge variant={user.mediaPermission ? 'default' : 'secondary'} className="text-[11px] font-medium">
                          {user.mediaPermission ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </InfoRow>
                      <InfoRow icon={Mail} label="Email Alerts">
                        <Badge variant={user.emailNotifyOnMessage ? 'default' : 'secondary'} className="text-[11px] font-medium">
                          {user.emailNotifyOnMessage ? 'Active' : 'Muted'}
                        </Badge>
                      </InfoRow>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="history" className="mt-0">
                  <div className="rounded-2xl border bg-card/50 backdrop-blur overflow-hidden shadow-sm p-2">
                    {history.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                        <History className="h-10 w-10 mb-3 opacity-20" />
                        <p className="font-medium text-sm">No status history found</p>
                      </div>
                    ) : (
                      <div className="space-y-2 p-3">
                        {history.map((h) => {
                          const cfg = STATUS_CONFIG[h.newStatus]
                          return (
                            <div key={h.id} className="flex items-start gap-4 rounded-xl border bg-background/50 p-4 transition-colors hover:bg-accent/30">
                              <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-full mt-0.5', cfg.bg)}>
                                <cfg.icon className={cn('h-4 w-4', cfg.color)} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <span className="font-semibold text-sm">{h.oldStatus} <ArrowLeft className="inline h-3 w-3 mx-1 text-muted-foreground rotate-180" /> {h.newStatus}</span>
                                {h.reason && <p className="text-sm text-foreground/80 mt-1 italic border-l-2 pl-3 border-border/50 bg-muted/10 p-2 rounded-r-lg">{h.reason}</p>}
                                <p className="text-[11px] font-medium text-muted-foreground mt-2 flex items-center gap-1.5"><Clock className="h-3 w-3" /> Changed by {h.changedByUser?.name ?? 'System'} • {formatRelativeTime(h.createdAt)}</p>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="audit" className="mt-0">
                  <div className="rounded-2xl border bg-card/50 backdrop-blur overflow-hidden shadow-sm p-4">
                    {auditLogs.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                        <ScrollText className="h-10 w-10 mb-3 opacity-20" />
                        <p className="font-medium text-sm">No activity logs recorded yet</p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {auditLogs.map((log) => (
                          <div key={log.id} className="rounded-xl border bg-background/50 p-4 transition-colors hover:bg-accent/30">
                            <div className="flex items-center justify-between gap-4 mb-2">
                              <span className="font-semibold text-sm tracking-tight">{log.action}</span>
                              <Badge variant="secondary" className="text-[10px] shrink-0 font-medium">{log.entityType}</Badge>
                            </div>
                            {log.details && <p className="text-xs text-muted-foreground bg-muted/20 p-2 rounded-lg font-mono">{log.details}</p>}
                            <p className="text-[11px] text-muted-foreground mt-3 flex items-center gap-1.5"><Clock className="h-3 w-3" />{formatRelativeTime(log.createdAt)}</p>
                          </div>
                        ))}
                        {auditHasMore && (
                          <Button variant="outline" className="w-full mt-4 rounded-xl gap-2 h-10 shadow-sm" onClick={() => fetchMoreAudit()} disabled={auditFetching}>
                            {auditFetching ? <LeafLogo className="h-4 w-4 animate-spin" /> : <History className="h-4 w-4" />}
                            Load older activity
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                </TabsContent>
              </Tabs>
            </div>

          </div>
        </div>
      </div>

      {/* Status change dialog */}
      <Dialog open={statusDialog} onOpenChange={setStatusDialog}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><UserCog className="h-5 w-5 text-primary" />Update Account Status</DialogTitle>
            <DialogDescription>Change the account status for {user.name}.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Select value={newStatus} onValueChange={(v) => setNewStatus(v as Status)}>
              <SelectTrigger className="rounded-xl h-10"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="APPROVED"><span className="flex items-center gap-2"><CheckCircle className="h-4 w-4 text-green-600" />Approved</span></SelectItem>
                <SelectItem value="REJECTED"><span className="flex items-center gap-2"><XCircle className="h-4 w-4 text-red-600" />Rejected</span></SelectItem>
                <SelectItem value="SUSPENDED"><span className="flex items-center gap-2"><ShieldOff className="h-4 w-4 text-red-600" />Suspended</span></SelectItem>
              </SelectContent>
            </Select>
            <div className="space-y-2">
              <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Reason</Label>
              <Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Provide a reason..." rows={3} className="rounded-xl resize-none" />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setStatusDialog(false)} className="rounded-xl">Cancel</Button>
            <Button onClick={handleStatusSubmit} disabled={updateStatus.isPending || newStatus === user.status} className="rounded-xl gap-2">
              {updateStatus.isPending && <LeafLogo className="h-4 w-4 animate-spin" />}Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
