import { useState, useCallback, useEffect, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, CheckCircle, Clock, XCircle, ShieldOff,
  ImageIcon, Users, MoreHorizontal, Mail, Phone,
  Eye, UserCog, MessageSquare,
} from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Textarea } from '@/components/ui/textarea'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn, getInitials } from '@/lib/utils'
import { useAdminUsers, useUpdateUserStatus, useUpdateMediaPermission } from '@/hooks/useUsers'
import { useQueryClient } from '@tanstack/react-query'
import { conversations as convApi } from '@/lib/api'
import type { User, Status } from '@/lib/schemas'
import { LeafLogo } from '@/components/ui/LeafLogo'

const STATUS_CONFIG: Record<Status, {
  icon: typeof Clock
  color: string
  bg: string
  border: string
  label: string
  description: string
}> = {
  PENDING: {
    icon: Clock,
    color: 'text-amber-700 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-900/15',
    border: 'border-amber-200 dark:border-amber-800',
    label: 'Pending',
    description: 'Awaiting approval',
  },
  APPROVED: {
    icon: CheckCircle,
    color: 'text-green-700 dark:text-green-400',
    bg: 'bg-green-50 dark:bg-green-900/15',
    border: 'border-green-200 dark:border-green-800',
    label: 'Approved',
    description: 'Active account',
  },
  REJECTED: {
    icon: XCircle,
    color: 'text-red-700 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-900/15',
    border: 'border-red-200 dark:border-red-800',
    label: 'Rejected',
    description: 'Application declined',
  },
  SUSPENDED: {
    icon: ShieldOff,
    color: 'text-red-700 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-900/15',
    border: 'border-red-200 dark:border-red-800',
    label: 'Suspended',
    description: 'Account suspended',
  },
}

function StatusBadge({ status }: { status: Status }) {
  const config = STATUS_CONFIG[status]
  const Icon = config.icon
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className={cn('gap-1 text-[10px] font-semibold border', config.color, config.bg, config.border)}>
          <Icon className="h-3 w-3" />
          {config.label}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{config.description}</TooltipContent>
    </Tooltip>
  )
}

function UserCard({
  user,
  onStatusChange,
  onMediaToggle,
  onOpenChat,
  onViewDetail,
}: {
  user: User
  onStatusChange: (user: User, targetStatus?: Status) => void
  onMediaToggle: (userId: string, enabled: boolean) => void
  onOpenChat: (userId: string) => void
  onViewDetail: (userId: string) => void
}) {
  const isPending = user.status === 'PENDING'

  return (
    <div
      onClick={() => onViewDetail(user.id)}
      className={cn(
        'group relative flex flex-col md:flex-row md:items-center justify-between border-b border-border/40 bg-transparent p-4 transition-all hover:bg-accent/30 gap-4 cursor-pointer',
        isPending && 'bg-amber-50/30 dark:bg-amber-900/10',
      )}
    >
      <div className="flex items-center gap-3.5 flex-1 min-w-0">
        <div className={cn(
          'flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-sm font-bold',
          user.status === 'APPROVED'
            ? 'bg-primary/10 text-primary'
            : user.status === 'PENDING'
              ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
              : 'bg-muted text-muted-foreground',
        )}>
          {getInitials(user.name)}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-sm font-semibold truncate text-foreground">{user.name}</span>
            <StatusBadge status={user.status} />
          </div>

          <div className="flex items-center gap-4 mt-1 text-[11px] text-muted-foreground flex-wrap">
            <span className="flex items-center gap-1.5 min-w-0 flex-shrink">
              <Mail className="h-3 w-3 shrink-0" />
              <span className="truncate">{user.email}</span>
            </span>
            {user.phone && (
              <span className="flex items-center gap-1.5 shrink-0">
                <Phone className="h-3 w-3 shrink-0" />
                <span>{user.phone}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 self-start ml-auto md:ml-0 md:self-auto" onClick={e => e.stopPropagation()}>
        {user.role === 'USER' && (
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center gap-2 rounded-lg bg-muted/50 px-3 py-2 border">
                <ImageIcon className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground font-medium">Media</span>
                <Switch
                  checked={user.mediaPermission}
                  onCheckedChange={(checked) => onMediaToggle(user.id, checked)}
                  className="scale-75"
                />
              </div>
            </TooltipTrigger>
            <TooltipContent side="left">
              <p className="text-xs">{user.mediaPermission ? 'Disable' : 'Enable'} media uploads for this user</p>
            </TooltipContent>
          </Tooltip>
        )}

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-9 w-9">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {user.status === 'PENDING' && (
              <>
                <DropdownMenuItem
                  className="gap-2 cursor-pointer text-green-700 dark:text-green-400 focus:text-green-700"
                  onClick={() => onStatusChange(user, 'APPROVED')}
                >
                  <CheckCircle className="h-4 w-4" />
                  Approve
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="gap-2 cursor-pointer text-red-600 dark:text-red-400 focus:text-red-600"
                  onClick={() => onStatusChange(user, 'REJECTED')}
                >
                  <XCircle className="h-4 w-4" />
                  Reject
                </DropdownMenuItem>
                <DropdownMenuSeparator />
              </>
            )}
            {user.status === 'APPROVED' && (
              <>
                <DropdownMenuItem
                  className="gap-2 cursor-pointer text-red-600 dark:text-red-400 focus:text-red-600"
                  onClick={() => onStatusChange(user, 'SUSPENDED')}
                >
                  <ShieldOff className="h-4 w-4" />
                  Suspend
                </DropdownMenuItem>
                <DropdownMenuSeparator />
              </>
            )}
            {(user.status === 'SUSPENDED' || user.status === 'REJECTED') && (
              <>
                <DropdownMenuItem
                  className="gap-2 cursor-pointer text-green-700 dark:text-green-400 focus:text-green-700"
                  onClick={() => onStatusChange(user, 'APPROVED')}
                >
                  <CheckCircle className="h-4 w-4" />
                  Reactivate
                </DropdownMenuItem>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem
              className="gap-2 cursor-pointer"
              onClick={() => onStatusChange(user)}
            >
              <UserCog className="h-4 w-4" />
              Change Status...
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="gap-2 cursor-pointer"
              onClick={() => onViewDetail(user.id)}
            >
              <Eye className="h-4 w-4" />
              View Details
            </DropdownMenuItem>
            <DropdownMenuItem
              className="gap-2 cursor-pointer"
              onClick={() => onOpenChat(user.id)}
            >
              <MessageSquare className="h-4 w-4" />
              View Conversation
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {isPending && (
        <div className="flex items-center gap-2 mt-4 pt-3 border-t border-dashed">
          <Button
            size="sm"
            className="flex-1 h-8 rounded-lg text-xs gap-1.5"
            onClick={() => onStatusChange(user, 'APPROVED')}
          >
            <CheckCircle className="h-3.5 w-3.5" />
            Approve
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="flex-1 h-8 rounded-lg text-xs gap-1.5 text-destructive hover:text-destructive"
            onClick={() => onStatusChange(user, 'REJECTED')}
          >
            <XCircle className="h-3.5 w-3.5" />
            Reject
          </Button>
        </div>
      )
      }
    </div >
  )
}

function FilterChip({
  active,
  onClick,
  children,
  count,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
  count?: number
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-semibold transition-all border',
        active
          ? 'bg-primary/10 border-primary/20 text-primary shadow-sm'
          : 'bg-background border-border text-muted-foreground hover:bg-accent',
      )}
    >
      {children}
      {count !== undefined && count > 0 && (
        <span className={cn(
          'rounded-full px-1.5 py-0.5 text-[10px] tabular-nums font-bold',
          active ? 'bg-primary-foreground/20' : 'bg-background',
        )}>
          {count}
        </span>
      )}
    </button>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="rounded-xl border p-4">
          <div className="flex items-start gap-3.5">
            <Skeleton className="h-12 w-12 rounded-full shrink-0" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-36" />
              <Skeleton className="h-3 w-48" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function useDebouncedValue<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setDebounced(value), delay)
    return () => { if (timerRef.current) clearTimeout(timerRef.current) }
  }, [value, delay])
  return debounced
}

export function UsersPage() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [dialogUser, setDialogUser] = useState<User | null>(null)
  const [newStatus, setNewStatus] = useState<Status>('APPROVED')
  const [reason, setReason] = useState('')
  const filterStatus = statusFilter === 'all' ? undefined : (statusFilter as Status)
  const debouncedSearch = useDebouncedValue(search, 300)
  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useAdminUsers({
    status: filterStatus,
    role: 'USER',
    search: debouncedSearch || undefined,
  })
  const updateStatus = useUpdateUserStatus()
  const updateMedia = useUpdateMediaPermission()

  const { allUsers, pendingCount, approvedCount, suspendedCount } = useMemo(() => {
    const flat = data?.pages.flatMap((p) => p.users) ?? []
    let pending = 0, approved = 0, suspended = 0
    for (const u of flat) {
      if (u.status === 'PENDING') pending++
      else if (u.status === 'APPROVED') approved++
      else if (u.status === 'SUSPENDED') suspended++
    }
    return { allUsers: flat, pendingCount: pending, approvedCount: approved, suspendedCount: suspended }
  }, [data])

  const handleStatusDialog = useCallback((user: User, targetStatus?: Status) => {
    setDialogUser(user)
    setNewStatus(targetStatus ?? (user.status === 'PENDING' ? 'APPROVED' : user.status))
    setReason('')
  }, [])

  const handleStatusSubmit = () => {
    if (!dialogUser) return
    updateStatus.mutate(
      { userId: dialogUser.id, status: newStatus, reason: reason || undefined },
      { onSuccess: () => setDialogUser(null) },
    )
  }

  const handleMediaToggle = useCallback((userId: string, enabled: boolean) => {
    updateMedia.mutate({ userId, mediaPermission: enabled })
  }, [updateMedia])

  const queryClient = useQueryClient()
  const handleOpenChat = useCallback(async (userId: string) => {
    try {
      const res = await convApi.forUser(userId)
      await queryClient.invalidateQueries({ queryKey: ['conversations'] })
      navigate(`/admin?conversationId=${res.conversation.id}`)
    } catch {
      navigate(`/admin?userId=${userId}`)
    }
  }, [navigate, queryClient])

  const handleViewDetail = useCallback((userId: string) => {
    navigate(`/admin/users/${userId}`)
  }, [navigate])

  return (
    <div className="flex h-full flex-col">
      <div className="p-4 lg:p-5 border-b space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <Users className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">User Management</h2>
              <p className="text-[11px] text-muted-foreground">
                {allUsers.length} total users
              </p>
            </div>
          </div>
          {pendingCount > 0 && (
            <Badge variant="secondary" className="gap-1.5 px-3 py-1.5 bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 border-amber-200 dark:border-amber-800">
              <Clock className="h-3.5 w-3.5" />
              {pendingCount} pending review
            </Badge>
          )}
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by name or email..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 h-9 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            />
          </div>
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 -mx-4 px-4 sm:mx-0 sm:px-0 sm:pb-0 [&::-webkit-scrollbar]:hidden">
            <FilterChip active={statusFilter === 'all'} onClick={() => setStatusFilter('all')}>
              All
            </FilterChip>
            <FilterChip active={statusFilter === 'PENDING'} onClick={() => setStatusFilter('PENDING')} count={pendingCount}>
              <Clock className="h-3 w-3" />
              Pending
            </FilterChip>
            <FilterChip active={statusFilter === 'APPROVED'} onClick={() => setStatusFilter('APPROVED')} count={approvedCount}>
              <CheckCircle className="h-3 w-3" />
              Active
            </FilterChip>
            <FilterChip active={statusFilter === 'SUSPENDED'} onClick={() => setStatusFilter('SUSPENDED')} count={suspendedCount}>
              <ShieldOff className="h-3 w-3" />
              Suspended
            </FilterChip>
          </div>
        </div>
      </div>

      {isLoading ? (
        <CardSkeleton />
      ) : (
        <ScrollArea className="flex-1 bg-background">
          <div className="flex flex-col pb-6 px-4 sm:px-0">
            {allUsers.length === 0 ? (
              <div className="flex flex-col items-center gap-4 py-24 text-muted-foreground">
                <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted">
                  <Users className="h-8 w-8" />
                </div>
                <div className="text-center space-y-1">
                  <p className="text-sm font-medium text-foreground">No users found</p>
                  <p className="text-xs">Try adjusting your search or filters</p>
                </div>
              </div>
            ) : (
              allUsers.map((user) => (
                <UserCard
                  key={user.id}
                  user={user}
                  onStatusChange={handleStatusDialog}
                  onMediaToggle={handleMediaToggle}
                  onOpenChat={handleOpenChat}
                  onViewDetail={handleViewDetail}
                />
              ))
            )}
            {hasNextPage && (
              <div className="flex justify-center pt-4">
                <Button
                  variant="outline"
                  size="sm"
                  className="rounded-xl gap-2"
                  onClick={() => fetchNextPage()}
                  disabled={isFetchingNextPage}
                >
                  {isFetchingNextPage && <LeafLogo className="h-4 w-4 animate-spin" />}
                  Load More
                </Button>
              </div>
            )}
          </div>
        </ScrollArea>
      )}

      <Dialog open={!!dialogUser} onOpenChange={(open) => !open && setDialogUser(null)}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserCog className="h-5 w-5 text-primary" />
              Update Account Status
            </DialogTitle>
            <DialogDescription>
              Change the account status for this user.
            </DialogDescription>
          </DialogHeader>
          {dialogUser && (
            <div className="space-y-5">
              <div className="flex items-center gap-3 rounded-xl bg-muted/50 p-3">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-sm font-bold">
                  {getInitials(dialogUser.name)}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold truncate">{dialogUser.name}</p>
                  <p className="text-xs text-muted-foreground truncate">{dialogUser.email}</p>
                </div>
                <StatusBadge status={dialogUser.status} />
              </div>

              <Separator />

              <div className="space-y-2">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  New Status
                </Label>
                <Select value={newStatus} onValueChange={(v) => setNewStatus(v as Status)}>
                  <SelectTrigger className="rounded-xl h-10">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="APPROVED">
                      <span className="flex items-center gap-2">
                        <CheckCircle className="h-4 w-4 text-green-600" />
                        <div>
                          <p className="font-medium">Approved</p>
                          <p className="text-xs text-muted-foreground">Full access to the platform</p>
                        </div>
                      </span>
                    </SelectItem>
                    <SelectItem value="REJECTED">
                      <span className="flex items-center gap-2">
                        <XCircle className="h-4 w-4 text-red-600" />
                        <div>
                          <p className="font-medium">Rejected</p>
                          <p className="text-xs text-muted-foreground">Application declined</p>
                        </div>
                      </span>
                    </SelectItem>
                    <SelectItem value="SUSPENDED">
                      <span className="flex items-center gap-2">
                        <ShieldOff className="h-4 w-4 text-red-600" />
                        <div>
                          <p className="font-medium">Suspended</p>
                          <p className="text-xs text-muted-foreground">Temporarily blocked</p>
                        </div>
                      </span>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Reason {(newStatus === 'REJECTED' || newStatus === 'SUSPENDED') && (
                    <span className="font-normal normal-case text-muted-foreground">(recommended)</span>
                  )}
                </Label>
                <Textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Provide a reason for this change..."
                  rows={3}
                  className="rounded-xl resize-none"
                />
              </div>
            </div>
          )}
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDialogUser(null)} className="rounded-xl">
              Cancel
            </Button>
            <Button
              onClick={handleStatusSubmit}
              disabled={updateStatus.isPending || newStatus === dialogUser?.status}
              className="rounded-xl gap-2"
            >
              {updateStatus.isPending && <LeafLogo className="h-4 w-4 animate-spin" />}
              Confirm Change
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
