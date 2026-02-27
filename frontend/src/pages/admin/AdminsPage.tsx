import { useState } from 'react'
import { format } from 'date-fns'
import { cn, formatRelativeTime, getInitials, parseTimestamp } from '@/lib/utils'
import {
  Shield, Plus, UserMinus, UserCheck, Mail, Calendar, Eye,
  ShieldCheck, UserCog, MoreVertical, MessageCircle, Clock, Users,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
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
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useAdminList, useCreateAdmin } from '@/hooks/useUsers'
import { useQueryClient } from '@tanstack/react-query'
import type { Conversation, User } from '@/lib/schemas'
import { adminAdmins } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { toast } from 'sonner'
import { LeafLogo } from '@/components/ui/LeafLogo'

// ─── Admin Detail Sheet ────────────────────────────────────────────────────────

function AdminDetailSheet({
  admin,
  currentUser,
  open,
  onClose,
  onSuspend,
  onReactivate,
  onDM,
  isPending,
}: {
  admin: User | null
  currentUser: User | null
  open: boolean
  onClose: () => void
  onSuspend: (u: User) => void
  onReactivate: (u: User) => void
  onDM: (u: User) => void
  isPending: boolean
}) {
  const queryClient = useQueryClient()
  if (!admin) return null

  const isSuperAdmin = admin.role === 'SUPER_ADMIN'
  const isCurrentUser = admin.id === currentUser?.id
  const viewerIsSuperAdmin = currentUser?.role === 'SUPER_ADMIN'
  const canManage = viewerIsSuperAdmin && !isCurrentUser
  const isSuspended = admin.status === 'SUSPENDED'

  // Read assigned users from conversations cache (already loaded by AdminLayout)
  type ConvPage = { conversations: Conversation[]; hasMore: boolean }
  type ConvInfinite = { pages: ConvPage[]; pageParams: unknown[] }
  const convCache = queryClient.getQueryData<ConvInfinite>(['conversations'])
  const assignedUsers = convCache
    ? convCache.pages.flatMap(p => p.conversations)
      .filter(c => c.assignedAdminId === admin.id && c.user)
      .map(c => c.user!)
      .filter((u, i, arr) => arr.findIndex(x => x.id === u.id) === i) // dedupe
    : []

  return (
    <Sheet open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <SheetContent className="w-full sm:max-w-[380px] flex flex-col gap-0 p-0">
        <SheetHeader className="px-5 pt-5 pb-4 border-b">
          <div className="flex items-center gap-3">
            <div className={cn(
              'flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-sm font-bold',
              isSuperAdmin ? 'bg-primary text-primary-foreground' : 'bg-primary/10 text-primary',
              isSuspended && 'bg-muted text-muted-foreground',
            )}>
              {getInitials(admin.name)}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <SheetTitle className={cn('text-sm font-bold', isSuspended && 'line-through text-muted-foreground')}>
                  {admin.name}
                </SheetTitle>
                <Badge variant={isSuperAdmin ? 'default' : 'secondary'} className="gap-1 text-[10px]">
                  <Shield className="h-3 w-3" />
                  {isSuperAdmin ? 'Super Admin' : 'Admin'}
                </Badge>
              </div>
              <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                {isSuspended && <Badge variant="destructive" className="text-[10px]">Suspended</Badge>}
                {isCurrentUser && <Badge variant="outline" className="text-[10px]">You</Badge>}
              </div>
            </div>
          </div>
        </SheetHeader>

        {/* Detail rows — same compact pattern as UserDetailPage overview tab */}
        <div className="flex-1 overflow-auto">
          <div className="divide-y divide-border/60">
            <div className="flex items-center gap-3 px-5 py-3 text-sm">
              <Mail className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span className="text-xs text-muted-foreground w-20 shrink-0">Email</span>
              <span className="text-xs truncate">{admin.email}</span>
            </div>
            <div className="flex items-center gap-3 px-5 py-3 text-sm">
              <Calendar className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span className="text-xs text-muted-foreground w-20 shrink-0">Joined</span>
              <span className="text-xs">{format(parseTimestamp(admin.createdAt), 'MMM d, yyyy')}</span>
            </div>
            <div className="flex items-center gap-3 px-5 py-3 text-sm">
              {admin.lastSeenAt
                ? <Eye className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                : <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              }
              <span className="text-xs text-muted-foreground w-20 shrink-0">Last seen</span>
              <span className="text-xs">{admin.lastSeenAt ? formatRelativeTime(admin.lastSeenAt) : 'Never'}</span>
            </div>
            <div className="flex items-center gap-3 px-5 py-3 text-sm">
              <UserCog className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span className="text-xs text-muted-foreground w-20 shrink-0">Status</span>
              <Badge variant={isSuspended ? 'destructive' : 'outline'} className="text-[10px]">
                {isSuspended ? 'Suspended' : 'Active'}
              </Badge>
            </div>
          </div>

          {/* Assigned users */}
          <div className="px-5 pt-3 pb-1">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Users className="h-3 w-3" />
              Assigned Customers ({assignedUsers.length})
            </p>
          </div>
          {assignedUsers.length === 0 ? (
            <p className="px-5 pb-3 text-xs text-muted-foreground">No customers assigned</p>
          ) : (
            <div className="divide-y divide-border/60">
              {assignedUsers.map(u => (
                <div key={u.id} className="flex items-center gap-2 px-5 py-2">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[10px] font-bold text-primary">
                    {getInitials(u.name)}
                  </div>
                  <span className="text-xs truncate">{u.name}</span>
                </div>
              ))}
            </div>
          )}

          {/* Actions */}
          {(canManage || !isCurrentUser) && (
            <>
              <Separator className="my-2" />
              <div className="px-5 pb-5 flex flex-col gap-2">
                {!isCurrentUser && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-start gap-2 rounded-xl"
                    onClick={() => { onDM(admin); onClose() }}
                  >
                    <MessageCircle className="h-3.5 w-3.5" />
                    Send Direct Message
                  </Button>
                )}
                {canManage && (
                  isSuspended ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start gap-2 rounded-xl text-green-600 hover:text-green-600 border-green-200 hover:bg-green-50 dark:border-green-900 dark:hover:bg-green-900/20"
                      disabled={isPending}
                      onClick={() => { onReactivate(admin); onClose() }}
                    >
                      {isPending ? <LeafLogo className="h-3.5 w-3.5 animate-spin" /> : <UserCheck className="h-3.5 w-3.5" />}
                      Reactivate Admin
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start gap-2 rounded-xl text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10"
                      disabled={isPending}
                      onClick={() => { onSuspend(admin); onClose() }}
                    >
                      {isPending ? <LeafLogo className="h-3.5 w-3.5 animate-spin" /> : <UserMinus className="h-3.5 w-3.5" />}
                      Suspend Admin
                    </Button>
                  )
                )}
              </div>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

// ─── Admin Card ────────────────────────────────────────────────────────────────

function AdminCard({
  admin,
  currentUser,
  onSuspend,
  onReactivate,
  onDM,
  onSelect,
  isPending,
}: {
  admin: User
  currentUser: User | null
  onSuspend: (user: User) => void
  onReactivate: (user: User) => void
  onDM: (admin: User) => void
  onSelect: (admin: User) => void
  isPending: boolean
}) {
  const isSuperAdmin = admin.role === 'SUPER_ADMIN'
  const isCurrentUser = admin.id === currentUser?.id
  const viewerIsSuperAdmin = currentUser?.role === 'SUPER_ADMIN'
  const canManage = viewerIsSuperAdmin && !isCurrentUser
  const isSuspended = admin.status === 'SUSPENDED'

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(admin)}
      onKeyDown={(e) => e.key === 'Enter' && onSelect(admin)}
      className="group relative flex flex-col md:flex-row md:items-center justify-between border-b border-border/40 bg-transparent p-4 transition-all hover:bg-accent/30 gap-4 cursor-pointer"
    >
      <div className="flex items-center gap-4 flex-1 min-w-0">
        <div className={cn(
          'flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-sm font-bold',
          isSuperAdmin ? 'bg-primary text-primary-foreground' : 'bg-primary/10 text-primary',
          isSuspended && 'bg-muted text-muted-foreground',
        )}>
          {getInitials(admin.name)}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('font-semibold truncate', isSuspended && 'text-muted-foreground line-through')}>{admin.name}</span>
            <Badge variant={isSuperAdmin ? 'default' : 'secondary'} className="gap-1 text-[10px]">
              <Shield className="h-3 w-3" />
              {isSuperAdmin ? 'Super Admin' : 'Admin'}
            </Badge>
            {isSuspended && (
              <Badge variant="destructive" className="text-[10px]">Suspended</Badge>
            )}
            {isCurrentUser && (
              <Badge variant="outline" className="text-[10px]">You</Badge>
            )}
          </div>
          <div className="flex items-center gap-4 mt-1.5 text-[11px] text-muted-foreground flex-wrap">
            <span className="flex items-center gap-1.5 min-w-0 flex-shrink">
              <Mail className="h-3 w-3 shrink-0" />
              <span className="truncate">{admin.email}</span>
            </span>
            <span className="flex items-center gap-1.5 shrink-0">
              <Calendar className="h-3 w-3 shrink-0" />
              <span>{format(parseTimestamp(admin.createdAt), 'MMM d, yyyy')}</span>
            </span>
            {admin.lastSeenAt && (
              <span className="flex items-center gap-1.5 shrink-0">
                <Eye className="h-3 w-3 shrink-0" />
                <span>{formatRelativeTime(admin.lastSeenAt)}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 self-end md:self-auto" onClick={(e) => e.stopPropagation()}>
        {!isCurrentUser && (
          <button
            onClick={() => onDM(admin)}
            title={`Message ${admin.name}`}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors"
          >
            <MessageCircle className="h-4 w-4" />
          </button>
        )}
        {canManage && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" disabled={isPending}>
                {isPending ? <LeafLogo className="h-4 w-4 animate-spin" /> : <MoreVertical className="h-4 w-4" />}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {isSuspended ? (
                <DropdownMenuItem
                  className="gap-2 text-green-600 focus:text-green-600 cursor-pointer"
                  onClick={() => onReactivate(admin)}
                >
                  <UserCheck className="h-4 w-4" />
                  Reactivate Admin
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem
                  className="gap-2 text-destructive focus:text-destructive cursor-pointer"
                  onClick={() => onSuspend(admin)}
                >
                  <UserMinus className="h-4 w-4" />
                  Suspend Admin
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </div>
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 rounded-xl border p-4">
          <Skeleton className="h-12 w-12 rounded-full shrink-0" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-3 w-56" />
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export function AdminsPage() {
  const user = useAuthStore((s) => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const { data, isLoading } = useAdminList()
  const createAdmin = useCreateAdmin()
  const queryClient = useQueryClient()

  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pendingAction, setPendingAction] = useState<string | null>(null)
  const [selectedAdmin, setSelectedAdmin] = useState<User | null>(null)

  const allAdmins = (data?.allAdmins ?? []).filter(a => a.role !== 'SUPER_ADMIN')
  const navigate = useNavigate()
  const handleDM = (admin: User) => navigate(`/admin/dm?partner=${admin.id}`)

  const handleCreate = () => {
    createAdmin.mutate(
      { name, email, password },
      {
        onSuccess: () => {
          setShowCreate(false)
          setName('')
          setEmail('')
          setPassword('')
        },
      },
    )
  }

  const handleSuspend = async (targetUser: User) => {
    if (targetUser.id === user?.id) {
      toast.error("You can't suspend yourself")
      return
    }
    setPendingAction(targetUser.id)
    try {
      await adminAdmins.suspend(targetUser.id)
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      toast.success(`${targetUser.name} has been suspended`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to suspend admin')
    } finally {
      setPendingAction(null)
    }
  }

  const handleReactivate = async (targetUser: User) => {
    setPendingAction(targetUser.id)
    try {
      await adminAdmins.reactivate(targetUser.id)
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      toast.success(`${targetUser.name} has been reactivated`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to reactivate admin')
    } finally {
      setPendingAction(null)
    }
  }

  if (isLoading) {
    return <CardSkeleton />
  }

  return (
    <div className="flex h-full flex-col">
      <div className="p-4 border-b space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <ShieldCheck className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">Admin Management</h2>
              <p className="text-[11px] text-muted-foreground">
                {allAdmins.length} total administrators
              </p>
            </div>
          </div>
          {isSuperAdmin && (
            <Button size="sm" className="gap-1.5 rounded-full px-4 shadow-sm" onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4" />
              Add Admin
            </Button>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1 bg-background">
        <div className="flex flex-col pb-4">
          {allAdmins.length > 0 && (
            <div className="flex flex-col">
              <div className="px-5 pt-4 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <UserCog className="h-3.5 w-3.5" />
                  Admins — click a row to view details
                </h3>
              </div>
              {allAdmins.map((admin) => (
                <AdminCard
                  key={admin.id}
                  admin={admin}
                  currentUser={user}
                  onSuspend={handleSuspend}
                  onReactivate={handleReactivate}
                  onDM={handleDM}
                  onSelect={setSelectedAdmin}
                  isPending={pendingAction === admin.id}
                />
              ))}
            </div>
          )}

          {allAdmins.length === 0 && (
            <div className="flex flex-col items-center gap-4 py-24 text-muted-foreground">
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted">
                <Shield className="h-8 w-8" />
              </div>
              <div className="text-center space-y-1">
                <p className="text-sm font-medium text-foreground">No administrators</p>
                <p className="text-xs">Add an admin to manage the platform</p>
              </div>
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Admin Detail Sheet */}
      <AdminDetailSheet
        admin={selectedAdmin}
        currentUser={user}
        open={!!selectedAdmin}
        onClose={() => setSelectedAdmin(null)}
        onSuspend={handleSuspend}
        onReactivate={handleReactivate}
        onDM={handleDM}
        isPending={!!(selectedAdmin && pendingAction === selectedAdmin.id)}
      />

      {/* Create Admin Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="h-5 w-5 text-primary" />
              Create New Admin
            </DialogTitle>
            <DialogDescription>
              Add a new administrator to the platform.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Full Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Admin Name" className="rounded-xl" />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Email</Label>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" type="email" className="rounded-xl" />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Password</Label>
              <Input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="Min. 8 characters" className="rounded-xl" />
              {password && password.length < 8 && (
                <p className="text-[10px] text-destructive">Password must be at least 8 characters</p>
              )}
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setShowCreate(false)} className="rounded-xl">Cancel</Button>
            <Button
              onClick={handleCreate}
              disabled={!name || !email || !password || password.length < 8 || createAdmin.isPending}
              className="rounded-xl gap-2"
            >
              {createAdmin.isPending && <LeafLogo className="h-4 w-4 animate-spin" />}
              Create Admin
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
