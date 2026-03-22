import { useState, useRef, useCallback, useEffect } from 'react'
import { format } from 'date-fns'
import { cn, formatRelativeTime, getInitials, parseTimestamp } from '@/lib/utils'
import {
  Shield, Plus, UserMinus, UserCheck, Mail, Calendar, Eye, Crown,
  ShieldCheck, UserCog, MoreVertical, MessageCircle, Clock, Users,
  User as UserIcon, AlertTriangle, ArrowLeft, Building2, Check, X,
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
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from '@/components/ui/sheet'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
  DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useAdminList, useCreateAdmin, useUpdateAdminRole } from '@/hooks/useUsers'
import { useQueryClient, useMutation } from '@tanstack/react-query'
import type { Conversation, User } from '@/lib/schemas'
import { adminAdmins } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { toast } from '@/components/ui/sonner'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useAppConfig } from '@/hooks/useConfig'
import { PasswordInput } from '@/components/ui/password-input'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'

// Parse subsidiaryIds JSON string safely
function parseSubIds(raw?: string | null): string[] {
  if (!raw) return []
  try { const p = JSON.parse(raw); return Array.isArray(p) ? p : [] } catch { return [] }
}

// ─── Subsidiary Tagger ────────────────────────────────────────────────────────

function SubsidiaryTagger({
  adminId,
  adminName,
  currentIds,
  allSubsidiaries,
  onSaved,
}: {
  adminId: string
  adminName: string
  currentIds: string[]
  allSubsidiaries: { id: string; name: string }[]
  onSaved: (ids: string[]) => void
}) {
  // Use ref to capture initial value — prevents re-render from parent resetting selections
  const initialIds = useRef(currentIds)
  const [selected, setSelected] = useState<string[]>(() => initialIds.current)
  const [dirty, setDirty] = useState(false)

  // If the server delivers fresher data while the sheet is open and the admin hasn't
  // started editing, silently update to the latest value so we don't overwrite it.
  // If they have unsaved changes (dirty), leave them alone and let them decide.
  useEffect(() => {
    if (dirty) return
    const incoming = JSON.stringify([...currentIds].sort())
    const current = JSON.stringify([...initialIds.current].sort())
    if (incoming !== current) {
      initialIds.current = currentIds
      setSelected(currentIds)
    }
  }, [currentIds, dirty])

  const mutation = useMutation({
    mutationFn: (ids: string[]) => adminAdmins.updateSubsidiaries(adminId, ids),
    onSuccess: (_, ids) => {
      // Update baseline so a subsequent edit that restores to this saved state
      // correctly shows dirty=false rather than diffing against the stale mount value.
      initialIds.current = ids
      onSaved(ids)
      setDirty(false)
      toast.success('Subsidiary routing saved')
    },
    onError: () => toast.error('Failed to save'),
  })

  const toggle = useCallback((id: string) => {
    setSelected(prev => {
      const next = prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
      setDirty(true)
      return next
    })
  }, [])

  const clearAll = useCallback(() => { setSelected([]); setDirty(true) }, [])

  const isGeneralist = selected.length === 0

  if (allSubsidiaries.length === 0) {
    return (
      <div className="px-5 py-3 text-xs text-muted-foreground italic">
        No subsidiaries configured yet — add them in Settings → Subsidiaries.
      </div>
    )
  }

  return (
    <div className="px-5 py-3 space-y-2.5">
      {/* Generalist hint */}
      <div className={cn(
        'flex items-start gap-2 rounded-lg px-3 py-2 border text-xs transition-colors',
        isGeneralist
          ? 'bg-primary/5 border-primary/20 text-primary'
          : 'bg-muted/30 border-border text-muted-foreground',
      )}>
        <Building2 className="h-3.5 w-3.5 mt-0.5 shrink-0" />
        <span>
          {isGeneralist
            ? <><strong>Generalist</strong> — {adminName} handles all subsidiaries.</>
            : `Select subsidiaries below, or clear all to make ${adminName} a generalist.`}
        </span>
      </div>

      {/* Subsidiary checkboxes */}
      <div className="space-y-1">
        {allSubsidiaries.map(sub => {
          const on = selected.includes(sub.id)
          return (
            <button
              key={sub.id}
              onClick={() => toggle(sub.id)}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-2 rounded-lg border text-sm transition-all text-left',
                on
                  ? 'bg-primary/8 border-primary/30 text-primary font-medium'
                  : 'bg-background border-border hover:border-primary/30 hover:bg-muted/30 text-foreground',
              )}
            >
              <div className={cn(
                'flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors',
                on ? 'bg-primary border-primary' : 'border-border',
              )}>
                {on && <Check className="h-2.5 w-2.5 text-primary-foreground" />}
              </div>
              <span className="flex-1 truncate">{sub.name}</span>
            </button>
          )
        })}
      </div>

      {/* Save / Clear row */}
      <div className="flex items-center gap-2 pt-1">
        <Button
          size="sm"
          className="flex-1 rounded-lg gap-1.5"
          disabled={!dirty || mutation.isPending}
          onClick={() => mutation.mutate(selected)}
        >
          {mutation.isPending ? <LeafLogo className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save routing
        </Button>
        {selected.length > 0 && (
          <Button
            size="sm"
            variant="ghost"
            className="rounded-lg gap-1.5 text-muted-foreground"
            disabled={mutation.isPending}
            onClick={clearAll}
          >
            <X className="h-3.5 w-3.5" />
            Clear (generalist)
          </Button>
        )}
      </div>
    </div>
  )
}

// ─── Admin Detail Sheet ────────────────────────────────────────────────────────

function AdminDetailSheet({
  admin, currentUser, open, onClose, onSuspend, onReactivate, onDM, isPending, onSubsidiariesSaved,
}: {
  admin: User | null
  currentUser: User | null
  open: boolean
  onClose: () => void
  onSuspend: (u: User) => void
  onReactivate: (u: User) => void
  onDM: (u: User) => void
  isPending: boolean
  onSubsidiariesSaved: (adminId: string, ids: string[]) => void
}) {
  const queryClient = useQueryClient()
  const { data: configData, isLoading: configLoading } = useAppConfig()
  const allSubsidiaries = configData?.subsidiaries ?? []
  const [sheetTab, setSheetTab] = useState<'info' | 'routing'>('info')

  // Reset tab whenever the sheet is reused for a different admin.
  // useEffect is safe here — the sheet's slide-in animation hides the 1-frame lag
  // and avoids the double-render that calling setState during render causes.
  useEffect(() => {
    setSheetTab('info')
  }, [admin?.id])

  if (!admin) return null

  const isSuperAdmin = admin.role === 'SUPER_ADMIN'
  const isCurrentUser = admin.id === currentUser?.id
  const viewerIsSuperAdmin = currentUser?.role === 'SUPER_ADMIN'
  const canManage = viewerIsSuperAdmin && !isCurrentUser
  const isSuspended = admin.status === 'SUSPENDED'

  type ConvPage = { conversations: Conversation[]; hasMore: boolean }
  type ConvInfinite = { pages: ConvPage[]; pageParams: unknown[] }
  const convCache = queryClient.getQueryData<ConvInfinite>(['conversations'])
  const assignedUsers = convCache
    ? convCache.pages.flatMap(p => p.conversations)
        .filter(c => c.assignedAdminId === admin.id && c.user)
        .map(c => c.user!)
        .filter((u, i, arr) => arr.findIndex(x => x.id === u.id) === i)
    : []

  const currentSubIds = parseSubIds(admin.subsidiaryIds)
  const hasSubsidiaries = allSubsidiaries.length > 0

  return (
    <Sheet open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <SheetContent className="w-full sm:max-w-[400px] flex flex-col gap-0 p-0">
        {/* Header */}
        <SheetHeader className="px-5 pt-5 pb-4 border-b shrink-0">
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
                {/* Routing summary badge */}
                {hasSubsidiaries && !isSuperAdmin && (
                  currentSubIds.length === 0
                    ? <Badge variant="outline" className="text-[10px] border-blue-300 text-blue-600 bg-blue-50 dark:bg-blue-950/30">Generalist</Badge>
                    : <Badge variant="outline" className="text-[10px] border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30">
                        {currentSubIds.length} subsidiary{currentSubIds.length !== 1 ? 'ies' : ''}
                      </Badge>
                )}
              </div>
            </div>
          </div>

          {/* Tab switcher — only show Routing tab if subsidiaries exist */}
          {hasSubsidiaries && viewerIsSuperAdmin && (
            <div className="flex gap-1 mt-3 bg-muted/40 rounded-lg p-0.5">
              {(['info', 'routing'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setSheetTab(t)}
                  className={cn(
                    'flex-1 text-xs py-1.5 rounded-md font-medium transition-all capitalize',
                    sheetTab === t ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {t === 'routing' ? '🏢 Routing' : '👤 Info'}
                </button>
              ))}
            </div>
          )}
        </SheetHeader>

        <div className="flex-1 overflow-auto">
          {/* Info Tab */}
          {sheetTab === 'info' && (
            <>
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
                    : <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
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

              {(canManage || !isCurrentUser) && (
                <>
                  <Separator className="my-2" />
                  <div className="px-5 pb-5 flex flex-col gap-2">
                    {!isCurrentUser && (
                      <Button variant="outline" size="sm" className="w-full justify-start gap-2 rounded-xl"
                        onClick={() => { onDM(admin); onClose() }}>
                        <MessageCircle className="h-3.5 w-3.5" />Send Direct Message
                      </Button>
                    )}
                    {canManage && (
                      isSuspended ? (
                        <Button variant="outline" size="sm" disabled={isPending}
                          className="w-full justify-start gap-2 rounded-xl text-green-600 hover:text-green-600 border-green-200 hover:bg-green-50 dark:border-green-900 dark:hover:bg-green-900/20"
                          onClick={() => { onReactivate(admin); onClose() }}>
                          {isPending ? <LeafLogo className="h-3.5 w-3.5 animate-spin" /> : <UserCheck className="h-3.5 w-3.5" />}
                          Reactivate Admin
                        </Button>
                      ) : (
                        <Button variant="outline" size="sm" disabled={isPending}
                          className="w-full justify-start gap-2 rounded-xl text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10"
                          onClick={() => { onSuspend(admin); onClose() }}>
                          {isPending ? <LeafLogo className="h-3.5 w-3.5 animate-spin" /> : <UserMinus className="h-3.5 w-3.5" />}
                          Suspend Admin
                        </Button>
                      )
                    )}
                  </div>
                </>
              )}
            </>
          )}

          {/* Routing Tab */}
          {sheetTab === 'routing' && (
            <div className="py-2">
              <div className="px-5 py-2">
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Choose which subsidiaries <strong>{admin.name}</strong> handles. Conversations tagged with a subsidiary are automatically routed to matching admins first.
                  Leave empty to make them a <strong>generalist</strong> (handles all).
                </p>
              </div>
              {configLoading && !allSubsidiaries.length ? (
                <div className="px-5 py-3 space-y-2">
                  {[0, 1, 2].map(i => (
                    <Skeleton key={i} className="h-10 w-full rounded-lg" />
                  ))}
                </div>
              ) : (
                <SubsidiaryTagger
                  key={admin.id}
                  adminId={admin.id}
                  adminName={admin.name}
                  currentIds={currentSubIds}
                  allSubsidiaries={allSubsidiaries}
                  onSaved={(ids) => onSubsidiariesSaved(admin.id, ids)}
                />
              )}
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

// ─── Admin Card ────────────────────────────────────────────────────────────────

function AdminCard({
  admin, currentUser, allSubsidiaries, onSuspend, onReactivate, onDM, onSelect, onRoleChange, isPending,
}: {
  admin: User
  currentUser: User | null
  allSubsidiaries: { id: string; name: string }[]
  onSuspend: (user: User) => void
  onReactivate: (user: User) => void
  onDM: (admin: User) => void
  onSelect: (admin: User) => void
  onRoleChange: (admin: User) => void
  isPending: boolean
}) {
  const isSuperAdmin = admin.role === 'SUPER_ADMIN'
  const isCurrentUser = admin.id === currentUser?.id
  const viewerIsSuperAdmin = currentUser?.role === 'SUPER_ADMIN'
  const canManage = viewerIsSuperAdmin && !isCurrentUser
  const isSuspended = admin.status === 'SUSPENDED'
  const subIds = parseSubIds(admin.subsidiaryIds)
  const subNames = subIds.map(id => allSubsidiaries.find(s => s.id === id)?.name).filter(Boolean) as string[]

  return (
    <div
      role="button" tabIndex={0}
      onClick={() => onSelect(admin)}
      onKeyDown={(e) => e.key === 'Enter' && onSelect(admin)}
      className="group relative flex flex-col md:flex-row md:items-center justify-between border-b border-border/40 bg-transparent p-4 transition-all hover:bg-accent/30 gap-3 cursor-pointer"
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
              <Shield className="h-3 w-3" />{isSuperAdmin ? 'Super Admin' : 'Admin'}
            </Badge>
            {isSuspended && <Badge variant="destructive" className="text-[10px]">Suspended</Badge>}
            {isCurrentUser && <Badge variant="outline" className="text-[10px]">You</Badge>}
          </div>
          <div className="flex items-center gap-4 mt-1 text-[11px] text-muted-foreground flex-wrap">
            <span className="flex items-center gap-1.5 min-w-0 flex-shrink">
              <Mail className="h-3 w-3 shrink-0" /><span className="truncate">{admin.email}</span>
            </span>
            <span className="flex items-center gap-1.5 shrink-0">
              <Calendar className="h-3 w-3 shrink-0" />{format(parseTimestamp(admin.createdAt), 'MMM d, yyyy')}
            </span>
            {admin.lastSeenAt && (
              <span className="flex items-center gap-1.5 shrink-0">
                <Eye className="h-3 w-3 shrink-0" />{formatRelativeTime(admin.lastSeenAt)}
              </span>
            )}
          </div>
          {/* Subsidiary routing pills */}
          {!isSuperAdmin && allSubsidiaries.length > 0 && (
            <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
              {subNames.length === 0 ? (
                <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-950/30 text-blue-600 border border-blue-200/60 dark:border-blue-800/40">
                  <Building2 className="h-2.5 w-2.5" />Generalist
                </span>
              ) : (
                <>
                  {subNames.slice(0, 3).map(name => (
                    <span key={name} className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border border-emerald-200/60 dark:border-emerald-800/40">
                      <Building2 className="h-2.5 w-2.5" />{name}
                    </span>
                  ))}
                  {subNames.length > 3 && (
                    <span className="text-[10px] text-muted-foreground">+{subNames.length - 3} more</span>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 self-end md:self-auto" onClick={(e) => e.stopPropagation()}>
        {!isCurrentUser && (
          <button onClick={() => onDM(admin)} title={`Message ${admin.name}`}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors">
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
              <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => onRoleChange(admin)}>
                <UserCog className="h-4 w-4" />Change Role
              </DropdownMenuItem>
              {isSuspended ? (
                <DropdownMenuItem className="gap-2 text-green-600 focus:text-green-600 cursor-pointer" onClick={() => onReactivate(admin)}>
                  <UserCheck className="h-4 w-4" />Reactivate Admin
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem className="gap-2 text-destructive focus:text-destructive cursor-pointer" onClick={() => onSuspend(admin)}>
                  <UserMinus className="h-4 w-4" />Suspend Admin
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </div>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 rounded-xl border p-4">
          <Skeleton className="h-12 w-12 rounded-full shrink-0" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-56" />
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
  const { data, isLoading, isError } = useAdminList()
  const { data: configData } = useAppConfig()
  const allSubsidiaries = configData?.subsidiaries ?? []
  const createAdmin = useCreateAdmin()
  const updateAdminRole = useUpdateAdminRole()
  const queryClient = useQueryClient()

  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pendingAction, setPendingAction] = useState<string | null>(null)
  const [selectedAdmin, setSelectedAdmin] = useState<User | null>(null)
  const [showRoleDialog, setShowRoleDialog] = useState(false)
  const [targetRole, setTargetRole] = useState<'ADMIN' | 'USER'>('ADMIN')
  const [confirmSuspendTarget, setConfirmSuspendTarget] = useState<User | null>(null)
  const [confirmReactivateTarget, setConfirmReactivateTarget] = useState<User | null>(null)

  const regularAdmins = (data?.admins ?? [])
  const superAdmins = (data?.superAdmins ?? [])  // FIX #7: include self — show "You" badge instead of hiding
  const allAdmins = [...superAdmins, ...regularAdmins]
  const navigate = useNavigate()
  const handleDM = (admin: User) => navigate(`/admin/dm?partner=${admin.id}`)

  const handleCreate = () => {
    createAdmin.mutate({ name, email, password }, {
      onSuccess: () => { setShowCreate(false); setName(''); setEmail(''); setPassword('') },
    })
  }

  const handleSuspend = async (targetUser: User) => {
    if (targetUser.id === user?.id) { toast.error("You can't suspend yourself"); return }
    setPendingAction(targetUser.id)
    try {
      await adminAdmins.suspend(targetUser.id)
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      toast.success(`${targetUser.name} has been suspended`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to suspend admin')
    } finally { setPendingAction(null) }
  }

  const handleReactivate = async (targetUser: User) => {
    setPendingAction(targetUser.id)
    try {
      await adminAdmins.reactivate(targetUser.id)
      queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
      toast.success(`${targetUser.name} has been reactivated`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to reactivate admin')
    } finally { setPendingAction(null) }
  }

  const handleRoleChange = async () => {
    if (!selectedAdmin) return
    updateAdminRole.mutate({ userId: selectedAdmin.id, role: targetRole }, {
      onSuccess: () => { setShowRoleDialog(false); setSelectedAdmin(null) },
    })
  }

  const openRoleDialog = (admin: User) => {
    setSelectedAdmin(admin); setTargetRole(admin.role as 'ADMIN' | 'USER'); setShowRoleDialog(true)
  }

  // When subsidiaries saved in the sheet, update the local cache so the card updates immediately
  const handleSubsidiariesSaved = (adminId: string, ids: string[]) => {
    queryClient.setQueryData<{ admins: User[]; superAdmins: User[] }>(['admin', 'admins'], (old) => {
      if (!old) return old
      const update = (list: User[]) => list.map(a =>
        a.id === adminId ? { ...a, subsidiaryIds: ids.length > 0 ? JSON.stringify(ids) : null } : a
      )
      return { ...old, admins: update(old.admins), superAdmins: update(old.superAdmins) }
    })
    if (selectedAdmin?.id === adminId) {
      setSelectedAdmin(prev => prev ? { ...prev, subsidiaryIds: ids.length > 0 ? JSON.stringify(ids) : null } : prev)
    }
  }

  if (isLoading) return <CardSkeleton />

  if (isError) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 text-muted-foreground p-8">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-8 w-8 text-destructive/60" />
        </div>
        <div className="text-center">
          <p className="font-semibold text-foreground">Failed to load admins</p>
          <p className="text-sm mt-1">There was an error loading the admin list.</p>
        </div>
        <Button variant="outline" className="gap-2 rounded-xl" onClick={() => queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })}>
          <ArrowLeft className="h-4 w-4" />Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="p-3 sm:p-4 border-b space-y-3 sm:space-y-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/10">
              <ShieldCheck className="h-5 w-5 text-primary" />
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-bold tracking-tight">Admin Management</h2>
              <p className="text-[11px] text-muted-foreground truncate">
                {allAdmins.length} administrator{allAdmins.length !== 1 ? 's' : ''} total
                {allSubsidiaries.length > 0 && <> · Click to configure routing</>}
              </p>
            </div>
          </div>
          {isSuperAdmin && (
            <Button size="sm" className="gap-1.5 rounded-full px-4 shadow-sm shrink-0" onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4" /><span className="hidden sm:inline">Add</span> Admin
            </Button>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1 bg-background">
        <div className="flex flex-col pb-4">
          {superAdmins.length > 0 && (
            <div className="flex flex-col">
              <div className="px-5 pt-4 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <Crown className="h-3.5 w-3.5 text-primary" />Super Admins
                </h3>
              </div>
              {superAdmins.map(admin => (
                <AdminCard key={admin.id} admin={admin} currentUser={user} allSubsidiaries={allSubsidiaries}
                  onSuspend={setConfirmSuspendTarget} onReactivate={setConfirmReactivateTarget} onDM={handleDM}
                  onSelect={setSelectedAdmin} onRoleChange={openRoleDialog} isPending={pendingAction === admin.id} />
              ))}
            </div>
          )}

          {regularAdmins.length > 0 && (
            <div className="flex flex-col">
              <div className="px-5 pt-4 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                  <UserCog className="h-3.5 w-3.5" />Admins
                </h3>
              </div>
              {regularAdmins.map(admin => (
                <AdminCard key={admin.id} admin={admin} currentUser={user} allSubsidiaries={allSubsidiaries}
                  onSuspend={setConfirmSuspendTarget} onReactivate={setConfirmReactivateTarget} onDM={handleDM}
                  onSelect={setSelectedAdmin} onRoleChange={openRoleDialog} isPending={pendingAction === admin.id} />
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

      <AdminDetailSheet
        admin={selectedAdmin} currentUser={user} open={!!selectedAdmin}
        onClose={() => setSelectedAdmin(null)} onSuspend={setConfirmSuspendTarget}
        onReactivate={setConfirmReactivateTarget} onDM={handleDM}
        isPending={!!(selectedAdmin && pendingAction === selectedAdmin.id)}
        onSubsidiariesSaved={handleSubsidiariesSaved}
      />

      {/* Create Admin Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Plus className="h-5 w-5 text-primary" />Create New Admin</DialogTitle>
            <DialogDescription>Add a new administrator to the platform.</DialogDescription>
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
              <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Min. 12 characters" className="rounded-xl" />
              {password && (() => {
                const checks = [
                  { label: '12+ characters', ok: password.length >= 12 },
                  { label: 'Uppercase letter', ok: /[A-Z]/.test(password) },
                  { label: 'Lowercase letter', ok: /[a-z]/.test(password) },
                  { label: 'Number', ok: /\d/.test(password) },
                  { label: 'Special character', ok: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password) },
                ]
                const passed = checks.filter(c => c.ok).length
                const strength = passed <= 2 ? 'Weak' : passed <= 3 ? 'Fair' : passed === 4 ? 'Good' : 'Strong'
                const strengthColor = passed <= 2 ? 'bg-destructive' : passed <= 3 ? 'bg-amber-500' : passed === 4 ? 'bg-blue-500' : 'bg-green-500'
                return (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all ${strengthColor}`} style={{ width: `${(passed / 5) * 100}%` }} />
                      </div>
                      <span className={`text-[10px] font-semibold ${passed <= 2 ? 'text-destructive' : passed <= 3 ? 'text-amber-600' : passed === 4 ? 'text-blue-600' : 'text-green-600'}`}>{strength}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-1">
                      {checks.map(c => (
                        <span key={c.label} className={`text-[10px] flex items-center gap-1 ${c.ok ? 'text-green-600' : 'text-muted-foreground'}`}>
                          <span>{c.ok ? '✓' : '○'}</span>{c.label}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              })()}
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setShowCreate(false)} className="rounded-xl">Cancel</Button>
            <Button onClick={handleCreate} disabled={!name || !email || !password || password.length < 12 || createAdmin.isPending} className="rounded-xl gap-2">
              {createAdmin.isPending && <LeafLogo className="h-4 w-4 animate-spin" />}Create Admin
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Role Dialog */}
      <Dialog open={showRoleDialog} onOpenChange={setShowRoleDialog}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><UserCog className="h-5 w-5 text-primary" />Change Admin Role</DialogTitle>
            <DialogDescription>Change the role for {selectedAdmin?.name}. Demoting to USER will revoke all their admin sessions.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-3">
              <button onClick={() => setTargetRole('ADMIN')} className={`flex flex-col items-center gap-2 p-4 rounded-xl border-2 transition-colors cursor-pointer ${targetRole === 'ADMIN' ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}`}>
                <Shield className="h-8 w-8 text-primary" />
                <span className="font-medium text-sm">Admin</span>
                <span className="text-[10px] text-muted-foreground text-center">Full admin access</span>
              </button>
              <button onClick={() => setTargetRole('USER')} className={`flex flex-col items-center gap-2 p-4 rounded-xl border-2 transition-colors cursor-pointer ${targetRole === 'USER' ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}`}>
                <UserIcon className="h-8 w-8 text-muted-foreground" />
                <span className="font-medium text-sm">User</span>
                <span className="text-[10px] text-muted-foreground text-center">Regular user access</span>
              </button>
            </div>
            {targetRole === 'USER' && (
              <p className="text-[11px] text-amber-600 bg-amber-50 dark:bg-amber-900/20 p-3 rounded-lg">
                Warning: Demoting to USER will immediately log this admin out of all sessions and remove their admin privileges.
              </p>
            )}
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setShowRoleDialog(false)} className="rounded-xl">Cancel</Button>
            <Button onClick={handleRoleChange} disabled={updateAdminRole.isPending || targetRole === selectedAdmin?.role} className="rounded-xl gap-2">
              {updateAdminRole.isPending && <LeafLogo className="h-4 w-4 animate-spin" />}Change Role
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Suspend Confirmation */}
      <AlertDialog open={!!confirmSuspendTarget} onOpenChange={(open) => { if (!open) setConfirmSuspendTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <UserMinus className="h-5 w-5 text-destructive" />
              Suspend {confirmSuspendTarget?.name}?
            </AlertDialogTitle>
            <AlertDialogDescription className="space-y-2">
              <span className="block">This will immediately:</span>
              <ul className="list-disc list-inside space-y-1 text-sm">
                <li>Log them out of all active sessions</li>
                <li>Unassign all their active conversations</li>
                <li>Block access until reactivated</li>
              </ul>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (confirmSuspendTarget) {
                  handleSuspend(confirmSuspendTarget)
                  setConfirmSuspendTarget(null)
                }
              }}
            >
              Suspend Admin
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Reactivate Confirmation */}
      <AlertDialog open={!!confirmReactivateTarget} onOpenChange={(open) => { if (!open) setConfirmReactivateTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <UserCheck className="h-5 w-5 text-green-600" />
              Reactivate {confirmReactivateTarget?.name}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will restore their admin access. They will need to log in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-green-600 text-white hover:bg-green-700"
              onClick={() => {
                if (confirmReactivateTarget) {
                  handleReactivate(confirmReactivateTarget)
                  setConfirmReactivateTarget(null)
                }
              }}
            >
              Reactivate Admin
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
