import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { MessageSquareLock, Crown, Users2, Eraser, ChevronRight, CheckSquare, Square, ShieldOff } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { cn, getInitials } from '@/lib/utils'
import { useInternalMessages, useSendInternalMessage, useDeleteInternalMessage, useClearInternalChat, useInternalReaction, useEmitInternalRead } from '@/hooks/useInternalChat'
import { useAdminList } from '@/hooks/useUsers'
import { useAuthStore } from '@/stores/authStore'
import { getSocket } from '@/lib/socket'
import { adminAdmins, adminUsers, adminInternal } from '@/lib/api'
import { toast } from '@/components/ui/sonner'
import { useQueryClient } from '@tanstack/react-query'
import { MessageInput } from '@/components/chat/MessageInput'
import { useChatStore } from '@/stores/chatStore'
import { MessageList } from '@/components/chat/MessageList'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'
import { BulkDeleteBar } from '@/components/chat/BulkDeleteBar'
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

export function InternalChatPage() {
  const user = useAuthStore(s => s.user)
  const queryClient = useQueryClient()

  // Mobile keyboard fix
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const update = () => document.documentElement.style.setProperty('--chat-h', `${vv.height}px`)
    update()
    vv.addEventListener('resize', update)
    vv.addEventListener('scroll', update)
    return () => { vv.removeEventListener('resize', update); vv.removeEventListener('scroll', update) }
  }, [])
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInternalMessages()
  const sendMessage = useSendInternalMessage(user)
  const deleteMessage = useDeleteInternalMessage()
  const clearChat = useClearInternalChat()
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const setReplyTo = useChatStore(s => s.setReplyTo)

  // Emit mark-read whenever this page is open → triggers group blue-tick for others
  useEmitInternalRead()

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isBulkDeleting, setIsBulkDeleting] = useState(false)

  // Suspend state
  const [suspendTarget, setSuspendTarget] = useState<{ id: string; name: string; role: string } | null>(null)
  const [isSuspending, setIsSuspending] = useState(false)

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const exitSelectMode = useCallback(() => {
    setSelectMode(false)
    setSelectedIds(new Set())
  }, [])

  // FIX #18: Use single bulk-delete endpoint — one transaction, one summary toast
  const handleBulkDelete = useCallback(async () => {
    if (selectedIds.size === 0) return
    setIsBulkDeleting(true)
    try {
      const ids = Array.from(selectedIds)
      const result = await adminInternal.bulkDelete(ids, 'me')
      if (result.succeeded > 0) {
        // Optimistically remove hidden messages from local cache
        queryClient.setQueriesData<{ pages: Array<{ messages: Array<{ id: string; hiddenFor?: string }> }> }>(
          { queryKey: ['admin', 'internal'] },
          (old) => {
            if (!old) return old
            const hiddenSet = new Set(ids)
            return {
              ...old,
              pages: old.pages.map(p => ({
                ...p,
                messages: p.messages.filter(m => !hiddenSet.has(m.id))
              }))
            }
          }
        )
        if (result.failed === 0) {
          toast.success(`Deleted ${result.succeeded} message${result.succeeded !== 1 ? 's' : ''}`)
        } else {
          toast.warning(`Deleted ${result.succeeded} of ${ids.length} messages — ${result.failed} failed`)
        }
      } else {
        toast.error('Failed to delete messages')
      }
    } catch {
      toast.error('Failed to delete messages')
    } finally {
      setIsBulkDeleting(false)
      exitSelectMode()
    }
  }, [selectedIds, queryClient, exitSelectMode])

  const navigate = useNavigate()
  const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set())
  const [showAdminList, setShowAdminList] = useState(false)
  const tempCounter = useRef(0)
  const reactionMut = useInternalReaction()

  const allMessages = useMemo(
    () => (data?.pages.flatMap(p => p.messages) ?? []).slice().reverse(),
    [data]
  )



  const sendTyping = useCallback((isTyping: boolean) => {
    const socket = getSocket()
    if (socket?.connected) socket.emit('internal:typing', { isTyping })
  }, [])


  // Get all admins from server for the team list
  const { data: adminListData } = useAdminList()
  const allAdmins = (adminListData?.allAdmins ?? []).filter(a => a.id !== user?.id)

  // Track typing via socket with auto-timeout (5 s) for abandoned typing indicators
  const typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onTyping = (data: { userId: string; userName: string; isTyping: boolean }) => {
      if (data.userId === user?.id) return

      // Clear any existing timer for this user
      const existing = typingTimersRef.current.get(data.userName)
      if (existing) clearTimeout(existing)

      if (data.isTyping) {
        setTypingUsers(prev => {
          const next = new Set(prev)
          next.add(data.userName)
          return next
        })
        // Auto-clear after 5 s of silence (user navigated away without stopping)
        const timer = setTimeout(() => {
          setTypingUsers(prev => {
            const next = new Set(prev)
            next.delete(data.userName)
            return next
          })
          typingTimersRef.current.delete(data.userName)
        }, 5000)
        typingTimersRef.current.set(data.userName, timer)
      } else {
        setTypingUsers(prev => {
          const next = new Set(prev)
          next.delete(data.userName)
          return next
        })
        typingTimersRef.current.delete(data.userName)
      }
    }

    const onNewMsg = () => {
      // Whenever a team message drops in while page is mounted, tell server we read it immediately
      socket.emit('internal:mark_read')
    }

    socket.on('internal:typing', onTyping)
    socket.on('internal:message', onNewMsg)
    return () => {
      socket.off('internal:typing', onTyping)
      socket.off('internal:message', onNewMsg)
      // Clear all pending timers on unmount
      typingTimersRef.current.forEach(t => clearTimeout(t))
      typingTimersRef.current.clear()
    }
  }, [user?.id])

  if (isLoading) {
    return (
      <div className="flex h-full flex-col p-4 space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className={cn('flex gap-2', i % 2 === 0 ? '' : 'flex-row-reverse')}>
            <Skeleton className="h-7 w-7 rounded-full shrink-0" />
            <Skeleton className={cn('h-10 rounded-2xl', i % 2 === 0 ? 'w-48' : 'w-32')} />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col bg-accent/20 dark:bg-background overflow-hidden relative">
      {/* Header */}
      <div className="flex items-center gap-3 border-b px-4 py-2.5 bg-sidebar shrink-0 z-10 shadow-sm">
        <div className={cn(
          'flex h-9 w-9 items-center justify-center rounded-xl',
          isSuperAdmin ? 'bg-primary/10' : 'bg-amber-100 dark:bg-amber-900/20'
        )}>
          {isSuperAdmin
            ? <Crown className="h-5 w-5 text-primary" />
            : <MessageSquareLock className="h-5 w-5 text-amber-600 dark:text-amber-400" />}
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-sm font-bold">
            {isSuperAdmin ? 'Admin Group Chat' : 'Team Chat'}
          </h2>
          <p className="text-[11px] text-muted-foreground truncate">
            {isSuperAdmin
              ? `${allAdmins.length + 1} member${allAdmins.length !== 0 ? 's' : ''} · Private admin channel`
              : 'Internal channel · visible to all admins'}
          </p>
        </div>
        <div className="relative">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 h-8 text-xs"
            onClick={() => setShowAdminList(v => !v)}
          >
            <Users2 className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Team</span>
            <Badge variant="secondary" className="text-[9px] h-4 min-w-4 px-1 rounded-full">
              {allAdmins.length}
            </Badge>
          </Button>
          {showAdminList && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setShowAdminList(false)} />
              <div className="absolute right-0 top-full mt-1.5 z-50 w-56 rounded-lg border bg-popover shadow-lg animate-in fade-in slide-in-from-top-1 duration-150">
                <div className="px-3 py-2 border-b">
                  <p className="text-xs font-semibold">Team Members</p>
                  <p className="text-[10px] text-muted-foreground">Click to open DM{isSuperAdmin ? ' · Super admins can suspend' : ''}</p>
                </div>
                <div className="max-h-64 overflow-y-auto py-1">
                  {allAdmins.map(admin => (
                    <div key={admin.id}>
                      <button
                        onClick={() => { setShowAdminList(false); navigate(`/admin/dm?partner=${admin.id}`) }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-accent transition-colors"
                      >
                        <div className={cn(
                          'flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[10px] font-bold',
                          admin.role === 'SUPER_ADMIN'
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-primary/20 text-primary'
                        )}>
                          {getInitials(admin.name)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1">
                            <span className="text-xs font-medium truncate">{admin.name}</span>
                            {admin.role === 'SUPER_ADMIN' && (
                              <Crown className="h-3 w-3 text-primary shrink-0" />
                            )}
                          </div>
                          <p className="text-[10px] text-muted-foreground">
                            {admin.role === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'}
                          </p>
                        </div>
                        <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      </button>
                      {isSuperAdmin && admin.role !== 'SUPER_ADMIN' && (
                        <button
                          onClick={(e) => { e.stopPropagation(); setShowAdminList(false); setSuspendTarget({ id: admin.id, name: admin.name, role: admin.role }) }}
                          className="w-full flex items-center gap-1.5 px-4 py-1 text-left text-[10px] text-destructive hover:bg-destructive/10 transition-colors"
                        >
                          <ShieldOff className="h-3 w-3" />
                          Suspend this admin
                        </button>
                      )}
                    </div>
                  ))}
                  {allAdmins.length === 0 && (
                    <p className="text-xs text-muted-foreground text-center py-4">No other admins</p>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
        {/* Select mode toggle */}
        <Button
          variant={selectMode ? 'secondary' : 'ghost'}
          size="icon"
          className="h-9 w-9 text-muted-foreground shrink-0"
          title={selectMode ? 'Cancel selection' : 'Select messages'}
          onClick={() => selectMode ? exitSelectMode() : setSelectMode(true)}
        >
          {selectMode ? <Square className="h-4 w-4" /> : <CheckSquare className="h-4 w-4" />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 text-muted-foreground hover:text-destructive shrink-0"
          title={isSuperAdmin ? 'Clear all messages permanently' : 'Clear chat for me'}
          onClick={() => setShowClearConfirm(true)}
        >
          <Eraser className="h-4 w-4" />
        </Button>
      </div>

      {/* Messages */}
      <div className="flex-1 relative min-h-0 flex flex-col">
        <MessageList
          messages={allMessages}
          isLoading={isLoading}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={hasNextPage}
          fetchNextPage={fetchNextPage}
          getTimestamp={(msg) => msg.createdAt}
          emptyState={
            <div className="flex flex-col items-center gap-4 py-24 text-muted-foreground">
              <div className={cn(
                'flex h-16 w-16 items-center justify-center rounded-2xl',
                isSuperAdmin ? 'bg-primary/10' : 'bg-amber-100 dark:bg-amber-900/20'
              )}>
                {isSuperAdmin
                  ? <Crown className="h-8 w-8 text-primary" />
                  : <MessageSquareLock className="h-8 w-8 text-amber-500" />}
              </div>
              <div className="text-center space-y-1">
                <p className="text-sm font-medium text-foreground">
                  {isSuperAdmin ? 'Admin group chat' : 'Team channel'}
                </p>
                <p className="text-xs">
                  {isSuperAdmin
                    ? 'Communicate with all admins. All admins can see this channel.'
                    : 'Send messages to the team. Super admin and all admins see this.'}
                </p>
              </div>
            </div>
          }
          bottomContent={
            typingUsers.size > 0 ? (
              <div className="flex flex-col gap-1 pb-2">
                {Array.from(typingUsers).map((u) => (
                  <TypingIndicator key={u} userName={u} />
                ))}
              </div>
            ) : null
          }
          renderMessage={(msg, idx) => {
            const isOwn = msg.senderId === user?.id || msg.sender.id === user?.id
            const prev = allMessages[idx - 1]
            const showAvatar = !isOwn && (!prev || prev.senderId !== msg.senderId)
            // Group tick: others = total admins minus self
            const groupSize = Math.max(0, allAdmins.length) // allAdmins already excludes self
            const readCount = (msg as any).readBy?.length ?? 0

            return (
              <div key={msg.id} className="relative">
                <MessageBubble
                  message={msg}
                  hideAvatar={!showAvatar}
                  isSelectMode={selectMode}
                  isSelected={selectedIds.has(msg.id)}
                  onSelect={toggleSelect}
                  groupMode
                  groupSize={groupSize}
                  readCount={readCount}
                  onAvatarClick={selectMode ? undefined : (senderId) => {
                    // Don't DM yourself
                    if (senderId === user?.id) return
                    navigate(`/admin/dm?partner=${senderId}`)
                  }}
                  onReact={selectMode ? undefined : (emoji) => {
                    const hasReacted = msg.reactions?.some((r) => r.userId === user?.id && r.emoji === emoji)
                    reactionMut.mutate({
                      messageId: msg.id,
                      emoji,
                      action: hasReacted ? 'remove' : 'add'
                    })
                  }}
                  onReply={selectMode ? undefined : (m) => setReplyTo(m as any)}
                  onDelete={selectMode ? undefined : () => deleteMessage.mutate({ id: msg.id, scope: 'me' })}
                  onRetry={(msg as any).status === 'FAILED' ? () => {
                    queryClient.setQueryData<{ pages: Array<{ messages: any[]; hasMore: boolean; success: boolean }> }>(
                      ['internal-messages'],
                      (old) => old ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter((m: any) => m.id !== msg.id) })) } : old
                    )
                    sendMessage.mutate({ type: msg.type, content: msg.content ?? undefined, tempId: `retry-${msg.id}` })
                  } : undefined}
                  canDeleteOverride={isOwn || user?.role === 'SUPER_ADMIN'}
                />
              </div>
            )
          }}
        />
      </div>

      {selectMode ? (
        <BulkDeleteBar
          count={selectedIds.size}
          onDelete={handleBulkDelete}
          onCancel={exitSelectMode}
          isDeleting={isBulkDeleting}
        />
      ) : (
        <MessageInput
          conversationId="internal"
          onSend={(data) => {
            const sendType = (data.type === 'TEXT' || data.type === 'IMAGE' || data.type === 'DOCUMENT') ? data.type : 'TEXT';
            const tempId = `temp-internal-${Date.now()}-${tempCounter.current++}`
            sendMessage.mutate({ ...data, type: sendType as 'TEXT' | 'IMAGE' | 'DOCUMENT', tempId })
          }}
          onTyping={sendTyping}
        />
      )}

      {/* Clear chat confirm dialog */}
      <AlertDialog open={showClearConfirm} onOpenChange={setShowClearConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Clear chat</AlertDialogTitle>
            <AlertDialogDescription>
              {isSuperAdmin
                ? 'This will permanently delete all messages for everyone. This cannot be undone.'
                : 'All current messages will be hidden for you only. Others can still see them.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { clearChat.mutate(); setShowClearConfirm(false) }}
            >
              {isSuperAdmin ? 'Clear for everyone' : 'Clear for me'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Suspend confirmation dialog */}
      <AlertDialog open={!!suspendTarget} onOpenChange={o => !o && setSuspendTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Suspend {suspendTarget?.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately suspend <strong>{suspendTarget?.name}</strong>'s account.
              They will be logged out and unable to access the site until reactivated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={isSuspending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={async () => {
                if (!suspendTarget) return
                setIsSuspending(true)
                try {
                  // Admins and Super Admins are in adminAdmins; regular Users in adminUsers
                  if (suspendTarget.role === 'ADMIN' || suspendTarget.role === 'SUPER_ADMIN') {
                    await adminAdmins.suspend(suspendTarget.id)
                    queryClient.invalidateQueries({ queryKey: ['admin', 'admins'] })
                  } else {
                    await adminUsers.updateStatus(suspendTarget.id, { status: 'SUSPENDED' })
                    queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
                  }
                  toast.success(`${suspendTarget.name} has been suspended`)
                  setSuspendTarget(null)
                } catch {
                  toast.error('Failed to suspend user')
                } finally {
                  setIsSuspending(false)
                }
              }}
            >
              {isSuspending ? 'Suspending…' : 'Suspend'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
