import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { MessageSquareLock, Crown, Users2, Eraser, ChevronRight, CheckSquare, Square } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { cn, getInitials } from '@/lib/utils'
import { useInternalMessages, useSendInternalMessage, useDeleteInternalMessage, useClearInternalChat, useInternalReaction } from '@/hooks/useInternalChat'
import { useAdminList } from '@/hooks/useUsers'
import { useAuthStore } from '@/stores/authStore'
import { getSocket } from '@/lib/socket'
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
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInternalMessages()
  const sendMessage = useSendInternalMessage()
  const deleteMessage = useDeleteInternalMessage()
  const clearChat = useClearInternalChat()
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const setReplyTo = useChatStore(s => s.setReplyTo)

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isBulkDeleting, setIsBulkDeleting] = useState(false)

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

  const handleBulkDelete = useCallback(async () => {
    if (selectedIds.size === 0) return
    setIsBulkDeleting(true)
    await Promise.allSettled(
      Array.from(selectedIds).map(id =>
        deleteMessage.mutateAsync({ id, scope: 'me' })
      )
    )
    setIsBulkDeleting(false)
    exitSelectMode()
  }, [selectedIds, deleteMessage, exitSelectMode])

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

  // Track typing via socket
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onTyping = (data: { userId: string; userName: string; isTyping: boolean }) => {
      if (data.userId === user?.id) return
      setTypingUsers(prev => {
        const next = new Set(prev)
        if (data.isTyping) next.add(data.userName)
        else next.delete(data.userName)
        return next
      })
    }
    socket.on('internal:typing', onTyping)
    return () => { socket.off('internal:typing', onTyping) }
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
    <div className="flex h-full flex-col bg-accent/20 dark:bg-background overflow-hidden relative">
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
                  <p className="text-[10px] text-muted-foreground">Click to open DM</p>
                </div>
                <div className="max-h-64 overflow-y-auto py-1">
                  {allAdmins.map(admin => (
                    <button
                      key={admin.id}
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
          className="h-7 w-7 text-muted-foreground shrink-0"
          title={selectMode ? 'Cancel selection' : 'Select messages'}
          onClick={() => selectMode ? exitSelectMode() : setSelectMode(true)}
        >
          {selectMode ? <Square className="h-4 w-4" /> : <CheckSquare className="h-4 w-4" />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:text-destructive shrink-0"
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

            return (
              <div key={msg.id} className="relative">
                <MessageBubble
                  message={msg}
                  hideAvatar={!showAvatar}
                  isSelectMode={selectMode}
                  isSelected={selectedIds.has(msg.id)}
                  onSelect={toggleSelect}
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
            const sendType = (data.type === 'TEXT' || data.type === 'IMAGE' || data.type === 'VIDEO' || data.type === 'DOCUMENT') ? data.type : 'TEXT';
            const tempId = `temp-internal-${Date.now()}-${tempCounter.current++}`
            sendMessage.mutate({ ...data, type: sendType as 'TEXT' | 'IMAGE' | 'VIDEO' | 'DOCUMENT', tempId })
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
    </div>
  )
}
