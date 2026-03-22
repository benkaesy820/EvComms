import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Crown, Shield, MessageCircle, Menu, ChevronDown, ChevronRight, Users, PanelLeftClose, PanelLeft } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Sheet, SheetContent, SheetTitle, SheetDescription } from '@/components/ui/sheet'
import { cn, getInitials } from '@/lib/utils'
import { useDMConversations, useDMMessages, useSendDM, useDeleteDM, useDMReaction, useMarkDMRead } from '@/hooks/useDM'
import { useAuthStore } from '@/stores/authStore'
import { useAdminList } from '@/hooks/useUsers'
import { getSocket } from '@/lib/socket'
import { EmptyState } from '@/components/ui/empty-state'
import { MessageInput } from '@/components/chat/MessageInput'
import { useChatStore } from '@/stores/chatStore'
import { MessageList } from '@/components/chat/MessageList'
import { MessageBubble, TypingIndicator } from '@/components/chat/MessageBubble'

function RoleIcon({ role }: { role: string }) {
  if (role === 'SUPER_ADMIN') return <Crown className="h-3 w-3 text-primary" />
  return <Shield className="h-3 w-3 text-amber-500" />
}

export function DMPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const currentUser = useAuthStore((s) => s.user)
  const isSuperAdmin = currentUser?.role === 'SUPER_ADMIN'
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

  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get('partner'))
  const [isMobile, setIsMobile] = useState(() => typeof window !== 'undefined' ? window.innerWidth < 768 : false)

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768)
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    // Never restore a collapsed sidebar on mobile — the Sheet handles navigation there
    if (typeof window !== 'undefined' && window.innerWidth < 768) return false
    try { return localStorage.getItem('dm-sidebar-collapsed') === 'true' } catch { return false }
  })
  const toggleSidebar = useCallback(() => setSidebarCollapsed(v => {
    const next = !v
    localStorage.setItem('dm-sidebar-collapsed', String(next))
    return next
  }), [])
  const [mobileOpen, setMobileOpen] = useState(!searchParams.get('partner') && isMobile)
  const setReplyTo = useChatStore(s => s.setReplyTo)
  const [onlineUsers, setOnlineUsers] = useState<Set<string>>(new Set())
  // Collapsible sidebar sections
  const [convosCollapsed, setConvosCollapsed] = useState(false)
  const [newCollapsed, setNewCollapsed] = useState(false)

  // Fix: Clear global reply state when leaving DM page
  useEffect(() => {
    return () => setReplyTo(null)
  }, [setReplyTo])

  // Fix: Handle resize properly to toggle mobile modal safely
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 768) {
        setMobileOpen(false)
      } else if (!searchParams.get('partner')) {
        setMobileOpen(true)
      }
    }
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [searchParams])

  // Fix: Track ALL online users globally for the contact list
  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const handleOnline = (data: { userId: string }) => setOnlineUsers(prev => new Set(prev).add(data.userId))
    const handleOffline = (data: { userId: string }) => {
      setOnlineUsers(prev => { const next = new Set(prev); next.delete(data.userId); return next })
    }
    // FIX #17: Request the current online roster on mount so presence dots show immediately
    const handlePresenceSnapshot = (data: { onlineUserIds: string[] }) => {
      setOnlineUsers(new Set(data.onlineUserIds))
    }
    socket.on('user:online', handleOnline)
    socket.on('user:offline', handleOffline)
    socket.on('presence:snapshot', handlePresenceSnapshot)
    socket.emit('presence:get')
    return () => {
      socket.off('user:online', handleOnline)
      socket.off('user:offline', handleOffline)
      socket.off('presence:snapshot', handlePresenceSnapshot)
    }
  }, [])

  const { data: convosData, isLoading: convosLoading } = useDMConversations()
  const { data: adminListData } = useAdminList()

  const conversations = convosData?.conversations ?? []
  const allAdmins = adminListData?.allAdmins ?? []

  const messagesQuery = useDMMessages(selectedId)
  const sendDM = useSendDM(selectedId)
  const deleteDM = useDeleteDM()
  // Zero unread badge instantly when a thread is opened
  useMarkDMRead(selectedId)

  const messages = useMemo(
    () => messagesQuery.data?.pages.flatMap((p) => p.messages) ?? [],
    [messagesQuery.data]
  )
  const partner = useMemo<any>(() => {
    const fromConvo = conversations.find((c) => c.partner.id === selectedId)?.partner
    const fromAdmin = allAdmins.find((a) => a.id === selectedId)
    return fromConvo || fromAdmin || null
  }, [conversations, allAdmins, selectedId])

  // Sync URL param with selected partner
  useEffect(() => {
    const fromUrl = searchParams.get('partner')
    if (fromUrl && fromUrl !== selectedId) {
      setSelectedId(fromUrl)
      setMobileOpen(false)
    }
  }, [searchParams])

  const selectPartner = useCallback((id: string) => {
    setSelectedId(id)
    setSearchParams({ partner: id }, { replace: true })
    setMobileOpen(false)
  }, [setSearchParams])

  // Auto-select latest conversation when no partner is set in URL
  useEffect(() => {
    if (selectedId) return
    const latest = conversations[0]
    if (latest) { selectPartner(latest.partner.id) }
  }, [conversations, selectedId, selectPartner])

  const handleDelete = useCallback((messageId: string, scope: 'me' | 'all') => {
    if (!selectedId) return
    deleteDM.mutate({ messageId, adminId: selectedId, scope })
  }, [selectedId, deleteDM])

  // All admins (excluding self) not yet in a conversation — available to all admins
  const newContacts = useMemo(() => {
    const contactIds = new Set(conversations.map((c) => c.partner.id))
    return allAdmins.filter(
      (a) => a.id !== currentUser?.id && !contactIds.has(a.id)
    )
  }, [conversations, allAdmins, currentUser?.id])
  const reactionMut = useDMReaction(selectedId || '')

  const [partnerTyping, setPartnerTyping] = useState(false)
  const partnerTypingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isPartnerOnline = partner ? onlineUsers.has(partner.id) : false

  useEffect(() => {
    if (!selectedId) return
    const socket = getSocket()
    if (!socket) return
    const handler = (data: { userId: string; isTyping: boolean }) => {
      if (data.userId !== selectedId) return
      setPartnerTyping(data.isTyping)
      if (partnerTypingTimerRef.current) clearTimeout(partnerTypingTimerRef.current)
      if (data.isTyping) {
        partnerTypingTimerRef.current = setTimeout(() => setPartnerTyping(false), 4000)
      }
    }

    socket.on('dm:typing', handler)
    return () => {
      socket.off('dm:typing', handler)
    }
  }, [selectedId])

  const sendTyping = useCallback((isTyping: boolean) => {
    if (!selectedId) return
    const socket = getSocket()
    if (socket?.connected) socket.emit('dm:typing', { partnerId: selectedId, isTyping })
  }, [selectedId])

  const ContactList = () => (
    <>
      <div className="px-4 py-3 border-b shrink-0 z-10 bg-background flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/10">
            <MessageCircle className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-sm font-bold">Direct Messages</h2>
            <p className="text-[10px] text-muted-foreground">Admin-to-admin</p>
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="py-2">
          {convosLoading && (
            <div className="px-3 space-y-2 py-1">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-center gap-2 p-2 rounded-lg">
                  <Skeleton className="h-8 w-8 rounded-full shrink-0" />
                  <div className="flex-1 space-y-1">
                    <Skeleton className="h-3 w-24" />
                    <Skeleton className="h-2.5 w-32" />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Conversations Section ── */}
          {conversations.length > 0 && (
            <>
              <button
                className="w-full flex items-center justify-between px-4 py-1.5 text-left hover:bg-accent/30 transition-colors group"
                onClick={() => setConvosCollapsed(v => !v)}
              >
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Conversations
                </span>
                {convosCollapsed
                  ? <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  : <ChevronDown className="h-3 w-3 text-muted-foreground" />}
              </button>

              {!convosCollapsed && conversations.map((conv) => {
                const unread = (conv as any).unreadCount ?? 0
                return (
                  <button
                    key={conv.partner.id}
                    onClick={() => selectPartner(conv.partner.id)}
                    className={cn(
                      'w-full flex items-center gap-2.5 px-3 py-3 text-left transition-all border-b border-border/40',
                      selectedId === conv.partner.id
                        ? 'bg-accent'
                        : 'hover:bg-accent/50 text-foreground',
                    )}
                  >
                    <div className="relative shrink-0">
                      <div className={cn(
                        'flex h-8 w-8 items-center justify-center rounded-full text-[11px] font-bold',
                        conv.partner.role === 'SUPER_ADMIN'
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-primary/20 text-primary',
                      )}>
                        {getInitials(conv.partner.name)}
                      </div>
                      {onlineUsers.has(conv.partner.id) && (
                        <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-green-500" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1">
                        <div className="flex items-center gap-1 min-w-0">
                          <span className={cn('text-xs truncate', unread > 0 ? 'font-bold' : 'font-semibold')}>
                            {conv.partner.name}
                          </span>
                          <RoleIcon role={conv.partner.role} />
                        </div>
                        {unread > 0 && (
                          <Badge className="h-4 min-w-4 rounded-full px-1 text-[9px] bg-primary text-primary-foreground shrink-0">
                            {unread}
                          </Badge>
                        )}
                      </div>
                      <p className={cn('text-[10px] truncate', unread > 0 ? 'text-foreground font-medium' : 'text-muted-foreground')}>
                        {conv.lastMessage.senderId === currentUser?.id ? 'You: ' : ''}
                        {conv.lastMessage.content ?? `[${conv.lastMessage.type.toLowerCase()}]`}
                      </p>
                    </div>
                  </button>
                )
              })}
            </>
          )}

          {/* ── New Contacts Section ── */}
          {newContacts.length > 0 && (
            <>
              <button
                className="w-full flex items-center justify-between px-4 py-1.5 text-left hover:bg-accent/30 transition-colors mt-1"
                onClick={() => setNewCollapsed(v => !v)}
              >
                <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Start a conversation
                </span>
                {newCollapsed
                  ? <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  : <ChevronDown className="h-3 w-3 text-muted-foreground" />}
              </button>

              {!newCollapsed && newContacts.map((admin) => (
                <button
                  key={admin.id}
                  onClick={() => selectPartner(admin.id)}
                  className={cn(
                    'w-full flex items-center gap-2.5 px-3 py-3 text-left transition-all border-b border-border/40',
                    selectedId === admin.id
                      ? 'bg-accent'
                      : 'hover:bg-accent/50 text-foreground',
                  )}
                >
                  <div className="relative shrink-0">
                    <div className={cn(
                      'flex h-8 w-8 items-center justify-center rounded-full text-[11px] font-bold',
                      admin.role === 'SUPER_ADMIN'
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-primary/20 text-primary',
                    )}>
                      {getInitials(admin.name)}
                    </div>
                    {onlineUsers.has(admin.id) && (
                      <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-green-500" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1">
                      <span className="text-xs font-semibold truncate">{admin.name}</span>
                      <RoleIcon role={admin.role} />
                    </div>
                    <p className="text-[10px] text-muted-foreground">Start conversation</p>
                  </div>
                </button>
              ))}
            </>
          )}

          {!convosLoading && conversations.length === 0 && newContacts.length === 0 && (
            <p className="text-[11px] text-muted-foreground text-center py-6 px-3">
              No other admins available.
            </p>
          )}
        </div>
      </ScrollArea>
    </>
  )

  return (
    <div className="flex h-full overflow-hidden relative">
      {/* Mobile Contact Sheet Overlay */}
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="p-0 flex flex-col w-[280px]" aria-describedby="dm-contacts-desc">
          <SheetTitle className="sr-only">Direct Message Contacts</SheetTitle>
          <SheetDescription id="dm-contacts-desc" className="sr-only">Select a contact to start a direct message conversation</SheetDescription>
          <ContactList />
        </SheetContent>
      </Sheet>

      {/* Desktop contact list */}
      <div className={cn(
        'hidden md:flex shrink-0 border-r flex-col bg-background transition-all duration-300 ease-in-out',
        selectedId && !sidebarCollapsed ? 'md:w-72' : '',
        selectedId && sidebarCollapsed ? 'md:w-0 md:overflow-hidden md:border-r-0' : '',
        !selectedId ? 'w-full md:w-72' : '',
      )}>
        <ContactList />
      </div>


      {/* Right panel: messages */}
      {!selectedId ? (
        <div className="flex-1 flex flex-col items-center justify-center relative">
          <button
            onClick={() => setMobileOpen(true)}
            className="md:hidden absolute top-4 left-4 flex h-10 w-10 items-center justify-center rounded-xl bg-accent text-muted-foreground hover:text-foreground hover:bg-accent/80 transition-colors"
          >
            <Menu className="h-5 w-5" />
          </button>
          <EmptyState
            icon={MessageCircle}
            title="No conversation selected"
            subtitle="Select an admin to message, or start a new conversation"
          />
        </div>
      ) : (
        <div className="chat-viewport-height flex-1 flex flex-col min-w-0 overflow-hidden bg-accent/20 dark:bg-background relative">
          {/* Partner header */}
          <div className="flex items-center gap-3 px-4 py-2.5 border-b shrink-0 bg-sidebar shadow-sm z-10">
            <button
              onClick={() => setMobileOpen(true)}
              className="md:hidden flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/50 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              <Menu className="h-4 w-4" />
            </button>
            {/* Desktop sidebar toggle */}
            <button
              onClick={toggleSidebar}
              className="hidden md:flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              {sidebarCollapsed
                ? <PanelLeft className="h-4 w-4" />
                : <PanelLeftClose className="h-4 w-4" />
              }
            </button>
            {messagesQuery.isLoading || convosLoading || !adminListData ? (
              <Skeleton className="h-8 w-48" />
            ) : partner ? (
              <>
                <div className={cn(
                  'relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-bold',
                  partner.role === 'SUPER_ADMIN'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-primary/20 text-primary',
                )}>
                  {getInitials(partner.name)}
                  <span className={cn(
                    'absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-background',
                    isPartnerOnline ? 'bg-green-500' : 'bg-muted-foreground'
                  )} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm font-bold">{partner.name}</span>
                    <Badge variant="outline" className="text-[10px] gap-1 py-0">
                      <RoleIcon role={partner.role} />
                      {partner.role === 'SUPER_ADMIN' ? 'Super Admin' : 'Admin'}
                    </Badge>
                  </div>
                  <p className="text-[11px] text-muted-foreground">{partnerTyping ? 'typing…' : 'Direct Message'}</p>
                </div>
              </>
            ) : selectedId ? (
              <div className="flex items-center gap-2">
                <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground text-sm font-bold">
                  <Users className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-sm font-bold">User not found</p>
                  <p className="text-[11px] text-muted-foreground">Admin no longer exists or invalid ID</p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/20 text-primary text-sm font-bold">
                  <MessageCircle className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-sm font-bold">New Conversation</p>
                  <p className="text-[11px] text-muted-foreground">Send your first message</p>
                </div>
              </div>
            )}
          </div>

          {/* Messages area */}
          <MessageList
            messages={messages}
            isLoading={messagesQuery.isLoading}
            isFetchingNextPage={messagesQuery.isFetchingNextPage}
            hasNextPage={messagesQuery.hasNextPage}
            fetchNextPage={messagesQuery.fetchNextPage}
            getTimestamp={(msg) => msg.createdAt}
            scrollDependencies={[selectedId]}
            emptyState={
              <div className="flex flex-col items-center justify-center py-16 gap-2 text-muted-foreground">
                <MessageCircle className="h-8 w-8 opacity-30" />
                <p className="text-sm">No messages yet. Say hello!</p>
              </div>
            }
            bottomContent={
              partnerTyping && partner ? (
                <div className="pb-2">
                  <TypingIndicator userName={partner.name.split(' ')[0]} />
                </div>
              ) : null
            }
            renderMessage={(msg) => {
              const isMine = msg.senderId === currentUser?.id
              const canDelete = isMine || isSuperAdmin

              return (
                <div key={msg.id} className="relative">
                  <MessageBubble
                    message={msg}
                    canDeleteOverride={canDelete}
                    onReact={(emoji) => {
                      const hasReacted = msg.reactions?.some((r) => r.userId === currentUser?.id && r.emoji === emoji)
                      reactionMut.mutate({
                        messageId: msg.id,
                        emoji,
                        action: hasReacted ? 'remove' : 'add'
                      })
                    }}
                    onReply={(m) => setReplyTo(m as any)}
                    onDelete={(scope) => handleDelete(msg.id, scope)}
                    onRetry={(msg as any).status === 'FAILED' ? () => {
                      queryClient.setQueryData<{ pages: Array<{ messages: any[]; hasMore: boolean; success: boolean }> }>(
                        ['dm-messages', selectedId],
                        (old) => old ? { ...old, pages: old.pages.map(p => ({ ...p, messages: p.messages.filter((m: any) => m.id !== msg.id) })) } : old
                      )
                      sendDM.mutate({ type: msg.type, content: msg.content ?? undefined })
                    } : undefined}
                  />
                </div>
              )
            }}
          />

          <MessageInput
            conversationId={selectedId!}
            onSend={(data) => {
              const sendType = (data.type === 'TEXT' || data.type === 'IMAGE' || data.type === 'DOCUMENT') ? data.type : 'TEXT';
              sendDM.mutate({ ...data, type: sendType as 'TEXT' | 'IMAGE' | 'DOCUMENT' })
            }}
            onTyping={sendTyping}
          />
        </div>
      )
      }
    </div >
  )
}
