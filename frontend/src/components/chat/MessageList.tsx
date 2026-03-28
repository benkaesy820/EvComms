import { LeafLogo } from '@/components/ui/LeafLogo'
import { useLayoutEffect, useRef, useState, useCallback, useMemo } from 'react'
import { ArrowDown, MessageCircle } from 'lucide-react'
import { format, isToday, isYesterday } from 'date-fns'
import { parseTimestamp, cn } from '@/lib/utils'

export interface MessageListProps<T extends { id: string }> {
    messages: T[]
    isLoading?: boolean
    isFetchingNextPage?: boolean
    hasNextPage?: boolean
    fetchNextPage?: () => void
    renderMessage: (msg: T, index: number, groupMessages: T[]) => React.ReactNode

    getTimestamp: (msg: T) => number | string

    emptyState?: React.ReactNode
    bottomContent?: React.ReactNode

    className?: string

    // Optional dependency array to trigger scroll to bottom when things change
    scrollDependencies?: any[]

    /**
     * Maximum number of paginated pages to keep rendered in the DOM.
     * Older pages are hidden (not unmounted) once the user loads past this limit.
     * Keeps DOM node count sane for long conversations.
     * Default: 6 pages (~300 messages for limit=50).
     */
    maxRenderedPages?: number

    /**
     * Ref callback attached to the last (newest) rendered message.
     * Used by useVisibilityMarkRead to fire markRead only when the
     * newest message actually enters the viewport.
     */
    lastMessageRef?: (el: HTMLDivElement | null) => void
}

function formatDateLabel(ts: number | string) {
    const d = typeof ts === 'number' ? new Date(ts) : new Date(parseTimestamp(ts))
    if (isToday(d)) return 'Today'
    if (isYesterday(d)) return 'Yesterday'
    return format(d, 'MMMM d, yyyy')
}

export function MessageList<T extends { id: string }>({
    messages,
    isLoading,
    isFetchingNextPage,
    hasNextPage,
    fetchNextPage,
    renderMessage,
    getTimestamp,
    emptyState,
    bottomContent,
    className,
    scrollDependencies = [],
    maxRenderedPages = 6,
    lastMessageRef,
}: MessageListProps<T>) {
    const [showScrollBtn, setShowScrollBtn] = useState(false)
    // Track how many pages have been loaded so we can cap DOM rendering
    const [, setLoadedPages] = useState(1)
    const viewportRef = useRef<HTMLDivElement>(null)
    const getTimestampRef = useRef(getTimestamp)
    getTimestampRef.current = getTimestamp

    const sortedMessages = useMemo(() => {
        const tsFn = getTimestampRef.current
        
        // Schwartzian transform: map to [msg, timeInt] once
        const mapped = messages.map(msg => {
            const ts = tsFn(msg)
            const timeInt = typeof ts === 'number' ? ts : parseTimestamp(ts).getTime()
            return { msg, timeInt }
        })
        
        // Sort efficiently using numbers
        mapped.sort((a, b) => a.timeInt - b.timeInt)
        
        const pageSize = 50
        const maxMessages = maxRenderedPages * pageSize
        return mapped.length > maxMessages 
            ? mapped.slice(mapped.length - maxMessages)
            : mapped
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [messages, maxRenderedPages])

    // Group messages by date — oldest first
    const messageGroups = useMemo(() => {
        const groups: { date: string; messages: T[] }[] = []
        let currentDayToken = ''
        let currentDateLabel = ''

        for (const item of sortedMessages) {
            const { msg, timeInt } = item
            
            // Format memory-cheap token for comparison: YYYY-MM-DD
            const d = new Date(timeInt)
            const dayToken = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
            
            // Only perform expensive date-fns formatting if the actual day shifted
            if (dayToken !== currentDayToken) {
                currentDayToken = dayToken
                currentDateLabel = formatDateLabel(timeInt)
                groups.push({ date: currentDateLabel, messages: [] })
            }
            groups[groups.length - 1].messages.push(msg)
        }
        return groups
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [sortedMessages])

    // With column-reverse layout, scrollTop=0 = newest messages (visual bottom).
    // We only need an effect for new incoming messages while the user is already at the bottom.
    const prevLengthRef = useRef(messages.length)

    useLayoutEffect(() => {
        const el = viewportRef.current
        if (!el) return
        // Only smooth-scroll for a new message if user was already at the bottom
        if (messages.length > prevLengthRef.current && el.scrollTop < 100) {
            el.scrollTo({ top: 0, behavior: 'smooth' })
        }
        prevLengthRef.current = messages.length
    }, [messages.length])

    // Reset when conversation changes — snap back to bottom (top in DOM = scrollTop 0)
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useLayoutEffect(() => {
        const el = viewportRef.current
        if (el) el.scrollTop = 0
        prevLengthRef.current = messages.length
        setLoadedPages(1)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [...scrollDependencies])

    const handleScroll = useCallback(() => {
        const el = viewportRef.current
        if (!el) return

        // With column-reverse: scrollTop=0 = bottom (newest). scrollTop > 0 = user scrolled up.
        setShowScrollBtn(el.scrollTop > 200)

        // Load older messages when user scrolls near the visual top
        // (which is scrollTop approaching max = scrollHeight - clientHeight)
        const distFromTop = el.scrollHeight - el.scrollTop - el.clientHeight
        if (distFromTop < 80 && hasNextPage && !isFetchingNextPage && fetchNextPage) {
            fetchNextPage()
            setLoadedPages(p => p + 1)
        }
    }, [hasNextPage, isFetchingNextPage, fetchNextPage])

    const scrollToBottom = useCallback(() => {
        viewportRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
    }, [])

    return (
        <div className={cn("flex-1 relative min-h-0 flex flex-col", className)}>
            <div
                ref={viewportRef}
                // column-reverse: first DOM child appears at visual bottom.
                // scrollTop=0 naturally shows the latest content — no scroll effects needed on mount.
                className="flex-1 overflow-y-auto overscroll-y-none flex flex-col-reverse"
                style={{ scrollBehavior: 'auto' }}
                onScroll={handleScroll}
            >
                {/* This inner div is the FIRST flex child → appears at visual bottom */}
                <div className="p-4 pt-2 pb-2 space-y-3">
                    {/* Typing indicators / extra bottom content */}
                    {bottomContent}
                </div>

                {/* Messages: groups rendered newest-first (latest group is first DOM child inside column-reverse = visual bottom) */}
                {isLoading && messages.length === 0 ? (
                    <div className="flex justify-center py-8">
                        <LeafLogo className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                ) : sortedMessages.length === 0 ? (
                    <div className="px-4">
                        {emptyState || (
                            <div className="flex flex-col items-center justify-center py-16 gap-2 text-muted-foreground">
                                <MessageCircle className="h-8 w-8 opacity-30" />
                                <p className="text-sm">No messages yet.</p>
                            </div>
                        )}
                    </div>
                ) : (
                    // Newest group first in DOM → appears at visual bottom (just above bottomContent)
                    [...messageGroups].reverse().map((group, groupIdx) => (
                        <div key={group.date} className="px-4">
                            {/* Date separator goes FIRST in DOM → appears at visual TOP of this group */}
                            <div className="flex items-center gap-3 mb-4 mt-2">
                                <div className="flex-1 h-px bg-border" />
                                <span className="text-[10px] font-medium text-muted-foreground bg-background px-2 select-none">{group.date}</span>
                                <div className="flex-1 h-px bg-border" />
                            </div>
                            {/* Messages in normal order within each group (oldest at top visually) */}
                            <div className="flex flex-col space-y-1 mb-2">
                                {group.messages.map((msg, idx) => (
                                    <div key={msg.id} ref={
                                        // Attach sentinel to the very last message of the newest group
                                        groupIdx === 0 && idx === group.messages.length - 1 && lastMessageRef
                                            ? lastMessageRef
                                            : undefined
                                    }>
                                        {renderMessage(msg, idx, group.messages)}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))
                )}

                {/* Load-older spinner appears at visual top (last DOM child in column-reverse) */}
                {isFetchingNextPage && (
                    <div className="flex justify-center py-2">
                        <LeafLogo className="h-4 w-4 animate-spin text-muted-foreground" />
                    </div>
                )}
            </div>

            {showScrollBtn && (
                <button
                    onClick={scrollToBottom}
                    className="absolute bottom-4 right-4 flex h-8 w-8 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg hover:opacity-90 z-10 transition-all opacity-100"
                >
                    <ArrowDown className="h-4 w-4" />
                </button>
            )}
        </div>
    )
}
