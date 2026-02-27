import { LeafLogo } from '@/components/ui/LeafLogo'
import { useLayoutEffect, useRef, useState, useCallback, useMemo } from 'react'
import { ArrowDown, MessageCircle } from 'lucide-react'
import { format, isToday, isYesterday } from 'date-fns'
import { parseTimestamp, cn } from '@/lib/utils'

export interface MessageListProps<T> {
    messages: T[]
    isLoading?: boolean
    isFetchingNextPage?: boolean
    hasNextPage?: boolean
    fetchNextPage?: () => void
    renderMessage: (msg: T, index: number) => React.ReactNode

    getTimestamp: (msg: T) => number | string

    emptyState?: React.ReactNode
    bottomContent?: React.ReactNode

    className?: string

    // Optional dependency array to trigger scroll to bottom when things change
    scrollDependencies?: any[]
}

function formatDateLabel(ts: number | string) {
    const d = new Date(parseTimestamp(ts))
    if (isToday(d)) return 'Today'
    if (isYesterday(d)) return 'Yesterday'
    return format(d, 'MMMM d, yyyy')
}

export function MessageList<T>({
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
}: MessageListProps<T>) {
    const [showScrollBtn, setShowScrollBtn] = useState(false)
    const viewportRef = useRef<HTMLDivElement>(null)
    const getTimestampRef = useRef(getTimestamp)
    getTimestampRef.current = getTimestamp

    const sortedMessages = useMemo(() => {
        return [...messages].sort((a, b) => {
            const ts = getTimestampRef.current
            const ta = typeof ts(a) === 'number' ? ts(a) as number : parseTimestamp(ts(a)).getTime()
            const tb = typeof ts(b) === 'number' ? ts(b) as number : parseTimestamp(ts(b)).getTime()
            return ta - tb
        })
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [messages])

    // Group messages by date — oldest first
    const messageGroups = useMemo(() => {
        const groups: { date: string; messages: T[] }[] = []
        let currentDateLabel = ''
        for (const msg of sortedMessages) {
            const label = formatDateLabel(getTimestampRef.current(msg))
            if (label !== currentDateLabel) {
                currentDateLabel = label
                groups.push({ date: label, messages: [] })
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
                    [...messageGroups].reverse().map((group) => (
                        <div key={group.date} className="px-4">
                            {/* Messages in normal order within each group (oldest at top visually) */}
                            <div className="flex flex-col space-y-1">
                                {group.messages.map((msg, idx) => renderMessage(msg, idx))}
                            </div>
                            {/* Date separator goes LAST in DOM → appears at visual TOP of this group (column-reverse parent) */}
                            <div className="flex items-center gap-3 my-4">
                                <div className="flex-1 h-px bg-border" />
                                <span className="text-[10px] font-medium text-muted-foreground bg-background px-2 select-none">{group.date}</span>
                                <div className="flex-1 h-px bg-border" />
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
