import { useState, useMemo, useEffect, useRef } from 'react'
import { Search, Clock } from 'lucide-react'
import { cn } from '@/lib/utils'
import { EMOJI_CATEGORIES, getRecentEmojis, recordRecentEmoji, type EmojiEntry } from '@/lib/emojis'

interface EmojiPickerProps {
    onSelect: (emoji: string) => void
    selectedEmojis?: string[]
    className?: string
}

export function EmojiPicker({ onSelect, selectedEmojis = [], className }: EmojiPickerProps) {
    const [query, setQuery] = useState('')
    const [activeCategory, setActiveCategory] = useState('recent')
    const [recentEmojis, setRecentEmojis] = useState<string[]>([])
    const searchRef = useRef<HTMLInputElement>(null)

    useEffect(() => {
        setRecentEmojis(getRecentEmojis())
        searchRef.current?.focus()
    }, [])

    const searchResults = useMemo<EmojiEntry[]>(() => {
        if (!query.trim()) return []
        const q = query.toLowerCase()
        return EMOJI_CATEGORIES.flatMap((c) =>
            c.emojis.filter((e) => e.name.includes(q) || e.emoji === q)
        )
    }, [query])

    const categoryToShow = query.trim() ? null : activeCategory

    const handleSelect = (emoji: string) => {
        recordRecentEmoji(emoji)
        setRecentEmojis(getRecentEmojis())
        onSelect(emoji)
    }

    const categories = [
        { id: 'recent', icon: <Clock className="h-3.5 w-3.5" />, label: 'Recent' },
        ...EMOJI_CATEGORIES.map((c) => ({ id: c.id, icon: <span className="text-sm">{c.icon}</span>, label: c.label })),
    ]

    const visibleEmojis: EmojiEntry[] = useMemo(() => {
        if (query.trim()) return searchResults
        if (activeCategory === 'recent') {
            return recentEmojis.map((emoji) => {
                const found = EMOJI_CATEGORIES.flatMap((c) => c.emojis).find((e) => e.emoji === emoji)
                return found ?? { emoji, name: emoji }
            })
        }
        return EMOJI_CATEGORIES.find((c) => c.id === activeCategory)?.emojis ?? []
    }, [query, searchResults, activeCategory, recentEmojis])

    return (
        <div className={cn('flex flex-col bg-popover rounded-xl border shadow-lg overflow-hidden w-72 max-w-[calc(100vw-1rem)]', className)}>
            {/* Search */}
            <div className="p-2 border-b">
                <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <input
                        ref={searchRef}
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search emojis..."
                        className="w-full pl-8 pr-3 h-8 text-sm bg-muted rounded-lg outline-none placeholder:text-muted-foreground"
                    />
                </div>
            </div>

            {/* Category tabs */}
            {!query.trim() && (
                <div className="flex border-b overflow-x-auto scrollbar-hide">
                    {categories.map((cat) => (
                        <button
                            key={cat.id}
                            onClick={() => setActiveCategory(cat.id)}
                            title={cat.label}
                            className={cn(
                                'flex shrink-0 items-center justify-center h-9 w-9 text-sm transition-colors',
                                activeCategory === cat.id
                                    ? 'bg-primary/10 text-primary'
                                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                            )}
                        >
                            {cat.icon}
                        </button>
                    ))}
                </div>
            )}

            {/* Emoji grid */}
            <div className="overflow-y-auto max-h-48 p-1.5 custom-scrollbar">
                {visibleEmojis.length === 0 ? (
                    <div className="flex items-center justify-center h-16 text-xs text-muted-foreground">
                        {query.trim() ? 'No emojis found' : 'No recent emojis yet'}
                    </div>
                ) : (
                    <div className="grid grid-cols-8 gap-0.5">
                        {visibleEmojis.map((entry) => (
                            <button
                                key={`${categoryToShow}-${entry.emoji}`}
                                onClick={() => handleSelect(entry.emoji)}
                                title={entry.name}
                                className={cn(
                                    'flex items-center justify-center h-8 w-8 rounded-lg text-lg transition-all hover:scale-110 hover:bg-accent',
                                    selectedEmojis.includes(entry.emoji) && 'bg-primary/15 ring-1 ring-primary/40'
                                )}
                            >
                                {entry.emoji}
                            </button>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}
