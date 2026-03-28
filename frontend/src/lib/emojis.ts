// Emoji data for the emoji picker — local JSON, no network dependency
// ~130 emojis organized by category

export interface EmojiEntry {
    emoji: string
    name: string
}

export interface EmojiCategory {
    id: string
    label: string
    icon: string
    emojis: EmojiEntry[]
}

export const EMOJI_CATEGORIES: EmojiCategory[] = [
    {
        id: 'common',
        label: 'Common',
        icon: '⭐',
        emojis: [
            { emoji: '👍', name: 'thumbs up' },
            { emoji: '❤️', name: 'heart' },
            { emoji: '😂', name: 'laughing' },
            { emoji: '😮', name: 'wow' },
            { emoji: '😢', name: 'crying' },
            { emoji: '🙏', name: 'pray' },
            { emoji: '🔥', name: 'fire' },
            { emoji: '✅', name: 'check' },
            { emoji: '👀', name: 'eyes' },
            { emoji: '💯', name: '100' },
            { emoji: '🎉', name: 'party' },
            { emoji: '💪', name: 'strong' },
        ],
    },
    {
        id: 'people',
        label: 'People',
        icon: '😀',
        emojis: [
            { emoji: '😀', name: 'grinning' },
            { emoji: '😃', name: 'smiley' },
            { emoji: '😄', name: 'smile' },
            { emoji: '😁', name: 'grin' },
            { emoji: '😆', name: 'laughing face' },
            { emoji: '😅', name: 'sweat smile' },
            { emoji: '🤣', name: 'rofl' },
            { emoji: '😊', name: 'blush' },
            { emoji: '😇', name: 'innocent' },
            { emoji: '🙂', name: 'slightly smiling' },
            { emoji: '😉', name: 'wink' },
            { emoji: '😌', name: 'relieved' },
            { emoji: '😍', name: 'heart eyes' },
            { emoji: '🥰', name: 'smiling with hearts' },
            { emoji: '😘', name: 'kissing heart' },
            { emoji: '😜', name: 'winking tongue' },
            { emoji: '🤔', name: 'thinking' },
            { emoji: '🤭', name: 'hand over mouth' },
            { emoji: '🤫', name: 'shushing' },
            { emoji: '🙄', name: 'eye roll' },
            { emoji: '😤', name: 'triumph' },
            { emoji: '😠', name: 'angry' },
            { emoji: '😡', name: 'rage' },
            { emoji: '🥺', name: 'pleading' },
            { emoji: '😞', name: 'disappointed' },
            { emoji: '😔', name: 'pensive' },
            { emoji: '😩', name: 'weary' },
            { emoji: '😭', name: 'loudly crying' },
            { emoji: '😱', name: 'screaming' },
            { emoji: '😎', name: 'cool' },
            { emoji: '🤓', name: 'nerd' },
            { emoji: '🥳', name: 'partying face' },
            { emoji: '🤩', name: 'star struck' },
            { emoji: '🤯', name: 'mind blown' },
            { emoji: '🥴', name: 'woozy' },
        ],
    },
    {
        id: 'hands',
        label: 'Gestures',
        icon: '👋',
        emojis: [
            { emoji: '👋', name: 'wave' },
            { emoji: '🤚', name: 'raised back of hand' },
            { emoji: '✋', name: 'raised hand' },
            { emoji: '🖐️', name: 'hand with fingers' },
            { emoji: '👌', name: 'ok hand' },
            { emoji: '🤌', name: 'pinched fingers' },
            { emoji: '✌️', name: 'victory hand' },
            { emoji: '🤞', name: 'crossed fingers' },
            { emoji: '🤟', name: 'love you gesture' },
            { emoji: '🤘', name: 'sign of the horns' },
            { emoji: '👈', name: 'point left' },
            { emoji: '👉', name: 'point right' },
            { emoji: '👆', name: 'point up' },
            { emoji: '👇', name: 'point down' },
            { emoji: '☝️', name: 'index pointing up' },
            { emoji: '👍', name: 'thumbs up' },
            { emoji: '👎', name: 'thumbs down' },
            { emoji: '✊', name: 'raised fist' },
            { emoji: '👊', name: 'oncoming fist' },
            { emoji: '🤛', name: 'left-facing fist' },
            { emoji: '🤜', name: 'right-facing fist' },
            { emoji: '👏', name: 'clapping' },
            { emoji: '🙌', name: 'raising hands' },
            { emoji: '👐', name: 'open hands' },
            { emoji: '🤲', name: 'palms together' },
            { emoji: '🤝', name: 'handshake' },
            { emoji: '🤙', name: 'call me hand' },
        ],
    },
    {
        id: 'nature',
        label: 'Nature',
        icon: '🌿',
        emojis: [
            { emoji: '🌸', name: 'cherry blossom' },
            { emoji: '🌺', name: 'hibiscus' },
            { emoji: '🌻', name: 'sunflower' },
            { emoji: '🌹', name: 'rose' },
            { emoji: '🌿', name: 'herb' },
            { emoji: '🍀', name: 'four leaf clover' },
            { emoji: '🍃', name: 'leaves' },
            { emoji: '🌈', name: 'rainbow' },
            { emoji: '☀️', name: 'sun' },
            { emoji: '🌙', name: 'moon' },
            { emoji: '⭐', name: 'star' },
            { emoji: '🌟', name: 'glowing star' },
            { emoji: '⚡', name: 'lightning' },
            { emoji: '🔥', name: 'fire' },
            { emoji: '❄️', name: 'snowflake' },
            { emoji: '🌊', name: 'wave' },
        ],
    },
    {
        id: 'food',
        label: 'Food',
        icon: '🍕',
        emojis: [
            { emoji: '🍕', name: 'pizza' },
            { emoji: '🍔', name: 'burger' },
            { emoji: '🍟', name: 'fries' },
            { emoji: '🌮', name: 'taco' },
            { emoji: '🍜', name: 'noodles' },
            { emoji: '🍣', name: 'sushi' },
            { emoji: '🍦', name: 'ice cream' },
            { emoji: '🎂', name: 'birthday cake' },
            { emoji: '☕', name: 'coffee' },
            { emoji: '🍺', name: 'beer' },
            { emoji: '🥂', name: 'champagne' },
            { emoji: '🍷', name: 'wine' },
        ],
    },
    {
        id: 'objects',
        label: 'Objects',
        icon: '💡',
        emojis: [
            { emoji: '💡', name: 'light bulb' },
            { emoji: '🔑', name: 'key' },
            { emoji: '🔒', name: 'lock' },
            { emoji: '📱', name: 'phone' },
            { emoji: '💻', name: 'laptop' },
            { emoji: '📧', name: 'email' },
            { emoji: '📝', name: 'memo' },
            { emoji: '📅', name: 'calendar' },
            { emoji: '⏰', name: 'alarm clock' },
            { emoji: '🔔', name: 'bell' },
            { emoji: '📢', name: 'loudspeaker' },
            { emoji: '🎯', name: 'target' },
            { emoji: '🏆', name: 'trophy' },
            { emoji: '🎁', name: 'gift' },
            { emoji: '💰', name: 'money bag' },
            { emoji: '📊', name: 'chart' },
        ],
    },
    {
        id: 'symbols',
        label: 'Symbols',
        icon: '💙',
        emojis: [
            { emoji: '❤️', name: 'red heart' },
            { emoji: '🧡', name: 'orange heart' },
            { emoji: '💛', name: 'yellow heart' },
            { emoji: '💚', name: 'green heart' },
            { emoji: '💙', name: 'blue heart' },
            { emoji: '💜', name: 'purple heart' },
            { emoji: '🖤', name: 'black heart' },
            { emoji: '🤍', name: 'white heart' },
            { emoji: '💔', name: 'broken heart' },
            { emoji: '❣️', name: 'heart exclamation' },
            { emoji: '💕', name: 'two hearts' },
            { emoji: '✅', name: 'check mark' },
            { emoji: '❌', name: 'cross mark' },
            { emoji: '⚠️', name: 'warning' },
            { emoji: '💯', name: '100' },
            { emoji: '🔴', name: 'red circle' },
            { emoji: '🟡', name: 'yellow circle' },
            { emoji: '🟢', name: 'green circle' },
        ],
    },
]

export const ALL_EMOJIS: EmojiEntry[] = EMOJI_CATEGORIES.flatMap((c) => c.emojis)

const RECENT_KEY = 'emoji_recent'
const MAX_RECENT = 16

export function getRecentEmojis(): string[] {
    try {
        return JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]')
    } catch {
        return []
    }
}

export function recordRecentEmoji(emoji: string): void {
    const recent = getRecentEmojis().filter((e) => e !== emoji)
    recent.unshift(emoji)
    localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, MAX_RECENT)))
}
