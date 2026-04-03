/**
 * Shared message-cache mutators
 *
 * Single source of truth for updating the ['messages', conversationId]
 * React Query cache in response to socket events.
 *
 * Both the global useSocket hook and page-level handlers (ChatPage,
 * AdminChatView) previously duplicated this logic inline. Any divergence
 * between the copies caused subtle bugs where behaviour differed depending
 * on which page the user was on.
 *
 * Rules:
 *  - All functions are pure updaters — they NEVER call queryClient directly.
 *  - Callers pass the old cache value and receive the new value.
 *  - Page-level handlers call queryClient.setQueryData with these updaters.
 *  - The global hook also uses these for background-cache freshness.
 */

import type { Message, MessageReaction } from '@/lib/schemas'

export type MessagesCache = {
  pages: Array<{ success: boolean; messages: Message[]; hasMore: boolean }>
  pageParams: unknown[]
}

// ── prepend ───────────────────────────────────────────────────────────────────
/**
 * Prepend a new message to the first page, with deduplication.
 * Returns old if the message is already present.
 */
export function prependMessage(old: MessagesCache | undefined, message: Message): MessagesCache | undefined {
  if (!old || old.pages.length === 0) {
    return { pages: [{ success: true, messages: [message], hasMore: false }], pageParams: [undefined] }
  }
  const alreadyPresent = old.pages.some(p => p.messages.some(m => m.id === message.id))
  if (alreadyPresent) return old
  const [first, ...rest] = old.pages
  return { ...old, pages: [{ ...first, messages: [message, ...first.messages] }, ...rest] }
}

// ── replace temp ──────────────────────────────────────────────────────────────
/**
 * Replace an optimistic (temp) message with the server-confirmed version.
 * Deduplicates so message:new arriving before message:sent doesn't double-add.
 */
export function replaceTempMessage(
  old: MessagesCache | undefined,
  tempId: string,
  confirmed: Message,
): { cache: MessagesCache | undefined; found: boolean } {
  if (!old) return { cache: undefined, found: false }
  let found = false
  const seen = new Set<string>()
  const cache: MessagesCache = {
    ...old,
    pages: old.pages.map(p => ({
      ...p,
      messages: p.messages
        .map(m => {
          if (m.id === tempId) {
            found = true
            // Preserve optimistic media if server didn't echo it back yet (upload race)
            const media = confirmed.media ?? m.media
            return { ...confirmed, media }
          }
          return m
        })
        .filter(m => { if (seen.has(m.id)) return false; seen.add(m.id); return true }),
    })),
  }
  return { cache, found }
}

// ── soft-delete ───────────────────────────────────────────────────────────────
/**
 * Soft-delete a message (set deletedAt timestamp, keep it in the list).
 */
export function softDeleteMessage(
  old: MessagesCache | undefined,
  messageId: string,
  deletedAt: number,
): MessagesCache | undefined {
  if (!old) return old
  return {
    ...old,
    pages: old.pages.map(p => ({
      ...p,
      messages: p.messages.map(m => (m.id === messageId ? { ...m, deletedAt } : m)),
    })),
  }
}

// ── mark read ─────────────────────────────────────────────────────────────────
/**
 * Mark messages as read.
 * Adds readBy to the per-message array and flips status → READ.
 * readBy is optional — the global hook uses this without tracking individual readers;
 * page-level handlers pass the specific reader's userId.
 */
export function markMessagesRead(
  old: MessagesCache | undefined,
  readAt: number,
): MessagesCache | undefined {
  if (!old) return old
  return {
    ...old,
    pages: old.pages.map(p => ({
      ...p,
      messages: p.messages.map(m => {
        if (m.status !== 'SENT' && m.status !== undefined) return m
        return { ...m, status: 'READ' as const, readAt }
      }),
    })),
  }
}

// ── reaction ──────────────────────────────────────────────────────────────────
type ReactionLike = { userId: string; emoji: string }

/**
 * Add or remove a reaction on a specific message.
 */
export function applyReaction(
  old: MessagesCache | undefined,
  messageId: string,
  reaction: MessageReaction | ReactionLike,
  action: 'add' | 'remove',
): MessagesCache | undefined {
  if (!old) return old
  return {
    ...old,
    pages: old.pages.map(p => ({
      ...p,
      messages: p.messages.map(m => {
        if (m.id !== messageId) return m
        const reactions = m.reactions ? [...m.reactions] : []
        if (action === 'remove') {
          return {
            ...m,
            reactions: reactions.filter(
              x => !(x.userId === reaction.userId && x.emoji === reaction.emoji),
            ),
          }
        }
        const full = reaction as MessageReaction
        // Deduplicate by id when available, otherwise by userId+emoji
        const alreadyThere = full.id
          ? reactions.some(x => x.id === full.id)
          : reactions.some(x => x.userId === full.userId && x.emoji === full.emoji)
        return { ...m, reactions: alreadyThere ? reactions : [...reactions, full] }
      }),
    })),
  }
}
