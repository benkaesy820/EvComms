import { create } from 'zustand'

export interface ReplyState {
    id: string
    content: string | null
    type: string
    sender: { name: string }
}

interface ChatState {
    replyTo: ReplyState | null
    setReplyTo: (reply: ReplyState | null) => void
    clearReply: () => void
}

export const useChatStore = create<ChatState>((set) => ({
    replyTo: null,
    setReplyTo: (reply) => set({ replyTo: reply }),
    clearReply: () => set({ replyTo: null }),
}))
