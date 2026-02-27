import { useMutation } from '@tanstack/react-query'
import { conversations } from '@/lib/api'
import { toast } from 'sonner'

export function useReaction() {
  return useMutation({
    mutationFn: ({ messageId, emoji, action }: { messageId: string; emoji: string; action: 'add' | 'remove' }) => {
      if (action === 'add') {
        return conversations.addReaction(messageId, emoji)
      } else {
        return conversations.removeReaction(messageId, emoji)
      }
    },
    onError: () => {
      toast.error('Failed to update reaction')
    },
  })
}
