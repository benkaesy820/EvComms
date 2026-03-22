import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { conversations } from '@/lib/api'
import { toast } from '@/components/ui/sonner'

export function useArchiveConversation() {
  return useMutation({
    mutationFn: ({ conversationId, closingNote }: { conversationId: string; closingNote?: string }) =>
      conversations.archive(conversationId, closingNote),
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to archive conversation')
    },
  })
}

export function useUnarchiveConversation() {
  return useMutation({
    mutationFn: (conversationId: string) => conversations.unarchive(conversationId),
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to unarchive conversation')
    },
  })
}

export function useReopenConversation() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (conversationId: string) => conversations.reopen(conversationId),
    onSuccess: () => {
      // Refresh user's own conversation view
      queryClient.invalidateQueries({ queryKey: ['conversation'] })
      // Also refresh admin list in case an admin is looking
      queryClient.invalidateQueries({ queryKey: ['conversations'], type: 'all' })
      toast.success('Conversation reopened')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to reopen conversation')
    },
  })
}

export function useArchivedConversations(params?: { before?: string; limit?: number }) {
  return useQuery({
    queryKey: ['conversations', 'archived', params],
    queryFn: () => conversations.getArchived(params),
  })
}

