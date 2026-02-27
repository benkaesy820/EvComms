import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { announcementsApi } from '@/lib/api'
import type { Announcement, AnnouncementComment, AnnouncementType } from '@/lib/schemas'
import { toast } from 'sonner'

type AnnouncementsCache = { success: boolean; announcements: Announcement[]; hasMore: boolean }
type CommentsCache = { success: boolean; comments: AnnouncementComment[]; hasMore: boolean }

export function useAnnouncement(id: string | undefined) {
  return useQuery({
    queryKey: ['announcement', id],
    queryFn: () => announcementsApi.get(id!),
    enabled: !!id,
    staleTime: 60_000,
  })
}

export function useAnnouncements(includeInactive?: boolean, limit = 50) {
  return useQuery({
    queryKey: ['announcements', { includeInactive, limit }],
    queryFn: () => announcementsApi.list({ limit, includeInactive }),
    staleTime: 60_000,
  })
}

export function useCreateAnnouncement() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: {
      title: string
      content: string
      type?: AnnouncementType
      template?: 'DEFAULT' | 'BANNER' | 'CARD' | 'MINIMAL'
      mediaId?: string
      targetRoles?: string[]
      expiresAt?: string
    }) => announcementsApi.create(data),
    onSuccess: (res) => {
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) => {
        if (!old) return old
        return { ...old, announcements: [res.announcement, ...old.announcements] }
      })
      toast.success('Announcement published')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to create announcement')
    },
  })
}

export function useUpdateAnnouncement() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, ...data }: {
      id: string
      title?: string
      content?: string
      type?: AnnouncementType
      template?: 'DEFAULT' | 'BANNER' | 'CARD' | 'MINIMAL'
      mediaId?: string | null
      targetRoles?: string[] | null
      expiresAt?: string | null
      isActive?: boolean
    }) => announcementsApi.update(id, data),
    onSuccess: (res) => {
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) => {
        if (!old) return old
        return { ...old, announcements: old.announcements.map((a) => a.id === res.announcement.id ? res.announcement : a) }
      })
      queryClient.setQueryData<{ success: boolean; announcement: Announcement }>(
        ['announcement', res.announcement.id],
        (old) => old ? { ...old, announcement: res.announcement } : old
      )
      toast.success('Announcement updated')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to update announcement')
    },
  })
}

export function useVoteAnnouncement() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, vote }: { id: string; vote: 'UP' | 'DOWN' }) =>
      announcementsApi.vote(id, vote),
    onMutate: async ({ id, vote }) => {
      await queryClient.cancelQueries({ queryKey: ['announcements'] })

      const queries = queryClient.getQueriesData<{ success: boolean; announcements: Announcement[]; hasMore: boolean }>({
        queryKey: ['announcements'],
      })

      for (const [key, data] of queries) {
        if (!data) continue
        queryClient.setQueryData(key, {
          ...data,
          announcements: data.announcements.map((ann) => {
            if (ann.id !== id) return ann
            const wasUp = ann.userVote === 'UP'
            const wasDown = ann.userVote === 'DOWN'
            const isToggleOff = ann.userVote === vote

            return {
              ...ann,
              userVote: isToggleOff ? null : vote,
              upvoteCount: ann.upvoteCount
                + (vote === 'UP' && !isToggleOff ? 1 : 0)
                + (wasUp && (isToggleOff || vote === 'DOWN') ? -1 : 0),
              downvoteCount: ann.downvoteCount
                + (vote === 'DOWN' && !isToggleOff ? 1 : 0)
                + (wasDown && (isToggleOff || vote === 'UP') ? -1 : 0),
            }
          }),
        })
      }

      return { queries }
    },
    onError: (_err, _vars, context) => {
      if (context?.queries) {
        for (const [key, data] of context.queries) {
          queryClient.setQueryData(key, data)
        }
      }
      toast.error('Failed to vote')
    },
  })
}

export function useDeleteAnnouncement() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => announcementsApi.remove(id),
    onSuccess: (_, id) => {
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) => {
        if (!old) return old
        return { ...old, announcements: old.announcements.filter((a) => a.id !== id) }
      })
      queryClient.removeQueries({ queryKey: ['announcement', id] })
      toast.success('Announcement removed')
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : 'Failed to remove announcement')
    },
  })
}

// ── Reactions ────────────────────────────────────────────────────────────────

export function useAnnouncementReaction(announcementId: string | undefined) {
  const queryClient = useQueryClient()

  const patchReactions = (updater: (a: Announcement) => Announcement) => {
    queryClient.setQueryData<{ success: boolean; announcement: Announcement }>(
      ['announcement', announcementId],
      (old) => old ? { ...old, announcement: updater(old.announcement) } : old
    )
    queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) => {
      if (!old) return old
      return { ...old, announcements: old.announcements.map((a) => a.id === announcementId ? updater(a) : a) }
    })
  }

  const react = useMutation({
    mutationFn: (emoji: string) => announcementsApi.react(announcementId!, emoji),
    onSuccess: (res) => {
      patchReactions((a) => ({
        ...a,
        userReaction: res.reaction,
        reactions: res.reaction
          ? [...(a.reactions ?? []).filter((r) => r.userId !== res.reaction!.userId), res.reaction]
          : (a.reactions ?? []).filter((r) => r.userId !== a.userReaction?.userId),
      }))
    },
    onError: () => toast.error('Failed to add reaction'),
  })

  const remove = useMutation({
    mutationFn: () => announcementsApi.removeReaction(announcementId!),
    onSuccess: (_res, _vars, _ctx) => {
      patchReactions((a) => ({
        ...a,
        userReaction: null,
        reactions: (a.reactions ?? []).filter((r) => r.userId !== a.userReaction?.userId),
      }))
    },
    onError: () => toast.error('Failed to remove reaction'),
  })

  return { react, remove }
}

// ── Comments ─────────────────────────────────────────────────────────────────

export function useAnnouncementComments(announcementId: string | undefined) {
  return useQuery({
    queryKey: ['announcement-comments', announcementId],
    queryFn: () => announcementsApi.listComments(announcementId!, { limit: 30 }),
    enabled: !!announcementId,
    staleTime: 30_000,
  })
}

export function useAddComment(announcementId: string | undefined) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (content: string) => announcementsApi.addComment(announcementId!, content),
    onSuccess: (res) => {
      queryClient.setQueryData<CommentsCache>(
        ['announcement-comments', announcementId],
        (old) => old ? { ...old, comments: [...old.comments, res.comment] } : old
      )
    },
    onError: () => toast.error('Failed to add comment'),
  })
}

export function useDeleteComment(announcementId: string | undefined) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (commentId: string) => announcementsApi.deleteComment(announcementId!, commentId),
    onSuccess: (_, commentId) => {
      queryClient.setQueryData<CommentsCache>(
        ['announcement-comments', announcementId],
        (old) => old ? { ...old, comments: old.comments.filter((c) => c.id !== commentId) } : old
      )
    },
    onError: () => toast.error('Failed to delete comment'),
  })
}
