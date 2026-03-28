import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { announcementsApi } from '@/lib/api'
import type { Announcement, AnnouncementComment, AnnouncementType } from '@/lib/schemas'
import { toast } from '@/components/ui/sonner'

type AnnouncementsCache = { success: boolean; announcements: Announcement[]; hasMore: boolean }
type CommentsCache = { success: boolean; comments: AnnouncementComment[]; hasMore: boolean }

export function useAnnouncement(id: string | undefined) {
  return useQuery({
    queryKey: ['announcement', id],
    queryFn: () => announcementsApi.get(id!),
    enabled: !!id,
    staleTime: 0,
  })
}

export function useAnnouncements(includeInactive?: boolean, limit = 50) {
  return useQuery({
    queryKey: ['announcements', { includeInactive, limit }],
    queryFn: () => announcementsApi.list({ limit, includeInactive }),
    staleTime: 0,
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
    staleTime: 0,
  })
}

export function useAddComment(announcementId: string | undefined) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (content: string) => announcementsApi.addComment(announcementId!, content),
    onSuccess: (res) => {
      queryClient.setQueryData<CommentsCache>(
        ['announcement-comments', announcementId],
        (old) => {
          if (!old) return old
          // Socket may have already added this comment before the API response arrived
          const already = old.comments.some((c) => c.id === res.comment.id)
          if (already) return old
          return { ...old, comments: [...old.comments, res.comment] }
        }
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

// ── Real-Time Socket Hook ────────────────────────────────────────────────────

import { useEffect } from 'react'
import { getSocket } from '@/lib/socket'
import type { AnnouncementReaction } from '@/lib/schemas'

interface CommentPayload { announcementId: string; comment: { id: string; content: string; createdAt: Date; user: { id: string; name: string; role: string } } }
interface CommentDeletedPayload { announcementId: string; commentId: string }
interface ReactionUpdatedPayload { announcementId: string; userId: string; emoji: string }
interface ReactionRemovedPayload { announcementId: string; userId: string }
interface VoteUpdatedPayload { announcementId: string; upvoteCount: number; downvoteCount: number }

/**
 * Subscribes to live announcement socket events and patches React Query cache.
 * Call with no announcementId to handle events for ALL announcements (list page).
 * Call with a specific id to only handle events for that announcement (detail page).
 */
export function useAnnouncementSocket(announcementId?: string) {
  const queryClient = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return

    const matches = (id: string) => !announcementId || id === announcementId

    const onCommentNew = ({ announcementId: id, comment }: CommentPayload) => {
      if (!matches(id)) return
      queryClient.setQueryData<CommentsCache>(
        ['announcement-comments', id],
        (old) => {
          if (!old) return old
          // Deduplicate — the comment poster also receives the socket event,
          // so the comment may already be in the cache from the mutation's onSuccess.
          const already = old.comments.some((c) => c.id === (comment as unknown as AnnouncementComment).id)
          if (already) return old
          return { ...old, comments: [...old.comments, comment as unknown as AnnouncementComment] }
        }
      )
    }

    const onCommentDeleted = ({ announcementId: id, commentId }: CommentDeletedPayload) => {
      if (!matches(id)) return
      queryClient.setQueryData<CommentsCache>(
        ['announcement-comments', id],
        (old) => old ? { ...old, comments: old.comments.filter((c) => c.id !== commentId) } : old
      )
    }

    const onReactionUpdated = ({ announcementId: id, userId, emoji }: ReactionUpdatedPayload) => {
      if (!matches(id)) return
      const patch = (a: Announcement): Announcement => ({
        ...a,
        reactions: [
          ...(a.reactions ?? []).filter((r) => r.userId !== userId),
          { userId, emoji } as AnnouncementReaction,
        ],
      })
      queryClient.setQueryData<{ success: boolean; announcement: Announcement }>(
        ['announcement', id],
        (old) => old ? { ...old, announcement: patch(old.announcement) } : old
      )
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) =>
        old ? { ...old, announcements: old.announcements.map((a) => a.id === id ? patch(a) : a) } : old
      )
    }

    const onReactionRemoved = ({ announcementId: id, userId }: ReactionRemovedPayload) => {
      if (!matches(id)) return
      const patch = (a: Announcement): Announcement => ({
        ...a,
        reactions: (a.reactions ?? []).filter((r) => r.userId !== userId),
      })
      queryClient.setQueryData<{ success: boolean; announcement: Announcement }>(
        ['announcement', id],
        (old) => old ? { ...old, announcement: patch(old.announcement) } : old
      )
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) =>
        old ? { ...old, announcements: old.announcements.map((a) => a.id === id ? patch(a) : a) } : old
      )
    }

    const onVoteUpdated = ({ announcementId: id, upvoteCount, downvoteCount }: VoteUpdatedPayload) => {
      if (!matches(id)) return
      const patch = (a: Announcement): Announcement => ({ ...a, upvoteCount, downvoteCount })
      queryClient.setQueryData<{ success: boolean; announcement: Announcement }>(
        ['announcement', id],
        (old) => old ? { ...old, announcement: patch(old.announcement) } : old
      )
      queryClient.setQueriesData<AnnouncementsCache>({ queryKey: ['announcements'] }, (old) =>
        old ? { ...old, announcements: old.announcements.map((a) => a.id === id ? patch(a) : a) } : old
      )
    }

    socket.on('announcement:comment:new', onCommentNew)
    socket.on('announcement:comment:deleted', onCommentDeleted)
    socket.on('announcement:reaction:updated', onReactionUpdated)
    socket.on('announcement:reaction:added', onReactionUpdated) // same shape, same handler
    socket.on('announcement:reaction:removed', onReactionRemoved)
    socket.on('announcement:vote:updated', onVoteUpdated)

    return () => {
      socket.off('announcement:comment:new', onCommentNew)
      socket.off('announcement:comment:deleted', onCommentDeleted)
      socket.off('announcement:reaction:updated', onReactionUpdated)
      socket.off('announcement:reaction:added', onReactionUpdated)
      socket.off('announcement:reaction:removed', onReactionRemoved)
      socket.off('announcement:vote:updated', onVoteUpdated)
    }
  }, [announcementId, queryClient])
}

// ── Public Announcements (unauthenticated) ────────────────────────────────────

export interface PublicAnnouncement {
  id: string
  title: string
  content: string
  type: string
  template: string
  author: { name: string }
  upvoteCount: number
  downvoteCount: number
  createdAt: number
  mediaAttachment: { id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null
}

export function usePublicAnnouncements(limit = 50) {
  return useQuery({
    queryKey: ['announcements', 'public', { limit }],
    queryFn: () => announcementsApi.listPublic({ limit }),
    staleTime: 30_000,
  })
}

export function usePublicAnnouncement(id: string | undefined) {
  return useQuery({
    queryKey: ['announcement', 'public', id],
    queryFn: () => announcementsApi.getPublic(id!),
    enabled: !!id,
    staleTime: 30_000,
  })
}

