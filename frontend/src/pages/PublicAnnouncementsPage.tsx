import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
  Megaphone,
  ThumbsUp, ThumbsDown, Clock, ChevronDown, ChevronUp,
  ArrowLeft, Shield, AlertTriangle, ExternalLink,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { cn, formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/empty-state'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { usePublicAnnouncements } from '@/hooks/useAnnouncements'
import { ANNOUNCEMENT_TYPE_CONFIG as TYPE_CONFIG, DEFAULTS } from '@/lib/constants'
import type { PublicAnnouncement } from '@/hooks/useAnnouncements'
import { useAppConfig } from '@/hooks/useConfig'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeSanitize from 'rehype-sanitize'

const inlineComponents = {
  p: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>
}

function getGradient(type: string) {
  switch (type) {
    case 'INFO': return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
    case 'WARNING': return 'hsl(38, 92%, 50%), hsl(45, 93%, 65%)'
    case 'IMPORTANT': return 'hsl(0, 72%, 51%), hsl(0, 84%, 65%)'
    default: return 'hsl(217, 91%, 60%), hsl(217, 91%, 75%)'
  }
}

function AuthorAvatar({ name }: { name: string }) {
  const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()
  return (
    <div className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/10 text-[9px] font-bold text-primary shrink-0">
      {initials}
    </div>
  )
}

function AnnouncementCard({
  announcement,
  onView,
}: {
  announcement: PublicAnnouncement
  onView: (id: string) => void
}) {
  const config = TYPE_CONFIG[announcement.type as keyof typeof TYPE_CONFIG]
  const Icon = config.icon
  const hasMedia = !!announcement.mediaAttachment
  const [expanded, setExpanded] = useState(false)
  const isLong = announcement.content.length > 200
  const authorName = announcement.author?.name ?? 'Admin'

  return (
    <div
      className={cn(
        'rounded-xl border overflow-hidden transition-all hover:shadow-lg bg-card cursor-pointer',
      )}
      onClick={() => onView(announcement.id)}
    >
      <div className="flex">
        {/* Gradient accent */}
        <div className="w-1 shrink-0" style={{
          background: `linear-gradient(to bottom, ${getGradient(announcement.type)})`,
        }} />

        <div className="flex-1 min-w-0">
          {/* Hero media */}
          {hasMedia && announcement.mediaAttachment && announcement.mediaAttachment.type === 'IMAGE' && (
            <div className="relative">
              <img
                src={announcement.mediaAttachment.cdnUrl}
                alt={announcement.mediaAttachment.filename}
                className="w-full h-44 object-cover"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />
              <div className="absolute bottom-3 left-4">
                <Badge variant="outline" className="text-[10px] bg-black/30 backdrop-blur-sm border-white/20 text-white">
                  {config.label}
                </Badge>
              </div>
            </div>
          )}

          <div className="p-4">
            {/* Header — no hero media */}
            {!hasMedia && (
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg', config.bg)}>
                  <Icon className={cn('h-4 w-4', config.color)} />
                </div>
                <Badge variant="outline" className={cn('text-[10px]', config.color, config.border)}>
                  {config.label}
                </Badge>
                <Badge variant="secondary" className="text-[10px] gap-1">
                  <Shield className="h-3 w-3" />
                  Public
                </Badge>
              </div>
            )}

            {/* Title */}
            <h3 className="text-sm font-bold leading-snug">
              {announcement.title}
            </h3>

            {/* Content */}
            <div className="mt-1.5">
              <div className={cn(
                'text-sm text-muted-foreground leading-relaxed prose prose-sm dark:prose-invert prose-p:my-0 prose-headings:my-0',
                !expanded && isLong && 'line-clamp-3',
              )}>
                <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]} components={inlineComponents}>
                  {announcement.content}
                </ReactMarkdown>
              </div>
              {isLong && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 mt-1 text-xs"
                  onClick={(e) => { e.stopPropagation(); setExpanded(!expanded) }}
                >
                  {expanded ? (
                    <><ChevronUp className="h-3 w-3 mr-1" /> Show less</>
                  ) : (
                    <><ChevronDown className="h-3 w-3 mr-1" /> Show more</>
                  )}
                </Button>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between mt-4 pt-3 border-t">
              {/* Votes (read-only for public) */}
              <div className="flex items-center gap-1">
                <span className="flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium text-muted-foreground bg-muted/50">
                  <ThumbsUp className="h-3.5 w-3.5" />
                  <span className="tabular-nums">{announcement.upvoteCount}</span>
                </span>
                <span className="flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium text-muted-foreground bg-muted/50">
                  <ThumbsDown className="h-3.5 w-3.5" />
                  <span className="tabular-nums">{announcement.downvoteCount}</span>
                </span>
              </div>

              {/* Meta */}
              <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1">
                  <AuthorAvatar name={authorName} />
                  {authorName}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatRelativeTime(announcement.createdAt)}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="rounded-xl border overflow-hidden">
          <Skeleton className="h-44 w-full" />
          <div className="p-4 space-y-2">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-32" />
          </div>
        </div>
      ))}
    </div>
  )
}

export function PublicAnnouncementsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { data: configData } = useAppConfig()
  const { data, isLoading, isError } = usePublicAnnouncements()

  const brand = configData?.brand
  const company = brand?.company || DEFAULTS.company

  const items = data?.announcements ?? []
  const infoCount = items.filter(a => a.type === 'INFO').length
  const warningCount = items.filter(a => a.type === 'WARNING').length
  const importantCount = items.filter(a => a.type === 'IMPORTANT').length

  return (
    <StaticLayout>
      <div className="mx-auto w-full max-w-3xl px-4 sm:px-6 py-8 sm:py-12">
        {/* Back button */}
        <Button
          variant="ghost"
          size="sm"
          className="mb-6 -ml-2 gap-1.5"
          onClick={() => navigate(-1)}
        >
          <ArrowLeft className="h-4 w-4" />
          Back
        </Button>

        {/* Page header */}
        <div className="flex items-start justify-between flex-wrap gap-4 mb-8">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
              <Megaphone className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight">Announcements</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Latest updates from {company}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {importantCount > 0 && (
              <Badge variant="destructive" className="text-[10px]">
                {importantCount} important
              </Badge>
            )}
            {warningCount > 0 && (
              <Badge className="text-[10px] bg-amber-500 hover:bg-amber-600">
                {warningCount} warning
              </Badge>
            )}
            {infoCount > 0 && (
              <Badge variant="outline" className="text-[10px] text-blue-600 border-blue-300">
                {infoCount} info
              </Badge>
            )}
          </div>
        </div>

        {/* Content */}
        {isLoading ? (
          <CardSkeleton />
        ) : isError ? (
          <div className="flex flex-col items-center justify-center gap-4 text-muted-foreground py-16">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-destructive/10">
              <AlertTriangle className="h-8 w-8 text-destructive/60" />
            </div>
            <div className="text-center">
              <p className="font-semibold text-foreground">Failed to load announcements</p>
              <p className="text-sm mt-1">There was an error loading the announcements.</p>
            </div>
            <Button variant="outline" className="gap-2 rounded-xl" onClick={() => { queryClient.invalidateQueries({ queryKey: ['announcements', 'public'] }) }}>
              Retry
            </Button>
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={Megaphone}
            title="No public announcements"
            subtitle="Check back later for updates from our team"
          />
        ) : (
          <div className="space-y-4 pb-8">
            {(items as PublicAnnouncement[]).map((ann) => (
              <AnnouncementCard key={ann.id} announcement={ann} />
            ))}
          </div>
        )}
      </div>
    </StaticLayout>
  )
}
