import { useState, memo } from 'react'
import { ZoomIn, Play, FileText, Download } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Media } from '@/lib/schemas'

interface MediaGridProps {
  media: Media[]
  onMediaClick: (index: number) => void
}

const GRID_CLASSES: Record<number, string> = {
  1: 'col-span-full',
  2: 'col-span-1',
  4: 'col-span-1',
}

const HEIGHT_CLASSES: Record<number, string> = {
  1: 'max-h-64',
  2: 'h-48',
  4: 'h-32',
}

function getGridClass(index: number, total: number): string {
  const capped = Math.min(total, 4)
  if (capped === 3) return index === 0 ? 'col-span-2 row-span-2' : 'col-span-1'
  return GRID_CLASSES[capped] || 'col-span-1'
}

function getHeightClass(index: number, total: number): string {
  const capped = Math.min(total, 4)
  if (capped === 3) return index === 0 ? 'h-full min-h-[200px]' : 'h-24'
  return HEIGHT_CLASSES[capped] || 'h-32'
}

function MediaSkeleton() {
  return (
    <div className="w-full h-full min-h-[120px] rounded-xl bg-muted animate-pulse" />
  )
}

const ImageThumbnail = memo(function ImageThumbnail({
  media,
  index,
  total,
  onClick,
  isLast
}: {
  media: Media
  index: number
  total: number
  onClick: () => void
  isLast?: boolean
}) {
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState(false)

  if (error) {
    return (
      <div className={cn(
        'relative rounded-xl bg-muted flex items-center justify-center cursor-pointer overflow-hidden',
        getGridClass(index, total),
        getHeightClass(index, total)
      )} onClick={onClick}>
        <FileText className="h-8 w-8 text-muted-foreground" />
      </div>
    )
  }

  return (
    <div
      className={cn(
        'relative rounded-xl overflow-hidden cursor-pointer group',
        getGridClass(index, total),
        getHeightClass(index, total)
      )}
      onClick={onClick}
    >
      {!loaded && <MediaSkeleton />}
      <img
        key={media.cdnUrl}
        src={media.cdnUrl}
        alt={media.filename}
        className={cn(
          'w-full h-full object-cover transition-opacity duration-200',
          loaded ? 'opacity-100' : 'opacity-0',
          'group-hover:scale-105'
        )}
        loading="lazy"
        decoding="async"
        onLoad={() => setLoaded(true)}
        onError={() => setError(true)}
      />

      {/* Hover overlay */}
      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center pointer-events-none">
        <ZoomIn className="h-6 w-6 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>

      {/* More indicator for last item when > 4 images */}
      {isLast && total > 4 && (
        <div className="absolute inset-0 bg-black/60 flex items-center justify-center pointer-events-none">
          <span className="text-white text-2xl font-bold">+{total - 4}</span>
        </div>
      )}
    </div>
  )
})

const VideoThumbnail = memo(function VideoThumbnail({
  media,
  index,
  total,
  onClick
}: {
  media: Media
  index: number
  total: number
  onClick: () => void
}) {
  if (!media.cdnUrl) return null

  const ext = media.filename.split('.').pop()?.toUpperCase() ?? 'VIDEO'
  const sizeKb = media.size ? Math.round(media.size / 1024) : null
  const sizeLabel = sizeKb ? (sizeKb >= 1024 ? `${(sizeKb / 1024).toFixed(1)} MB` : `${sizeKb} KB`) : null

  return (
    <div
      className={cn(
        'relative rounded-xl overflow-hidden cursor-pointer group bg-zinc-900',
        getGridClass(index, total),
        getHeightClass(index, total)
      )}
      onClick={onClick}
    >
      {/* Static dark background — no video loaded */}
      <div className="absolute inset-0 bg-gradient-to-br from-zinc-800 to-zinc-950" />

      {/* Centered play button */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-white/15 backdrop-blur-sm ring-2 ring-white/20 group-hover:scale-110 group-hover:bg-white/25 transition-all">
          <Play className="h-6 w-6 text-white ml-0.5" fill="white" />
        </div>
      </div>

      {/* Bottom row — extension badge + file size */}
      <div className="absolute bottom-0 left-0 right-0 flex items-end justify-between px-3 py-2">
        <span className="text-[10px] font-bold text-zinc-300 bg-zinc-900/60 rounded px-1.5 py-0.5">
          {ext}
        </span>
        {sizeLabel && (
          <span className="text-[10px] text-zinc-400">{sizeLabel}</span>
        )}
      </div>
    </div>
  )
})


export const MediaGrid = memo(function MediaGrid({ media, onMediaClick }: MediaGridProps) {
  const images = media.filter(m => m.type === 'IMAGE')
  const videos = media.filter(m => m.type === 'VIDEO')
  const hasMixed = images.length > 0 && videos.length > 0

  if (hasMixed) {
    // Show all media in a grid
    return (
      <div className={cn(
        'grid gap-1.5 mb-2 max-w-sm',
        media.length === 1 ? 'grid-cols-1' :
          media.length === 2 ? 'grid-cols-2' :
            media.length === 3 ? 'grid-cols-2 grid-rows-2' :
              'grid-cols-2'
      )}>
        {media.slice(0, 4).map((m, i) => (
          m.type === 'IMAGE' ? (
            <ImageThumbnail
              key={m.id}
              media={m}
              index={i}
              total={media.length}
              onClick={() => onMediaClick(i)}
              isLast={i === 3 && media.length > 4}
            />
          ) : (
            <VideoThumbnail
              key={m.id}
              media={m}
              index={i}
              total={media.length}
              onClick={() => onMediaClick(i)}
            />
          )
        ))}
      </div>
    )
  }

  if (images.length > 0) {
    return (
      <div className={cn(
        'grid gap-1.5 mb-2 max-w-sm',
        images.length === 1 ? 'grid-cols-1' :
          images.length === 2 ? 'grid-cols-2' :
            images.length === 3 ? 'grid-cols-2 grid-rows-2' :
              'grid-cols-2'
      )}>
        {images.slice(0, 4).map((img, i) => (
          <ImageThumbnail
            key={img.id}
            media={img}
            index={i}
            total={images.length}
            onClick={() => onMediaClick(i)}
            isLast={i === 3 && images.length > 4}
          />
        ))}
      </div>
    )
  }

  if (videos.length > 0) {
    return (
      <div className={cn(
        'grid gap-1.5 mb-2 max-w-sm',
        videos.length === 1 ? 'grid-cols-1' :
          videos.length === 2 ? 'grid-cols-2' :
            videos.length === 3 ? 'grid-cols-2 grid-rows-2' :
              'grid-cols-2'
      )}>
        {videos.slice(0, 4).map((vid, i) => (
          <VideoThumbnail
            key={vid.id}
            media={vid}
            index={i}
            total={videos.length}
            onClick={() => onMediaClick(i)}
          />
        ))}
      </div>
    )
  }

  return null
})

interface DocumentPreviewProps {
  media: Media
  isMine: boolean
}

export const DocumentPreview = memo(function DocumentPreview({ media, isMine }: DocumentPreviewProps) {
  const isPDF = media.mimeType === 'application/pdf'
  const fileExt = media.filename.split('.').pop()?.toUpperCase() || 'FILE'
  const fileSize = media.size > 1024 * 1024
    ? `${(media.size / 1024 / 1024).toFixed(1)} MB`
    : `${(media.size / 1024).toFixed(0)} KB`

  return (
    <a
      href={media.cdnUrl}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        'flex items-center gap-3 rounded-xl px-4 py-3 mb-2 transition-all hover:scale-[1.02]',
        isMine
          ? 'bg-primary-foreground/10 hover:bg-primary-foreground/20'
          : 'bg-muted hover:bg-muted/80'
      )}
    >
      <div className={cn(
        'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
        isMine ? 'bg-primary-foreground/20' : 'bg-background'
      )}>
        {isPDF ? (
          <span className="text-xs font-bold text-red-500">PDF</span>
        ) : (
          <FileText className={cn(
            'h-5 w-5',
            isMine ? 'text-primary-foreground/70' : 'text-muted-foreground'
          )} />
        )}
      </div>

      <div className="flex-1 min-w-0">
        <p className={cn(
          'truncate font-medium text-sm',
          isMine ? 'text-primary-foreground' : 'text-foreground'
        )}>
          {media.filename}
        </p>
        <p className={cn(
          'text-[11px]',
          isMine ? 'text-primary-foreground/60' : 'text-muted-foreground'
        )}>
          {fileExt} • {fileSize}
        </p>
      </div>

      <Download className={cn(
        'h-4 w-4 shrink-0',
        isMine ? 'text-primary-foreground/60' : 'text-muted-foreground'
      )} />
    </a>
  )
})
