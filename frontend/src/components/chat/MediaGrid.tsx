import { useState, memo } from 'react'
import { ZoomIn, FileText, Download } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Media } from '@/lib/schemas'

interface MediaGridProps {
  media: Media[]
  onMediaClick: (index: number) => void
}

const GRID_CLASSES: Record<number, string> = { 1: 'col-span-full', 2: 'col-span-1', 4: 'col-span-1' }
const HEIGHT_CLASSES: Record<number, string> = { 1: 'max-h-64', 2: 'h-48', 4: 'h-32' }

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

const ImageThumbnail = memo(function ImageThumbnail({ media, index, total, onClick, isLast }: {
  media: Media; index: number; total: number; onClick: () => void; isLast?: boolean
}) {
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState(false)

  if (error) {
    return (
      <div className={cn('relative rounded-xl bg-muted flex items-center justify-center cursor-pointer overflow-hidden',
        getGridClass(index, total), getHeightClass(index, total))} onClick={onClick}>
        <FileText className="h-8 w-8 text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className={cn('relative rounded-xl overflow-hidden cursor-pointer group',
      getGridClass(index, total), getHeightClass(index, total))} onClick={onClick}>
      {!loaded && <div className="w-full h-full min-h-[120px] rounded-xl bg-muted animate-pulse" />}
      <img key={media.cdnUrl} src={media.cdnUrl} alt={media.filename}
        className={cn('w-full h-full object-cover transition-opacity duration-200',
          loaded ? 'opacity-100' : 'opacity-0', 'group-hover:scale-105')}
        loading="lazy" decoding="async"
        onLoad={() => setLoaded(true)} onError={() => setError(true)} />
      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center pointer-events-none">
        <ZoomIn className="h-6 w-6 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
      {isLast && total > 4 && (
        <div className="absolute inset-0 bg-black/60 flex items-center justify-center pointer-events-none">
          <span className="text-white text-2xl font-bold">+{total - 4}</span>
        </div>
      )}
    </div>
  )
})

export const MediaGrid = memo(function MediaGrid({ media, onMediaClick }: MediaGridProps) {
  const images = media.filter(m => m.type === 'IMAGE')
  if (images.length === 0) return null

  return (
    <div className={cn('grid gap-1.5 mb-2 max-w-sm',
      images.length === 1 ? 'grid-cols-1' :
      images.length === 2 ? 'grid-cols-2' :
      images.length === 3 ? 'grid-cols-2 grid-rows-2' : 'grid-cols-2')}>
      {images.slice(0, 4).map((img, i) => (
        <ImageThumbnail key={img.id} media={img} index={i} total={images.length}
          onClick={() => onMediaClick(i)} isLast={i === 3 && images.length > 4} />
      ))}
    </div>
  )
})

interface DocumentPreviewProps { media: Media; isMine: boolean }

export const DocumentPreview = memo(function DocumentPreview({ media, isMine }: DocumentPreviewProps) {
  const isPDF = media.mimeType === 'application/pdf'
  const fileExt = media.filename.split('.').pop()?.toUpperCase() || 'FILE'
  const fileSize = media.size > 1024 * 1024
    ? `${(media.size / 1024 / 1024).toFixed(1)} MB`
    : `${(media.size / 1024).toFixed(0)} KB`

  return (
    <a href={media.cdnUrl} target="_blank" rel="noopener noreferrer"
      className={cn('flex items-center gap-3 rounded-xl px-4 py-3 mb-2 transition-all hover:scale-[1.02]',
        isMine ? 'bg-primary-foreground/10 hover:bg-primary-foreground/20' : 'bg-muted hover:bg-muted/80')}>
      <div className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
        isMine ? 'bg-primary-foreground/20' : 'bg-background')}>
        {isPDF ? <span className="text-xs font-bold text-red-500">PDF</span>
          : <FileText className={cn('h-5 w-5', isMine ? 'text-primary-foreground/70' : 'text-muted-foreground')} />}
      </div>
      <div className="flex-1 min-w-0">
        <p className={cn('truncate font-medium text-sm', isMine ? 'text-primary-foreground' : 'text-foreground')}>
          {media.filename}
        </p>
        <p className={cn('text-[11px]', isMine ? 'text-primary-foreground/60' : 'text-muted-foreground')}>
          {fileExt} • {fileSize}
        </p>
      </div>
      <Download className={cn('h-4 w-4 shrink-0', isMine ? 'text-primary-foreground/60' : 'text-muted-foreground')} />
    </a>
  )
})
