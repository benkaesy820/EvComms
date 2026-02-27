import { useState, useRef, useEffect, useCallback } from 'react'
import { X, ZoomIn, ZoomOut, Download, Play, Pause, Maximize2, Volume2, VolumeX, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface MediaViewerProps {
  src: string
  type: 'IMAGE' | 'VIDEO'
  filename: string
  onClose: () => void
}

export function MediaViewer({ src, type, filename, onClose }: MediaViewerProps) {
  const [zoom, setZoom] = useState(1)
  const [playing, setPlaying] = useState(false)
  const [muted, setMuted] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [imageLoaded, setImageLoaded] = useState(false)
  const videoRef = useRef<HTMLVideoElement>(null)
  const backdropRef = useRef<HTMLDivElement>(null)

  const togglePlay = useCallback(() => {
    if (!videoRef.current) return
    if (videoRef.current.paused) {
      videoRef.current.play()
      setPlaying(true)
    } else {
      videoRef.current.pause()
      setPlaying(false)
    }
  }, [])

  useEffect(() => {
    const videoEl = videoRef.current

    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (type === 'IMAGE') {
        if (e.key === '+' || e.key === '=') setZoom((z) => Math.min(z + 0.25, 5))
        if (e.key === '-') setZoom((z) => Math.max(z - 0.25, 0.25))
        if (e.key === '0') setZoom(1)
      }
      if (type === 'VIDEO' && e.key === ' ') {
        e.preventDefault()
        togglePlay()
      }
    }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
      videoEl?.pause()
    }
  }, [onClose, type, togglePlay])

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === backdropRef.current) onClose()
  }

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = Math.floor(s % 60)
    return `${m}:${sec.toString().padStart(2, '0')}`
  }

  const handleWheel = useCallback((e: React.WheelEvent) => {
    if (type !== 'IMAGE') return
    e.preventDefault()
    setZoom((z) => {
      const delta = e.deltaY > 0 ? -0.1 : 0.1
      return Math.max(0.25, Math.min(5, z + delta))
    })
  }, [type])

  return (
    <div
      ref={backdropRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={handleBackdropClick}
    >
      {/* Top bar */}
      <div className="absolute top-0 left-0 right-0 flex items-center justify-between p-4 z-10 bg-gradient-to-b from-black/50 to-transparent">
        <span className="text-sm text-white/80 truncate max-w-[60%]">{filename}</span>
        <div className="flex items-center gap-1">
          {type === 'IMAGE' && (
            <>
              <Button variant="ghost" size="icon" className="text-white hover:bg-white/10" onClick={() => setZoom((z) => Math.min(z + 0.25, 5))}>
                <ZoomIn className="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="icon" className="text-white hover:bg-white/10" onClick={() => setZoom((z) => Math.max(z - 0.25, 0.25))}>
                <ZoomOut className="h-4 w-4" />
              </Button>
              {zoom !== 1 && (
                <Button variant="ghost" size="icon" className="text-white hover:bg-white/10" onClick={() => setZoom(1)}>
                  <RotateCcw className="h-4 w-4" />
                </Button>
              )}
            </>
          )}
          <a href={src} download={filename} target="_blank" rel="noopener noreferrer">
            <Button variant="ghost" size="icon" className="text-white hover:bg-white/10">
              <Download className="h-4 w-4" />
            </Button>
          </a>
          <Button variant="ghost" size="icon" className="text-white hover:bg-white/10" onClick={onClose}>
            <X className="h-5 w-5" />
          </Button>
        </div>
      </div>

      {type === 'IMAGE' && (
        <div
          className="relative overflow-auto max-h-[85vh] max-w-[90vw] flex items-center justify-center"
          onWheel={handleWheel}
        >
          {!imageLoaded && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="h-8 w-8 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            </div>
          )}
          <img
            src={src}
            alt={filename}
            className="transition-transform duration-200 ease-out select-none max-h-[85vh]"
            style={{
              transform: `scale(${zoom})`,
              transformOrigin: 'center',
              opacity: imageLoaded ? 1 : 0,
            }}
            draggable={false}
            onLoad={() => setImageLoaded(true)}
            onDoubleClick={() => setZoom(zoom === 1 ? 2 : 1)}
          />
        </div>
      )}

      {type === 'VIDEO' && (
        <div className="flex flex-col items-center gap-4 w-full max-w-4xl px-4 justify-center h-full">
          <div className="relative w-full max-h-[75vh] md:max-h-[85vh] aspect-video bg-black rounded-lg overflow-hidden cursor-pointer" onClick={togglePlay}>
            <video
              ref={videoRef}
              src={src}
              className="w-full h-full object-contain"
              muted={muted}
              onTimeUpdate={() => setCurrentTime(videoRef.current?.currentTime ?? 0)}
              onLoadedMetadata={() => setDuration(videoRef.current?.duration ?? 0)}
              onEnded={() => setPlaying(false)}
              playsInline
            />
            {!playing && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/20 transition-colors">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-white/20 backdrop-blur-sm hover:bg-white/30 transition-colors">
                  <Play className="h-8 w-8 text-white ml-1" fill="white" />
                </div>
              </div>
            )}
          </div>

          {/* Video controls */}
          <div className="w-full flex items-center gap-3 px-2">
            <Button variant="ghost" size="icon" className="text-white hover:bg-white/10 shrink-0" onClick={togglePlay}>
              {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>

            <span className="text-xs text-white/70 tabular-nums w-10 shrink-0">{formatTime(currentTime)}</span>

            <input
              type="range"
              value={currentTime}
              max={duration || 1}
              step={0.1}
              onChange={(e) => {
                const v = parseFloat(e.target.value)
                if (videoRef.current) videoRef.current.currentTime = v
                setCurrentTime(v)
              }}
              className="flex-1 accent-white h-1 cursor-pointer"
            />

            <span className="text-xs text-white/70 tabular-nums w-10 shrink-0">{formatTime(duration)}</span>

            <Button variant="ghost" size="icon" className="text-white hover:bg-white/10 shrink-0" onClick={() => setMuted((m) => !m)}>
              {muted ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="text-white hover:bg-white/10 shrink-0"
              onClick={() => videoRef.current?.requestFullscreen?.()}
            >
              <Maximize2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
