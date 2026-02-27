import { useRef, useEffect } from 'react'
import { Image, Camera, FileText, X } from 'lucide-react'
import { cn } from '@/lib/utils'

interface AttachmentPickerProps {
  isOpen: boolean
  onClose: () => void
  onSelectImage: () => void
  onSelectCamera: () => void
  onSelectDocument: () => void
}

const options = [
  { id: 'image', label: 'Gallery', icon: Image, color: 'bg-purple-500', hoverColor: 'hover:bg-purple-600' },
  { id: 'camera', label: 'Camera', icon: Camera, color: 'bg-red-500', hoverColor: 'hover:bg-red-600' },
  { id: 'document', label: 'Document', icon: FileText, color: 'bg-blue-500', hoverColor: 'hover:bg-blue-600' },
]

export function AttachmentPicker({
  isOpen,
  onClose,
  onSelectImage,
  onSelectCamera,
  onSelectDocument
}: AttachmentPickerProps) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(e: MouseEvent | TouchEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        onClose()
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      document.addEventListener('touchstart', handleClickOutside, { passive: true })
      return () => {
        document.removeEventListener('mousedown', handleClickOutside)
        document.removeEventListener('touchstart', handleClickOutside)
      }
    }
  }, [isOpen, onClose])

  if (!isOpen) return null

  const handleOptionClick = (id: string) => {
    switch (id) {
      case 'image':
        onSelectImage()
        break
      case 'camera':
        onSelectCamera()
        break
      case 'document':
        onSelectDocument()
        break
    }
    onClose()
  }

  return (
    <div
      ref={containerRef}
      className="absolute bottom-full left-0 mb-3 bg-card border rounded-2xl shadow-xl p-4 z-50 min-w-[280px] animate-in fade-in slide-in-from-bottom-2 duration-200"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-2 border-b border-border">
        <span className="text-sm font-semibold text-foreground">Attach</span>
        <button
          onClick={onClose}
          className="p-1.5 rounded-full hover:bg-muted transition-colors"
        >
          <X className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>

      {/* Options List */}
      <div className="flex flex-col gap-1">
        {options.map((option) => (
          <button
            key={option.id}
            onClick={() => handleOptionClick(option.id)}
            className="flex items-center gap-3 px-2 py-2.5 rounded-xl hover:bg-muted transition-colors group text-left w-full"
          >
            <div className={cn(
              'w-9 h-9 rounded-xl flex items-center justify-center text-white shadow-sm flex-shrink-0 transition-transform duration-200 group-hover:scale-105',
              option.color
            )}>
              <option.icon className="h-4 w-4" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
                {option.label}
              </span>
              <span className="text-[10px] text-muted-foreground">
                {option.id === 'image' && 'Photos & Videos'}
                {option.id === 'camera' && 'Take a photo'}
                {option.id === 'document' && 'Files & PDFs'}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}
