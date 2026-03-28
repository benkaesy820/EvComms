import { useState, useRef, useCallback, useEffect } from 'react'
import { Send, Paperclip, X, Image, FileText, Reply, Megaphone, Upload } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useAuthStore } from '@/stores/authStore'
import { getSocket } from '@/lib/socket'
import { media as mediaApi } from '@/lib/api'
import { toast } from '@/components/ui/sonner'
import { AttachmentPicker } from './AttachmentPicker'
import { cn } from '@/lib/utils'
import { useChatStore } from '@/stores/chatStore'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useAppConfig } from '@/hooks/useConfig'

const DEFAULT_MAX_TEXT_LENGTH = 5000

// Normalize message content before sending:
// - strip leading/trailing whitespace and newlines (same as trim)
// - collapse 3+ consecutive newlines down to 2 (one blank line max between paragraphs)
function sanitizeMessageContent(raw: string): string {
  return raw.trim().replace(/\n{3,}/g, '\n\n')
}

function getDraftKey(conversationId: string | undefined): string {
  return conversationId ? `draft:${conversationId}` : ''
}

function loadDraft(conversationId: string | undefined): string {
  if (!conversationId) return ''
  try {
    return localStorage.getItem(getDraftKey(conversationId)) || ''
  } catch {
    return ''
  }
}

function saveDraft(conversationId: string | undefined, text: string): void {
  if (!conversationId) return
  try {
    if (text.trim()) {
      localStorage.setItem(getDraftKey(conversationId), text)
    } else {
      localStorage.removeItem(getDraftKey(conversationId))
    }
  } catch {
    return
  }
}

const ALLOWED_TYPES: Record<string, string> = {
  'image/jpeg': 'IMAGE', 'image/png': 'IMAGE', 'image/gif': 'IMAGE', 'image/webp': 'IMAGE',
  'application/pdf': 'DOCUMENT',
  'application/msword': 'DOCUMENT',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOCUMENT',
  'application/vnd.ms-excel': 'DOCUMENT',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'DOCUMENT',
  'text/plain': 'DOCUMENT',
}

// dynamic max sizes will be read from config

function normalizeMimeType(mime: string): string {
  return mime.split(';')[0].trim()
}

function TypeIcon({ type }: { type: string }) {
  switch (type) {
    case 'IMAGE': return <Image className="h-4 w-4" />
    default: return <FileText className="h-4 w-4" />
  }
}

interface MessageInputProps {
  conversationId: string | undefined
  onSend: (data: { type: string; content?: string; mediaId?: string; media?: { id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null; replyToId?: string; announcementId?: string; subsidiaryId?: string }) => void
  disabled?: boolean
  linkedAnnouncement?: { id: string; title: string; type: string } | null
  onClearAnnouncement?: () => void
  onTyping?: (isTyping: boolean) => void
}

type PendingAttachment = {
  file?: File
  mediaId?: string
  type: string
  filename: string
  previewUrl?: string
}

export function MessageInput({ conversationId, onSend, disabled, linkedAnnouncement, onClearAnnouncement, onTyping }: MessageInputProps) {
  const user = useAuthStore((s) => s.user)
  const { replyTo, clearReply } = useChatStore()
  const [text, setText] = useState(() => loadDraft(conversationId))
  const [attachment, setAttachment] = useState<PendingAttachment | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [showAttachmentPicker, setShowAttachmentPicker] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputImageRef = useRef<HTMLInputElement>(null)
  const fileInputCameraRef = useRef<HTMLInputElement>(null)
  const fileInputDocRef = useRef<HTMLInputElement>(null)
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const typingHeartbeatRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const draftTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isTypingRef = useRef(false)
  const [isSending, setIsSending] = useState(false)

  const [isDragging, setIsDragging] = useState(false)

  useEffect(() => {
    setText(loadDraft(conversationId))
  }, [conversationId])

  // Auto-resize textarea to fit content, capped at max-h
  useEffect(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`
  }, [text])

  const { data: configData } = useAppConfig()

  const maxTextLength = conversationId === 'internal'
    ? (configData?.limits?.message?.teamTextMaxLength ?? DEFAULT_MAX_TEXT_LENGTH)
    : (configData?.limits?.message?.textMaxLength ?? DEFAULT_MAX_TEXT_LENGTH)

  const canAttach = configData?.features?.mediaUpload !== false && (user?.mediaPermission || user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN')

  const revokeObjectUrl = useCallback((url?: string) => {
    if (url && url.startsWith('blob:')) {
      URL.revokeObjectURL(url)
    }
  }, [])

  const setAttachmentWithCleanup = useCallback((next: PendingAttachment | null) => {
    setAttachment((prev) => {
      if (prev?.previewUrl && prev.previewUrl !== next?.previewUrl) {
        revokeObjectUrl(prev.previewUrl)
      }
      return next
    })
  }, [revokeObjectUrl])

  const clearAttachment = useCallback(() => {
    setAttachmentWithCleanup(null)
  }, [setAttachmentWithCleanup])

  useEffect(() => {
    return () => {
      if (attachment?.previewUrl) {
        revokeObjectUrl(attachment.previewUrl)
      }
    }
  }, [attachment?.previewUrl, revokeObjectUrl])

  // Upload function - must be defined before drag handlers that use it
  const uploadFile = useCallback(async (file: File | Blob, mimeType: string, filename: string): Promise<{ id: string; type: string; cdnUrl: string; filename: string; size: number; mimeType: string } | null> => {
    const normalizedMime = normalizeMimeType(mimeType)
    const mediaType = ALLOWED_TYPES[normalizedMime]
    if (!mediaType) {
      toast.error('File type not allowed')
      return null
    }

    let fileToUpload = file

    // Compress images before upload
    if (mediaType === 'IMAGE' && (normalizedMime === 'image/jpeg' || normalizedMime === 'image/png' || normalizedMime === 'image/webp')) {
      try {
        const imageCompression = (await import('browser-image-compression')).default
        const options = {
          maxSizeMB: 1, // Compress down to 1MB
          maxWidthOrHeight: 1920, // Max 1080p dimensions
          useWebWorker: true,
          fileType: normalizedMime,
        }
        fileToUpload = await imageCompression(file as File, options)
      } catch {
        // Compression failed — fall back to original file silently
      }
    }

    // Get dynamic max sizes from config, fallback to typical defaults if loading
    const defaultSizes = {
      IMAGE: 5242880,      // 5MB
      DOCUMENT: 10485760   // 10MB
    }
    const maxSize = configData?.limits?.media ? (
      mediaType === 'IMAGE' ? configData.limits.media.maxSizeImage :
        configData.limits.media.maxSizeDocument
    ) : defaultSizes[mediaType as keyof typeof defaultSizes] || defaultSizes.DOCUMENT

    if (fileToUpload.size > maxSize) {
      toast.error(`File too large. Maximum size: ${(maxSize / 1024 / 1024).toFixed(0)} MB`)
      return null
    }

    const result = await mediaApi.upload(fileToUpload, mediaType, filename, (pct) => setUploadProgress(pct))
    return result.media
  }, [configData?.limits?.media])

  // Emit typing:start only once when the user begins typing, not on every keystroke.
  // Reset the stop-timer on each keystroke — only emit typing:stop after 2s of silence.
  const emitTypingRaw = useCallback(
    (isTyping: boolean) => {
      if (onTyping) { onTyping(isTyping); return }
      if (!conversationId) return
      const socket = getSocket()
      if (socket?.connected) {
        socket.emit(isTyping ? 'typing:start' : 'typing:stop', { conversationId })
      }
    },
    [conversationId, onTyping],
  )

  const stopTyping = useCallback(() => {
    if (typingTimeoutRef.current) { clearTimeout(typingTimeoutRef.current); typingTimeoutRef.current = null }
    if (typingHeartbeatRef.current) { clearInterval(typingHeartbeatRef.current); typingHeartbeatRef.current = null }
    if (isTypingRef.current) {
      isTypingRef.current = false
      emitTypingRaw(false)
    }
  }, [emitTypingRaw])

  const handleTextChange = (value: string) => {
    const trimmed = value.slice(0, maxTextLength)
    setText(trimmed)
    // Debounce draft saves — writing to localStorage on every keystroke is wasteful
    if (draftTimerRef.current) clearTimeout(draftTimerRef.current)
    draftTimerRef.current = setTimeout(() => saveDraft(conversationId, trimmed), 500)

    // Only emit typing:start when transitioning from not-typing → typing
    if (!isTypingRef.current) {
      isTypingRef.current = true
      emitTypingRaw(true)
      // Heartbeat: re-emit typing:start every 3s so the receiver's fallback timer
      // keeps getting reset and the indicator never disappears mid-session.
      if (typingHeartbeatRef.current) clearInterval(typingHeartbeatRef.current)
      typingHeartbeatRef.current = setInterval(() => {
        if (isTypingRef.current) emitTypingRaw(true)
      }, 3000)
    }
    // Debounce: reset the stop-timer on every keystroke
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current)
    typingTimeoutRef.current = setTimeout(stopTyping, 2000)
  }

  useEffect(() => {
    return () => {
      stopTyping()
      if (draftTimerRef.current) clearTimeout(draftTimerRef.current)
    }
  // stopTyping is stable (useCallback with stable deps) — intentionally omitted
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Stop typing indicator immediately when the tab goes hidden — browser pauses
  // timers in background tabs, which would leave the admin seeing "typing…" indefinitely.
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) stopTyping()
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange)
  }, [stopTyping])
  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (!canAttach || uploading) return
    setIsDragging(true)
  }, [canAttach, uploading])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }, [])

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    if (!canAttach || uploading || disabled) return

    const files = Array.from(e.dataTransfer.files)
    if (files.length === 0) return

    const file = files[0]
    const mediaType = ALLOWED_TYPES[normalizeMimeType(file.type)]
    if (!mediaType) {
      toast.error('File type not allowed')
      return
    }

    let previewUrl: string | undefined
    if (mediaType === 'IMAGE') {
      previewUrl = URL.createObjectURL(file)
    }

    // All file types use deferred upload (stored in state, uploaded on send)
    setAttachmentWithCleanup({ file, type: mediaType, filename: file.name, previewUrl })
    toast.success(`${mediaType === 'IMAGE' ? 'Image' : 'File'} attached — send when ready`)
  }, [canAttach, uploading, disabled, setAttachmentWithCleanup])

  const handleSend = async () => {
    if (isSending || uploading || disabled) return
    const trimmed = sanitizeMessageContent(text)
    if (!trimmed && !attachment) return

    // Flush pending draft save immediately before clearing
    if (draftTimerRef.current) { clearTimeout(draftTimerRef.current); draftTimerRef.current = null }

    setIsSending(true)
    const replyToId = replyTo?.id

    if (attachment?.file) {
      setUploading(true)
      setUploadProgress(0)
      try {
        const uploadedMedia = await uploadFile(attachment.file, attachment.file.type, attachment.filename)

        if (uploadedMedia) {
          onSend({ type: attachment.type, content: trimmed || undefined, mediaId: uploadedMedia.id, media: uploadedMedia, replyToId, announcementId: linkedAnnouncement?.id })
          clearAttachment()
          clearReply()
          onClearAnnouncement?.()
          setText('')
          saveDraft(conversationId, '')
          stopTyping()
          textareaRef.current?.focus()
        }
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Upload failed')
      } finally {
        setUploading(false)
        setUploadProgress(0)
        setIsSending(false)
      }
      return
    }

    const announcementId = linkedAnnouncement?.id
    if (attachment?.mediaId) {
      onSend({ type: attachment.type, content: trimmed || undefined, mediaId: attachment.mediaId, replyToId, announcementId })
      clearAttachment()
    } else {
      onSend({ type: 'TEXT', content: trimmed, replyToId, announcementId })
    }

    clearReply()
    onClearAnnouncement?.()
    setText('')
    saveDraft(conversationId, '')
    stopTyping()
    textareaRef.current?.focus()

    // Release sending lock next tick after React reconciles
    setTimeout(() => setIsSending(false), 50)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''

    const mediaType = ALLOWED_TYPES[normalizeMimeType(file.type)]
    if (!mediaType) {
      toast.error('File type not allowed')
      return
    }

    let previewUrl: string | undefined
    if (mediaType === 'IMAGE') {
      previewUrl = URL.createObjectURL(file)
    }

    // All file types use deferred upload (stored in state, uploaded on send)
    setAttachmentWithCleanup({ file, type: mediaType, filename: file.name, previewUrl })
    toast.success(`${mediaType === 'IMAGE' ? 'Image' : 'File'} attached — send when ready`)
  }

  const hasContent = text.trim().length > 0 || !!attachment

  return (
    <div
      className="bg-sidebar px-4 py-3 shrink-0 relative border-t border-border/40 z-10"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {isDragging && (
        <div className="absolute inset-0 bg-primary/10 border-2 border-dashed border-primary rounded-lg z-50 flex flex-col items-center justify-center gap-2 animate-in fade-in duration-200">
          <Upload className="h-10 w-10 text-primary" />
          <span className="text-sm font-medium text-primary">Drop file to upload</span>
        </div>
      )}

      {linkedAnnouncement && (
        <div className="mb-2 flex items-center gap-2 rounded-lg border-l-2 border-primary/50 bg-primary/5 pl-3 pr-2 py-1.5">
          <Megaphone className="h-3.5 w-3.5 shrink-0 text-primary/60" />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-semibold text-primary/70 uppercase tracking-wider">Announcement</p>
            <p className="text-xs text-foreground truncate font-medium">{linkedAnnouncement.title}</p>
          </div>
          <button onClick={onClearAnnouncement} className="p-1.5 -mr-1 rounded-full text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors" aria-label="Remove announcement">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {replyTo && (
        <div className="mb-2 flex items-center gap-2 rounded-lg border-l-2 border-primary/50 bg-muted/40 pl-3 pr-2 py-1.5">
          <Reply className="h-3.5 w-3.5 shrink-0 text-primary/60" />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-semibold text-primary/70">{replyTo.sender.name}</p>
            <p className="text-xs text-muted-foreground truncate">
              {replyTo.content
                ? replyTo.content.slice(0, 60) + (replyTo.content.length > 60 ? '…' : '')
                : `[${replyTo.type.toLowerCase()}]`}
            </p>
          </div>
          <button
            onClick={clearReply}
            className="p-1.5 -mr-1 rounded-full text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
            aria-label="Cancel reply"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {uploading && (
        <div className="mb-2">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-muted-foreground">Uploading...</span>
            <span className="text-xs font-mono tabular-nums text-muted-foreground">{uploadProgress}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-primary transition-all duration-75"
              style={{ width: `${Math.max(5, uploadProgress)}%` }}
            />
          </div>
        </div>
      )}
      {attachment && (
        <div className="mb-2">
          {attachment.previewUrl && attachment.type === 'IMAGE' && (
            <div className="relative mb-2 rounded-md overflow-hidden max-h-40 max-w-xs">
              <img
                src={attachment.previewUrl}
                alt="Preview"
                className="w-full h-full object-contain"
              />
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-1 right-1 h-6 w-6 bg-black/50 hover:bg-black/70 text-white rounded-full"
                onClick={clearAttachment}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
          {(!attachment.previewUrl) && (
            <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-sm">
              <TypeIcon type={attachment.type} />
              <span className="truncate flex-1">{attachment.filename}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={clearAttachment}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Hidden file inputs — outside flex row so they don't create ghost flex items */}
      <input
        ref={fileInputImageRef}
        type="file"
        className="hidden"
        accept="image/*"
        onChange={handleFileSelect}
        aria-label="Select image file"
        id="file-input-image"
      />
      <input
        ref={fileInputCameraRef}
        type="file"
        className="hidden"
        accept="image/*"
        capture="environment"
        onChange={handleFileSelect}
        aria-label="Take photo with camera"
        id="file-input-camera"
      />
      <input
        ref={fileInputDocRef}
        type="file"
        className="hidden"
        accept=".pdf,.doc,.docx,.txt,.xls,.xlsx"
        onChange={handleFileSelect}
        aria-label="Select document file"
        id="file-input-document"
      />

      <div className="flex items-end gap-2 relative min-w-0">
        {canAttach && (
          <div className="relative">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-10 w-10 rounded-full shrink-0 text-muted-foreground hover:bg-black/5 dark:hover:bg-white/5"
                  onClick={() => setShowAttachmentPicker(!showAttachmentPicker)}
                  disabled={uploading || disabled}
                >
                  {uploading ? (
                    <LeafLogo className="h-4 w-4 animate-spin" />
                  ) : (
                    <Paperclip className="h-4 w-4" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Attach file</TooltipContent>
            </Tooltip>

            <AttachmentPicker
              isOpen={showAttachmentPicker}
              onClose={() => setShowAttachmentPicker(false)}
              onSelectImage={() => fileInputImageRef.current?.click()}
              onSelectCamera={() => fileInputCameraRef.current?.click()}
              onSelectDocument={() => fileInputDocRef.current?.click()}
            />
          </div>
        )}

        <div className="relative flex-1 min-w-0 overflow-hidden">
          <Textarea
            ref={textareaRef}
            value={text}
            onChange={(e) => handleTextChange(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message…"
            className="min-h-[44px] max-h-[120px] resize-none pr-14 pl-4 py-3 rounded-2xl bg-background border-transparent focus-visible:ring-0 shadow-sm transition-shadow text-[15px] overflow-y-auto overflow-x-hidden [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]"
            rows={1}
            disabled={disabled}
            enterKeyHint="send"
            inputMode="text"
          />
          {/* Only show character counter when user is near the limit (≥90%) to avoid clutter */}
          {text.length >= maxTextLength * 0.9 && (
            <div className={cn(
              'absolute bottom-1 right-2 text-[10px] tabular-nums',
              text.length >= maxTextLength ? 'text-destructive font-medium' : 'text-orange-500',
            )}>
              {text.length}/{maxTextLength}
            </div>
          )}
        </div>

        {hasContent ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                className="h-[44px] w-[44px] rounded-full shrink-0 shadow-sm transition-all"
                onClick={handleSend}
                disabled={(!text.trim() && !attachment) || disabled}
              >
                <Send className="h-5 w-5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Send message</TooltipContent>
          </Tooltip>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                className="h-[44px] w-[44px] rounded-full shrink-0 shadow-sm transition-all bg-muted text-muted-foreground hover:bg-muted"
                onClick={handleSend}
                disabled
              >
                <Send className="h-5 w-5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Send message</TooltipContent>
          </Tooltip>
        )}
      </div>
    </div>
  )
}
