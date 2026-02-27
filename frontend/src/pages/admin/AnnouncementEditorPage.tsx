import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Megaphone, ArrowLeft, Image, X,
  Users, Calendar, Eye, EyeOff, Upload,
  Bold, Italic, List, ListOrdered, Link2, Crop, Sparkles,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip'
import { cn, parseTimestamp } from '@/lib/utils'
import { useAnnouncement, useCreateAnnouncement, useUpdateAnnouncement } from '@/hooks/useAnnouncements'
import { media as mediaApi } from '@/lib/api'
import { format } from 'date-fns'
import type { AnnouncementType, AnnouncementTemplate } from '@/lib/schemas'
import { toast } from 'sonner'
import { ANNOUNCEMENT_TYPE_CONFIG as TYPE_CONFIG } from '@/lib/constants'
import { ImageEditor } from '@/components/ui/image-editor'
import { LeafLogo } from '@/components/ui/LeafLogo'

const TEMPLATES: { value: AnnouncementTemplate; label: string; description: string; icon: string }[] = [
  { value: 'DEFAULT', label: 'Default', description: 'Icon + bordered card', icon: '📋' },
  { value: 'BANNER', label: 'Banner', description: 'Full-width prominent strip', icon: '🏷️' },
  { value: 'CARD', label: 'Card', description: 'Elevated card with shadow', icon: '🃏' },
  { value: 'MINIMAL', label: 'Minimal', description: 'Clean and text-focused', icon: '✏️' },
]

// --- Formatting Toolbar Helpers ---
function insertMarkdown(
  textarea: HTMLTextAreaElement,
  prefix: string,
  suffix: string,
  setText: (fn: (prev: string) => string) => void,
) {
  const start = textarea.selectionStart
  const end = textarea.selectionEnd
  const selected = textarea.value.substring(start, end)
  const replacement = `${prefix}${selected || 'text'}${suffix}`

  setText(prev => prev.substring(0, start) + replacement + prev.substring(end))
  requestAnimationFrame(() => {
    textarea.focus()
    const newCursor = start + prefix.length + (selected ? selected.length : 4)
    textarea.setSelectionRange(newCursor, newCursor)
  })
}

function insertListItem(
  textarea: HTMLTextAreaElement,
  bullet: string,
  setText: (fn: (prev: string) => string) => void,
) {
  const start = textarea.selectionStart
  const beforeCursor = textarea.value.substring(0, start)
  const isStartOfLine = start === 0 || beforeCursor.endsWith('\n')
  const prefix = isStartOfLine ? `${bullet} ` : `\n${bullet} `

  setText(prev => prev.substring(0, start) + prefix + prev.substring(start))
  requestAnimationFrame(() => {
    textarea.focus()
    const newPos = start + prefix.length
    textarea.setSelectionRange(newPos, newPos)
  })
}

// --- Template Preview ---
function TemplatePreview({ type, template, title, content, mediaUrl }: {
  type: AnnouncementType; template: AnnouncementTemplate; title: string; content: string; mediaUrl?: string
}) {
  const cfg = TYPE_CONFIG[type]
  const Icon = cfg.icon
  const displayTitle = title || 'Untitled Announcement'
  const displayContent = content || 'Your announcement content will appear here...'

  if (template === 'BANNER') {
    return (
      <div className="space-y-0">
        {mediaUrl && <img src={mediaUrl} alt="" className="w-full h-32 object-cover" />}
        <div className={cn('p-4 flex items-center gap-4 w-full', cfg.bg, `border-y ${cfg.border}`)}>
          <Icon className={cn('h-5 w-5 shrink-0', cfg.color)} />
          <div className="flex-1 min-w-0">
            <p className={cn('text-sm font-bold', cfg.color)}>{displayTitle}</p>
            {content && <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{displayContent}</p>}
          </div>
          <Badge variant="outline" className={cn('shrink-0 text-[10px]', cfg.color, cfg.border)}>{cfg.label}</Badge>
        </div>
      </div>
    )
  }

  if (template === 'CARD') {
    return (
      <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
        {mediaUrl && <img src={mediaUrl} alt="" className="w-full h-36 object-cover" />}
        <div className="p-5 space-y-3">
          <div className="flex items-center gap-3">
            <div className={cn('flex h-10 w-10 items-center justify-center rounded-xl', cfg.bg)}>
              <Icon className={cn('h-5 w-5', cfg.color)} />
            </div>
            <div>
              <p className="text-sm font-bold">{displayTitle}</p>
              <Badge variant="outline" className={cn('text-[10px] mt-0.5', cfg.color, cfg.border)}>{cfg.label}</Badge>
            </div>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed line-clamp-4">{displayContent}</p>
        </div>
      </div>
    )
  }

  if (template === 'MINIMAL') {
    return (
      <div className="space-y-2">
        {mediaUrl && <img src={mediaUrl} alt="" className="w-full h-32 object-cover rounded-lg" />}
        <div className="border-l-2 border-muted-foreground/30 pl-4 py-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{cfg.label}</p>
          <p className="text-sm font-medium mt-1">{displayTitle}</p>
          {content && <p className="text-xs text-muted-foreground mt-0.5 line-clamp-3">{displayContent}</p>}
        </div>
      </div>
    )
  }

  // DEFAULT
  return (
    <div className={cn('rounded-xl border overflow-hidden', cfg.bg, cfg.border)}>
      {mediaUrl && <img src={mediaUrl} alt="" className="w-full h-36 object-cover" />}
      <div className="p-4 flex items-start gap-3">
        <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg', cfg.bg)}>
          <Icon className={cn('h-4 w-4', cfg.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-semibold">{displayTitle}</p>
            <Badge variant="outline" className={cn('text-[10px]', cfg.color, cfg.border)}>{cfg.label}</Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1 leading-relaxed line-clamp-4">{displayContent}</p>
        </div>
      </div>
    </div>
  )
}

// --- Main Editor ---
export function AnnouncementEditorPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id?: string }>()
  const isEdit = !!id

  const { data: existingData } = useAnnouncement(isEdit ? id : undefined)
  const existing = existingData?.announcement ?? undefined

  const createAnnouncement = useCreateAnnouncement()
  const updateAnnouncement = useUpdateAnnouncement()

  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [type, setType] = useState<AnnouncementType>('INFO')
  const [template, setTemplate] = useState<AnnouncementTemplate>('DEFAULT')
  const [targetAll, setTargetAll] = useState(true)
  const [targetUser, setTargetUser] = useState(false)
  const [targetAdmin, setTargetAdmin] = useState(false)
  const [targetSuper, setTargetSuper] = useState(false)
  const [expiresAt, setExpiresAt] = useState('')
  const [isActive, setIsActive] = useState(true)
  const [mediaPreview, setMediaPreview] = useState<{ id: string; url: string; filename: string } | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isDragging, setIsDragging] = useState(false)
  const [showPreview, setShowPreview] = useState(true)
  const [imageEditorSrc, setImageEditorSrc] = useState<string | null>(null)
  const [imageEditorFilename, setImageEditorFilename] = useState('image.jpg')

  const fileRef = useRef<HTMLInputElement>(null)
  const contentRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (existing) {
      setTitle(existing.title)
      setContent(existing.content)
      setType(existing.type)
      setTemplate(existing.template)
      setIsActive(existing.isActive)
      const roles = existing.targetRoles
      if (!roles || roles.length === 0) {
        setTargetAll(true)
      } else {
        setTargetAll(false)
        setTargetUser(roles.includes('USER'))
        setTargetAdmin(roles.includes('ADMIN'))
        setTargetSuper(roles.includes('SUPER_ADMIN'))
      }
      if (existing.expiresAt) {
        const d = new Date(parseTimestamp(existing.expiresAt))
        setExpiresAt(format(d, "yyyy-MM-dd'T'HH:mm"))
      }
      if (existing.mediaAttachment) {
        setMediaPreview({ id: existing.mediaAttachment.id, url: existing.mediaAttachment.cdnUrl, filename: existing.mediaAttachment.filename })
      }
    }
  }, [existing])

  const handleFileUpload = async (file: File) => {
    setUploading(true)
    setUploadProgress(0)
    try {
      const result = await mediaApi.upload(file, 'IMAGE', file.name, (pct) => setUploadProgress(pct))
      if (result.success && result.media) {
        setMediaPreview({ id: result.media.id, url: result.media.cdnUrl, filename: result.media.filename })
      }
    } catch {
      toast.error('Failed to upload image')
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFileUpload(file)
    e.target.value = ''
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation(); setIsDragging(false)
    if (uploading) return
    const file = e.dataTransfer.files[0]
    if (file && file.type.startsWith('image/')) handleFileUpload(file)
  }, [uploading])

  const openImageEditor = () => {
    if (mediaPreview) {
      setImageEditorSrc(mediaPreview.url)
      setImageEditorFilename(mediaPreview.filename)
    }
  }

  const handleImageEditorSave = async (blob: Blob, filename: string) => {
    setImageEditorSrc(null)
    const file = new File([blob], filename, { type: 'image/jpeg' })
    await handleFileUpload(file)
  }

  const handlePublish = () => {
    const targetRoles: string[] = []
    if (!targetAll) {
      if (targetUser) targetRoles.push('USER')
      if (targetAdmin) targetRoles.push('ADMIN')
      if (targetSuper) targetRoles.push('SUPER_ADMIN')
    }

    const payload = {
      title,
      content,
      type,
      template,
      mediaId: mediaPreview?.id,
      targetRoles: targetRoles.length > 0 ? targetRoles : undefined,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
    }

    if (isEdit && id) {
      updateAnnouncement.mutate(
        { id, ...payload, isActive, targetRoles: targetRoles.length > 0 ? targetRoles : null },
        { onSuccess: () => navigate('/admin/announcements') }
      )
    } else {
      createAnnouncement.mutate(payload, { onSuccess: () => navigate('/admin/announcements') })
    }
  }

  const isPending = createAnnouncement.isPending || updateAnnouncement.isPending
  const isValid = title.trim().length > 0 && content.trim().length > 0

  const wordCount = useMemo(() => { const t = content.trim(); return t ? t.split(/\s+/).length : 0 }, [content])

  // Formatting toolbar actions
  const fmt = {
    bold: () => contentRef.current && insertMarkdown(contentRef.current, '**', '**', setContent),
    italic: () => contentRef.current && insertMarkdown(contentRef.current, '*', '*', setContent),
    link: () => contentRef.current && insertMarkdown(contentRef.current, '[', '](url)', setContent),
    ul: () => contentRef.current && insertListItem(contentRef.current, '•', setContent),
    ol: () => contentRef.current && insertListItem(contentRef.current, '1.', setContent),
  }

  const handleContentKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.ctrlKey || e.metaKey) {
      if (e.key === 'b') { e.preventDefault(); fmt.bold() }
      if (e.key === 'i') { e.preventDefault(); fmt.italic() }
      if (e.key === 'k') { e.preventDefault(); fmt.link() }
    }
  }

  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex h-full flex-col">
        {/* Header */}
        <div className="flex items-center gap-3 border-b px-4 py-2.5 shrink-0 bg-background">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => navigate('/admin/announcements')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 shrink-0">
              <Megaphone className="h-4 w-4 text-primary" />
            </div>
            <div>
              <span className="font-semibold text-sm">{isEdit ? 'Edit Announcement' : 'New Announcement'}</span>
              {isEdit && <span className="text-[10px] text-muted-foreground ml-2">Editing draft</span>}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button variant="ghost" size="sm" className="gap-1.5 text-xs hidden md:flex" onClick={() => setShowPreview(p => !p)}>
              {showPreview ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              {showPreview ? 'Hide' : 'Preview'}
            </Button>
            <Button size="sm" className="gap-1.5 rounded-xl px-5" onClick={handlePublish} disabled={!isValid || isPending}>
              {isPending ? <LeafLogo className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
              {isEdit ? 'Save' : 'Publish'}
            </Button>
          </div>
        </div>

        <div className="flex flex-1 overflow-hidden">
          {/* Editor Panel */}
          <div className="flex-1 overflow-y-auto min-w-0">
            <Tabs defaultValue="content" className="h-full flex flex-col">
              <div className="border-b px-4 shrink-0">
                <TabsList className="h-10 bg-transparent gap-4 px-0">
                  <TabsTrigger value="content" className="text-xs data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-1 pb-2.5">
                    Content
                  </TabsTrigger>
                  <TabsTrigger value="settings" className="text-xs data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-1 pb-2.5">
                    Settings
                  </TabsTrigger>
                </TabsList>
              </div>

              {/* Content Tab */}
              <TabsContent value="content" className="flex-1 overflow-y-auto mt-0 p-5 space-y-5">
                {/* Title */}
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Title</Label>
                  <Input
                    value={title}
                    onChange={e => setTitle(e.target.value)}
                    placeholder="Give your announcement a clear, attention-grabbing title…"
                    maxLength={200}
                    className="text-lg font-semibold rounded-xl h-12 border-dashed focus:border-solid"
                  />
                  <p className="text-[10px] text-muted-foreground text-right tabular-nums">{title.length}/200</p>
                </div>

                {/* Content with toolbar */}
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Content</Label>
                  <div className="rounded-xl border focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-1 overflow-hidden">
                    {/* Formatting Toolbar */}
                    <div className="flex items-center gap-0.5 px-2 py-1.5 bg-muted/50 border-b">
                      {[
                        { icon: Bold, action: fmt.bold, label: 'Bold (Ctrl+B)' },
                        { icon: Italic, action: fmt.italic, label: 'Italic (Ctrl+I)' },
                        { icon: Link2, action: fmt.link, label: 'Link (Ctrl+K)' },
                        { icon: List, action: fmt.ul, label: 'Bullet list' },
                        { icon: ListOrdered, action: fmt.ol, label: 'Numbered list' },
                      ].map(btn => (
                        <Tooltip key={btn.label}>
                          <TooltipTrigger asChild>
                            <button
                              type="button"
                              onClick={btn.action}
                              className="h-7 w-7 flex items-center justify-center rounded-md hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
                            >
                              <btn.icon className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent side="bottom" className="text-xs">{btn.label}</TooltipContent>
                        </Tooltip>
                      ))}
                    </div>
                    <Textarea
                      ref={contentRef}
                      value={content}
                      onChange={e => setContent(e.target.value)}
                      onKeyDown={handleContentKeyDown}
                      placeholder="Write your announcement content here…

You can use **bold**, *italic*, and [links](url) to format your text.
Use bullet points and numbered lists to organize information."
                      rows={12}
                      className="resize-none border-0 rounded-none text-sm leading-relaxed focus-visible:ring-0 focus-visible:ring-offset-0"
                      maxLength={10000}
                    />
                    {/* Footer */}
                    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-t text-[10px] text-muted-foreground">
                      <span>{wordCount} words</span>
                      <span className="tabular-nums">{content.length}/10,000</span>
                    </div>
                  </div>
                </div>

                {/* Type + Template */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                  {/* Type Selector */}
                  <div className="space-y-2">
                    <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Alert Type</Label>
                    <div className="grid grid-cols-3 gap-2">
                      {(Object.keys(TYPE_CONFIG) as AnnouncementType[]).map(t => {
                        const cfg = TYPE_CONFIG[t]
                        const Icon = cfg.icon
                        return (
                          <button
                            key={t}
                            onClick={() => setType(t)}
                            className={cn(
                              'flex flex-col items-center gap-2 rounded-xl border-2 p-4 text-xs font-medium transition-all',
                              type === t
                                ? cn(cfg.bg, cfg.border, cfg.color, 'shadow-sm scale-[1.02]')
                                : 'border-transparent hover:bg-muted/50 text-muted-foreground bg-muted/20',
                            )}
                          >
                            <div className={cn('h-9 w-9 rounded-lg flex items-center justify-center', type === t ? cfg.bg : 'bg-muted')}>
                              <Icon className={cn('h-4 w-4', type === t ? cfg.color : 'text-muted-foreground')} />
                            </div>
                            {cfg.label}
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Template Selector */}
                  <div className="space-y-2">
                    <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Display Template</Label>
                    <div className="grid grid-cols-2 gap-2">
                      {TEMPLATES.map(t => (
                        <button
                          key={t.value}
                          onClick={() => setTemplate(t.value)}
                          className={cn(
                            'text-left rounded-xl border-2 px-3 py-3 transition-all',
                            template === t.value
                              ? 'border-primary bg-primary/5 shadow-sm'
                              : 'border-transparent hover:bg-muted/50 bg-muted/20',
                          )}
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-base">{t.icon}</span>
                            <span className="text-xs font-semibold">{t.label}</span>
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-1">{t.description}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Media Upload */}
                <div className="space-y-2">
                  <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Image className="h-3.5 w-3.5" />
                    Cover Image
                    <span className="font-normal text-muted-foreground/70">(optional)</span>
                  </Label>
                  {mediaPreview ? (
                    <div className="relative rounded-xl border-2 border-dashed overflow-hidden group">
                      <img src={mediaPreview.url} alt={mediaPreview.filename} className="w-full h-48 object-cover" />
                      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/40 transition-colors flex items-center justify-center gap-3 opacity-0 group-hover:opacity-100">
                        <Button size="sm" variant="secondary" className="gap-1.5 text-xs rounded-lg" onClick={openImageEditor}>
                          <Crop className="h-3.5 w-3.5" /> Edit
                        </Button>
                        <Button size="sm" variant="secondary" className="gap-1.5 text-xs rounded-lg" onClick={() => fileRef.current?.click()}>
                          <Upload className="h-3.5 w-3.5" /> Replace
                        </Button>
                        <Button size="sm" variant="destructive" className="gap-1.5 text-xs rounded-lg" onClick={() => setMediaPreview(null)}>
                          <X className="h-3.5 w-3.5" /> Remove
                        </Button>
                      </div>
                      <div className="px-3 py-1.5 bg-muted/80 text-[10px] text-muted-foreground truncate">{mediaPreview.filename}</div>
                    </div>
                  ) : (
                    <div
                      className={cn(
                        'relative rounded-xl border-2 border-dashed p-10 transition-all',
                        isDragging
                          ? 'border-primary bg-primary/5 scale-[1.01]'
                          : 'border-muted-foreground/20 hover:border-primary hover:bg-primary/5',
                      )}
                      onDragEnter={e => { e.preventDefault(); setIsDragging(true) }}
                      onDragLeave={e => { e.preventDefault(); setIsDragging(false) }}
                      onDragOver={e => e.preventDefault()}
                      onDrop={handleDrop}
                    >
                      <button
                        onClick={() => fileRef.current?.click()}
                        disabled={uploading}
                        className="flex flex-col items-center gap-3 w-full text-muted-foreground disabled:opacity-50"
                      >
                        {uploading ? <LeafLogo className="h-8 w-8 animate-spin text-primary" /> : <Upload className="h-8 w-8" />}
                        <div className="text-center">
                          <p className="text-xs font-medium">{uploading ? 'Uploading…' : isDragging ? 'Drop image here' : 'Click or drag to upload'}</p>
                          <p className="text-[10px] mt-0.5">JPG, PNG, GIF, WebP</p>
                        </div>
                      </button>
                      {uploading && (
                        <div className="mt-4 mx-auto max-w-xs">
                          <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                            <div className="h-full rounded-full bg-primary transition-all duration-150" style={{ width: `${Math.max(5, uploadProgress)}%` }} />
                          </div>
                          <p className="text-[10px] text-center mt-1 tabular-nums text-muted-foreground">{uploadProgress}%</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </TabsContent>

              {/* Settings Tab */}
              <TabsContent value="settings" className="flex-1 overflow-y-auto mt-0 p-5 space-y-5">
                {/* Scheduling */}
                <div className="space-y-2">
                  <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Calendar className="h-3.5 w-3.5" />
                    Expiry Date
                    <span className="font-normal text-muted-foreground/70">(optional)</span>
                  </Label>
                  <Input
                    type="datetime-local"
                    value={expiresAt}
                    onChange={e => setExpiresAt(e.target.value)}
                    className="rounded-xl max-w-xs"
                  />
                  {expiresAt && (
                    <button className="text-[10px] text-destructive hover:underline" onClick={() => setExpiresAt('')}>Clear expiry</button>
                  )}
                </div>

                {/* Status (edit only) */}
                {isEdit && (
                  <div className="space-y-2">
                    <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Status</Label>
                    <label className={cn(
                      'flex items-center gap-3 rounded-xl border-2 p-4 cursor-pointer transition-all',
                      isActive ? 'border-green-300 bg-green-50 dark:border-green-800 dark:bg-green-900/15' : 'border-muted hover:bg-accent/30',
                    )}>
                      <Switch checked={isActive} onCheckedChange={setIsActive} />
                      <div>
                        <p className="text-sm font-medium">{isActive ? 'Active' : 'Inactive'}</p>
                        <p className="text-[10px] text-muted-foreground">{isActive ? 'Visible to targeted users' : 'Hidden from all users'}</p>
                      </div>
                    </label>
                  </div>
                )}

                <Separator />

                {/* Target Audience */}
                <div className="space-y-3">
                  <Label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Users className="h-3.5 w-3.5" />
                    Target Audience
                  </Label>
                  <label className={cn(
                    'flex items-center gap-3 rounded-xl border-2 p-4 cursor-pointer transition-all',
                    targetAll ? 'border-primary bg-primary/5' : 'border-muted hover:bg-accent/30',
                  )}>
                    <Switch checked={targetAll} onCheckedChange={v => { setTargetAll(v); if (v) { setTargetUser(false); setTargetAdmin(false); setTargetSuper(false) } }} />
                    <div>
                      <p className="text-sm font-medium">All users</p>
                      <p className="text-[10px] text-muted-foreground">Everyone on the platform</p>
                    </div>
                  </label>
                  {!targetAll && (
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                      {[
                        { key: 'user', label: 'Users', desc: 'Regular users', value: targetUser, set: setTargetUser },
                        { key: 'admin', label: 'Admins', desc: 'Admin team', value: targetAdmin, set: setTargetAdmin },
                        { key: 'super', label: 'Super Admins', desc: 'Highest access', value: targetSuper, set: setTargetSuper },
                      ].map(item => (
                        <label key={item.key} className={cn(
                          'flex items-start gap-3 rounded-xl border-2 p-3 cursor-pointer transition-all',
                          item.value ? 'border-primary bg-primary/5' : 'border-muted hover:bg-accent/30',
                        )}>
                          <Switch checked={item.value} onCheckedChange={item.set} className="mt-0.5 scale-75" />
                          <div>
                            <p className="text-xs font-semibold">{item.label}</p>
                            <p className="text-[10px] text-muted-foreground">{item.desc}</p>
                          </div>
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </div>

          {/* Live Preview Panel */}
          {showPreview && (
            <div className="hidden md:flex flex-col w-[360px] border-l overflow-hidden shrink-0 bg-muted/10">
              <div className="px-4 py-2.5 border-b shrink-0 flex items-center gap-2">
                <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Live Preview</span>
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {/* Preview card */}
                <div>
                  <p className="text-[10px] text-muted-foreground mb-2 uppercase tracking-wider">
                    {TEMPLATES.find(t => t.value === template)?.icon} {TEMPLATES.find(t => t.value === template)?.label} · {TYPE_CONFIG[type].label}
                  </p>
                  <TemplatePreview
                    type={type}
                    template={template}
                    title={title}
                    content={content}
                    mediaUrl={mediaPreview?.url}
                  />
                </div>

                <Separator />

                {/* Settings summary */}
                <div className="space-y-2">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Settings</p>
                  <div className="space-y-1.5 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Audience</span>
                      <span className="font-medium">
                        {targetAll ? 'Everyone' : [targetUser && 'Users', targetAdmin && 'Admins', targetSuper && 'Super'].filter(Boolean).join(', ') || 'None'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status</span>
                      <span className={cn('font-medium', isActive ? 'text-green-600' : 'text-muted-foreground')}>
                        {isActive ? 'Active' : 'Draft'}
                      </span>
                    </div>
                    {expiresAt && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Expires</span>
                        <span className="font-medium">{format(new Date(expiresAt), 'MMM d, yyyy')}</span>
                      </div>
                    )}
                    {mediaPreview && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Media</span>
                        <span className="font-medium text-green-600">Attached</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Words</span>
                      <span className="font-medium tabular-nums">{wordCount}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Image Editor Modal */}
        {imageEditorSrc && (
          <ImageEditor
            open={!!imageEditorSrc}
            imageSrc={imageEditorSrc}
            filename={imageEditorFilename}
            onClose={() => setImageEditorSrc(null)}
            onSave={handleImageEditorSave}
          />
        )}

        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleFileSelect}
        />
      </div>
    </TooltipProvider>
  )
}
