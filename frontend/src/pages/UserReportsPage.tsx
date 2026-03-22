import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FileWarning, Plus, Clock, CheckCircle2,
  Paperclip, X, FileImage, FileText, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { cn, formatRelativeTime } from '@/lib/utils'
import { EmptyState } from '@/components/ui/empty-state'
import { useUserReports, useCreateUserReport, useUploadMedia } from '@/hooks/useUserReports'
import { toast } from '@/components/ui/sonner'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { getSocket } from '@/lib/socket'
import { useQueryClient } from '@tanstack/react-query'

function ReportCard({ report, onClick }: {
  report: {
    id: string
    subject: string
    description: string
    status: 'PENDING' | 'RESOLVED'
    createdAt: number
    media?: { id: string; type: string; filename: string }
  }
  onClick: () => void
}) {
  const isPending = report.status === 'PENDING'

  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-xl border bg-card hover:bg-accent/40 hover:border-primary/30 hover:shadow-sm transition-all group"
    >
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Status dot */}
          <div className={cn(
            'h-2 w-2 rounded-full shrink-0 mt-2',
            isPending ? 'bg-amber-500' : 'bg-green-500'
          )} />

          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-semibold text-sm truncate group-hover:text-primary transition-colors">
                {report.subject}
              </h3>
              <Badge
                variant="outline"
                className={cn(
                  'shrink-0 text-[10px] font-medium',
                  isPending
                    ? 'border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-400'
                    : 'border-green-300 text-green-600 bg-green-50 dark:bg-green-900/20 dark:text-green-400'
                )}
              >
                {isPending ? <><Clock className="h-2.5 w-2.5 mr-1" />Pending</> : <><CheckCircle2 className="h-2.5 w-2.5 mr-1" />Resolved</>}
              </Badge>
            </div>

            <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
              {report.description}
            </p>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                {report.media && (
                  <span className="flex items-center gap-1">
                    <Paperclip className="h-3 w-3" />
                    {report.media.filename}
                  </span>
                )}
                <span>{formatRelativeTime(report.createdAt)}</span>
                <span className="font-mono">#{report.id.slice(-6).toUpperCase()}</span>
              </div>
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
            </div>
          </div>
        </div>
      </div>
    </button>
  )
}

function CreateReportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [subject, setSubject] = useState('')
  const [description, setDescription] = useState('')
  const [mediaFile, setMediaFile] = useState<File | null>(null)
  const [mediaId, setMediaId] = useState<string | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isUploading, setIsUploading] = useState(false)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const createReport = useCreateUserReport()
  const uploadMedia = useUploadMedia()

  useEffect(() => {
    if (mediaFile?.type.startsWith('image/')) {
      const url = URL.createObjectURL(mediaFile)
      setPreviewUrl(url)
      return () => { URL.revokeObjectURL(url); setPreviewUrl(null) }
    } else {
      setPreviewUrl(null)
    }
  }, [mediaFile])

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (file.size > 10 * 1024 * 1024) { toast.error('File size must be less than 10MB'); return }
    setMediaFile(file)
    toast.success('File attached — will upload when you submit')
  }

  const removeMedia = () => { setMediaFile(null); setMediaId(null); setUploadProgress(0) }

  const handleSubmit = async () => {
    if (!subject.trim() || !description.trim()) { toast.error('Please fill in all fields'); return }
    let uploadedMediaId = mediaId
    if (mediaFile && !mediaId) {
      setIsUploading(true)
      setUploadProgress(0)
      try {
        const result = await uploadMedia.mutateAsync({
          file: mediaFile, type: mediaFile.type.startsWith('image/') ? 'IMAGE' : 'DOCUMENT',
          onProgress: setUploadProgress, context: 'report',
        })
        if (result.success && result.media) uploadedMediaId = result.media.id
      } catch {
        toast.error('File upload failed. Please try again or submit without an attachment.')
        setIsUploading(false); setMediaFile(null); setMediaId(null); setUploadProgress(0)
        if (fileInputRef.current) fileInputRef.current.value = ''
        return
      } finally { setIsUploading(false) }
    }
    try {
      await createReport.mutateAsync({ subject: subject.trim(), description: description.trim(), mediaId: uploadedMediaId || undefined })
      setSubject(''); setDescription(''); setMediaFile(null); setMediaId(null)
      onClose()
    } catch { /* handled by mutation */ }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Submit a Report</DialogTitle>
          <DialogDescription>Report an issue to our team. We'll review it and follow up with you.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 pt-4">
          <div className="space-y-2">
            <Label htmlFor="subject">Subject</Label>
            <Input id="subject" placeholder="Brief description of the issue" maxLength={200} value={subject} onChange={e => setSubject(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Details</Label>
            <Textarea id="description" placeholder="Please describe the issue in detail..." maxLength={5000} rows={5} value={description} onChange={e => setDescription(e.target.value)} className="resize-none" />
            <p className="text-[10px] text-muted-foreground text-right">{description.length}/5000</p>
          </div>
          <div className="space-y-2">
            <Label>Attachment (optional)</Label>
            {!mediaFile ? (
              <>
                <input type="file" accept="image/*,.pdf,.doc,.docx,.txt" onChange={handleFileSelect} className="hidden" id="report-media" ref={fileInputRef} />
                <label htmlFor="report-media" className={cn('flex items-center justify-center gap-2 px-4 py-3 rounded-lg border-2 border-dashed cursor-pointer transition-colors', isUploading ? 'border-muted-foreground/25 opacity-50 cursor-not-allowed' : 'border-muted-foreground/25 hover:border-muted-foreground/50 hover:bg-muted/30')}>
                  {isUploading ? <><LeafLogo className="h-4 w-4 animate-spin" /><span className="text-sm">Uploading... {uploadProgress}%</span></> : <><Paperclip className="h-4 w-4 text-muted-foreground" /><span className="text-sm text-muted-foreground">Add photo or document</span></>}
                </label>
                {isUploading && <div className="w-full h-1 bg-muted rounded-full overflow-hidden"><div className="h-full bg-primary transition-all duration-200" style={{ width: `${uploadProgress}%` }} /></div>}
              </>
            ) : (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted border">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  {previewUrl ? <img src={previewUrl} alt="Preview" className="h-10 w-10 object-cover rounded-lg" /> : mediaFile.type.startsWith('image/') ? <FileImage className="h-4 w-4" /> : <FileText className="h-4 w-4" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{mediaFile.name}</p>
                  <p className="text-xs text-muted-foreground">{(mediaFile.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <button type="button" onClick={removeMedia} className="p-1.5 rounded-full hover:bg-background transition-colors"><X className="h-4 w-4 text-muted-foreground" /></button>
              </div>
            )}
            <p className="text-[10px] text-muted-foreground">Max file size: 10MB</p>
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={onClose}>Cancel</Button>
            <Button onClick={handleSubmit} disabled={createReport.isPending || isUploading || !subject.trim() || !description.trim()}>
              {createReport.isPending ? <><LeafLogo className="h-4 w-4 mr-2 animate-spin" />Submitting...</> : 'Submit Report'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function CardSkeleton() {
  return (
    <div className="p-4 space-y-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="rounded-xl border p-4 space-y-3">
          <div className="flex justify-between"><Skeleton className="h-4 w-32" /><Skeleton className="h-5 w-16" /></div>
          <Skeleton className="h-3 w-full" /><Skeleton className="h-3 w-24" />
        </div>
      ))}
    </div>
  )
}

export function UserReportsPage() {
  const navigate = useNavigate()
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const { data, isLoading } = useUserReports()
  const queryClient = useQueryClient()

  useEffect(() => {
    const socket = getSocket()
    if (!socket) return
    const onResolved = (payload: { reportId: string }) => {
      queryClient.setQueryData<{ reports: Array<{ id: string; status: string }> }>(['user-reports', undefined], (old) => {
        if (!old) return old
        return { ...old, reports: old.reports.map(r => r.id === payload.reportId ? { ...r, status: 'RESOLVED' } : r) }
      })
      queryClient.invalidateQueries({ queryKey: ['user-reports'] })
      toast.success('Your report has been resolved!')
    }
    const onNew = () => queryClient.invalidateQueries({ queryKey: ['user-reports'] })
    socket.on('user_report:resolved', onResolved)
    socket.on('user_report:new', onNew)
    return () => { socket.off('user_report:resolved', onResolved); socket.off('user_report:new', onNew) }
  }, [queryClient])

  const reports = data?.reports ?? []
  const pendingCount = reports.filter(r => r.status === 'PENDING').length

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="p-4 border-b"><Skeleton className="h-6 w-32" /></div>
        <CardSkeleton />
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 sm:p-4 border-b space-y-4 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <FileWarning className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">My Reports</h2>
              <p className="text-[11px] text-muted-foreground">{reports.length} total · {pendingCount} pending</p>
            </div>
          </div>
          <Button size="sm" onClick={() => setShowCreateDialog(true)} className="gap-1.5">
            <Plus className="h-4 w-4" /> New Report
          </Button>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-3 sm:p-4 space-y-3">
          {reports.length === 0 ? (
            <div className="flex flex-col items-center">
              <EmptyState icon={FileWarning} title="No reports yet" subtitle="Submit a report to get help from our team" />
              <Button onClick={() => setShowCreateDialog(true)} className="mt-4">
                <Plus className="h-4 w-4 mr-2" /> Submit Report
              </Button>
            </div>
          ) : (
            reports.map(report => (
              <ReportCard
                key={report.id}
                report={report}
                onClick={() => navigate(`/home/reports/${report.id}`)}
              />
            ))
          )}
        </div>
      </ScrollArea>

      <CreateReportDialog open={showCreateDialog} onClose={() => setShowCreateDialog(false)} />
    </div>
  )
}
