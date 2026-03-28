import { useState, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { CheckCircle, AlertCircle, ArrowRight, ArrowLeft, ShieldOff, ChevronDown, MessageSquareWarning, Paperclip, X, FileImage, FileText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/ui/password-input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { registerSchema, type RegisterInput } from '@/lib/schemas'
import { API_URL, ApiError } from '@/lib/api'
import { useAppConfig } from '@/hooks/useConfig'
import { LeafLogo } from '@/components/ui/LeafLogo'
import { cn } from '@/lib/utils'

// ─── Password strength checker ───────────────────────────────────────────────
const PWD_CRITERIA = [
  { label: 'At least 12 characters', test: (v: string) => v.length >= 12 },
  { label: 'Uppercase letter', test: (v: string) => /[A-Z]/.test(v) },
  { label: 'Number', test: (v: string) => /[0-9]/.test(v) },
  { label: 'Symbol (!@#$…)', test: (v: string) => /[^A-Za-z0-9]/.test(v) },
]

function PasswordStrength({ value }: { value: string }) {
  if (!value) return null
  const passed = PWD_CRITERIA.filter(c => c.test(value)).length
  const colors = ['bg-destructive', 'bg-destructive', 'bg-amber-500', 'bg-amber-400', 'bg-green-500']
  return (
    <div className="mt-2 space-y-2">
      <div className="flex gap-1">
        {PWD_CRITERIA.map((_, i) => (
          <div key={i} className={cn('h-1 flex-1 rounded-full transition-colors duration-300', i < passed ? colors[passed] : 'bg-muted')} />
        ))}
      </div>
      <ul className="space-y-0.5">
        {PWD_CRITERIA.map(c => {
          const ok = c.test(value)
          return (
            <li key={c.label} className={cn('flex items-center gap-1.5 text-[11px] transition-colors', ok ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground')}>
              <span className={cn('h-1.5 w-1.5 rounded-full shrink-0', ok ? 'bg-green-500' : 'bg-muted-foreground/40')} />
              {c.label}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

// Maps MIME types to their valid file extensions for fallback validation
const ALLOWED_MIME_EXTENSIONS: Record<string, string[]> = {
  'image/jpeg': ['jpg', 'jpeg'],
  'image/png': ['png'],
  'image/webp': ['webp'],
  'image/gif': ['gif'],
  'application/pdf': ['pdf'],
  'text/plain': ['txt'],
  'application/msword': ['doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx'],
}
const ALLOWED_MIME_TYPES = Object.keys(ALLOWED_MIME_EXTENSIONS)

export function RegisterPage() {
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)
  const [successState, setSuccessState] = useState<{ message: string; hasReport: boolean; hasMedia: boolean } | null>(null)
  const [showReport, setShowReport] = useState(false)
  const [reportMedia, setReportMedia] = useState<File | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data: configData } = useAppConfig()
  const registrationDisabled = configData !== undefined && configData.features?.userRegistration === false

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
  })

  const reportDescription = watch('reportDescription') ?? ''

  const onSubmit = async (data: RegisterInput) => {
    setError(null)
    setIsSubmitting(true)

    try {
      // Build FormData for multipart submission (user + report + media in ONE request)
      const formData = new FormData()
      formData.append('email', data.email)
      formData.append('password', data.password)
      formData.append('name', data.name)
      if (data.phone) {
        formData.append('phone', data.phone)
      }

      // Add report fields if the section is open and both fields are filled
      const hasReport = showReport && !!data.reportSubject?.trim() && !!data.reportDescription?.trim()
      if (hasReport) {
        formData.append('reportSubject', data.reportSubject!.trim())
        formData.append('reportDescription', data.reportDescription!.trim())

        // Add media file if selected (sent with registration, no pre-upload!)
        if (reportMedia) {
          formData.append('media', reportMedia)
        }
      }

      const response = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        body: formData,
        credentials: 'include',
      })

      const result = await response.json()

      if (!result.success) {
        if (result.error?.code === 'RATE_LIMITED') {
          throw new ApiError(result.error.message || 'Too many attempts', response.status)
        }
        throw new ApiError(result.error?.message || 'Registration failed', response.status)
      }

      setSuccessState({
        message: result.message || 'Registration successful!',
        hasReport: !!result.hasReport,
        hasMedia: !!result.hasMedia,
      })
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setError('Too many attempts. Please try again later.')
        } else if (err.status === 409) {
          setError('This email is already registered.')
        } else {
          setError(err.message || 'Registration failed. Please try again or contact support.')
        }
      } else {
        setError('An unexpected error occurred.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    // Validate file size (max 10MB for reports)
    const maxSize = 10 * 1024 * 1024
    if (file.size > maxSize) {
      setError('File size must be less than 10MB')
      return
    }

    // Validate MIME type — check declared type first, then fall back to extension
    const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
    const mimeAllowed = ALLOWED_MIME_TYPES.includes(file.type)
    const extAllowed = Object.values(ALLOWED_MIME_EXTENSIONS).some(exts => exts.includes(ext))
    if (!mimeAllowed && !extAllowed) {
      setError('File type not allowed. Please upload an image, PDF, or document.')
      return
    }

    setReportMedia(file)
    setError(null)
  }

  const removeMedia = () => {
    setReportMedia(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const getFileIcon = (type: string) => {
    if (type.startsWith('image/')) return <FileImage className="h-4 w-4" />
    return <FileText className="h-4 w-4" />
  }

  if (registrationDisabled) {
    return (
      <AuthLayout title="Registration closed" subtitle="New registrations are not currently accepted">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted ring-8 ring-muted/30">
            <ShieldOff className="h-8 w-8 text-muted-foreground" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Registration Disabled</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              New account registration is temporarily closed. Please contact the support team for access.
            </p>
          </div>
          <Button onClick={() => navigate('/login')} variant="outline" className="h-11 rounded-xl gap-2 px-6">
            <ArrowLeft className="h-4 w-4" />
            Back to Sign In
          </Button>
        </div>
      </AuthLayout>
    )
  }

  if (successState) {
    return (
      <AuthLayout title="You're all set!" subtitle="Your registration was submitted successfully.">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/20 ring-8 ring-green-50 dark:ring-green-900/10">
            <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Account Created</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              {successState.message}
            </p>
            {successState.hasReport && (
              <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
                Your report{successState.hasMedia ? ' and attachment were' : ' was'} received and will be reviewed by our team.
              </p>
            )}
          </div>
          <Button onClick={() => navigate('/login')} className="h-11 rounded-xl gap-2 px-6">
            <ArrowLeft className="h-4 w-4" />
            Back to Sign In
          </Button>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="Get started with a free account"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-destructive/20 bg-destructive/5 px-4 py-3">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="name" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Full Name
            </Label>
            <Input
              id="name"
              placeholder="John Doe"
              autoComplete="name"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('name')}
            />
            {errors.name && (
              <p className="text-xs text-destructive pl-1">{errors.name.message}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="phone" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Phone
            </Label>
            <Input
              id="phone"
              type="tel"
              placeholder="+1 234 567 890"
              autoComplete="tel"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('phone')}
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="email" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Email Address
          </Label>
          <Input
            id="email"
            type="email"
            placeholder="you@company.com"
            autoComplete="email"
            className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            {...register('email')}
          />
          {errors.email && (
            <p className="text-xs text-destructive pl-1">{errors.email.message}</p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="password" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Password
          </Label>
          <PasswordInput
            id="password"
            placeholder="Min 12 characters"
            autoComplete="new-password"
            className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            {...register('password')}
          />
          <PasswordStrength value={watch('password') ?? ''} />
          {errors.password && (
            <p className="text-xs text-destructive pl-1">{errors.password.message}</p>
          )}
        </div>

        {/* Optional Issue Report - Now with direct file upload */}
        <div className="rounded-xl border border-dashed overflow-hidden">
          <button
            type="button"
            onClick={() => setShowReport(v => !v)}
            className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-muted/40 transition-colors"
          >
            <div className="flex items-center gap-2 text-muted-foreground">
              <MessageSquareWarning className="h-4 w-4 shrink-0" />
              <span className="text-xs font-medium">Have an issue to report? <span className="font-normal">(optional)</span></span>
            </div>
            <ChevronDown className={cn('h-4 w-4 text-muted-foreground transition-transform duration-200 shrink-0', showReport && 'rotate-180')} />
          </button>
          {showReport && (
            <div className="px-4 pb-4 pt-1 space-y-3 border-t bg-muted/20">
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Submit a support request with your registration. Our team reviews it once your account is approved. This doesn't replace normal reports you can submit after sign-in.
              </p>
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Subject</Label>
                <Input
                  placeholder="Brief description of the issue"
                  className="h-10 rounded-lg bg-background text-sm"
                  {...register('reportSubject')}
                />
                {errors.reportSubject && (
                  <p className="text-xs text-destructive pl-1">{errors.reportSubject.message}</p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Details</Label>
                <Textarea
                  placeholder="Please describe the issue in detail…"
                  rows={4}
                  className="rounded-lg bg-background text-sm resize-none"
                  {...register('reportDescription')}
                />
                {errors.reportDescription && (
                  <p className="text-xs text-destructive pl-1">{errors.reportDescription.message}</p>
                )}
                <p className="text-[10px] text-muted-foreground text-right tabular-nums">{reportDescription.length}/2000</p>
              </div>

              {/* Media Upload - Direct file attachment (no pre-upload!) */}
              <div className="space-y-2">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Attachment <span className="font-normal normal-case">(optional)</span></Label>

                {!reportMedia ? (
                  <>
                    <input
                      ref={fileInputRef}
                      type="file"
                      name="media"
                      accept="image/*,.pdf,.doc,.docx,.txt"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg border-2 border-dashed border-muted-foreground/25 hover:border-muted-foreground/50 hover:bg-muted/30 transition-colors text-muted-foreground"
                    >
                      <Paperclip className="h-4 w-4" />
                      <span className="text-sm">Add photo or document</span>
                    </button>
                  </>
                ) : (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-background border">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      {reportMedia.type.startsWith('image/') ? (
                        <img
                          src={URL.createObjectURL(reportMedia)}
                          alt="Preview"
                          className="h-10 w-10 object-cover rounded-lg"
                        />
                      ) : (
                        getFileIcon(reportMedia.type)
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{reportMedia.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {(reportMedia.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={removeMedia}
                      className="p-1.5 rounded-full hover:bg-muted transition-colors"
                    >
                      <X className="h-4 w-4 text-muted-foreground" />
                    </button>
                  </div>
                )}
                <p className="text-[10px] text-muted-foreground">Max file size: 10MB. Supported: images, PDF, DOC</p>
              </div>
            </div>
          )}
        </div>

        <Button
          type="submit"
          className="h-11 w-full rounded-xl text-sm font-semibold gap-2"
          disabled={isSubmitting}
        >
          {isSubmitting ? (
            <LeafLogo className="h-4 w-4 animate-spin" />
          ) : (
            <>
              Create Account
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-primary hover:underline underline-offset-4">
            Sign in
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
