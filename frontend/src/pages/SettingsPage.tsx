import { useState, useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { format } from 'date-fns'
import { parseTimestamp, getInitials } from '@/lib/utils'
import {
  Monitor, Smartphone, Globe, Trash2, KeyRound, Bell, LogOut,
  Shield, Palette, Sliders, Zap, Lock, Check, Loader2,
} from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { PasswordInput } from '@/components/ui/password-input'
import { AppHeader } from '@/components/layout/AppHeader'
import { useAuthStore } from '@/stores/authStore'
import { auth, preferences, appConfig, ApiError, type AppConfig } from '@/lib/api'
import { changePasswordSchema, type ChangePasswordInput } from '@/lib/schemas'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAppConfig } from '@/hooks/useConfig'
import { toast } from 'sonner'
import { LeafLogo } from '@/components/ui/LeafLogo'

// ─── Schemas ─────────────────────────────────────────────────────────────────

const brandSchema = z.object({
  siteName: z.string().min(1, 'Required'),
  tagline: z.string(),
  company: z.string().min(1, 'Required'),
  supportEmail: z.string().email('Valid email required'),
  logoUrl: z.string().optional(),
  primaryColor: z.string().optional(),
})
type BrandInput = z.infer<typeof brandSchema>

const limitsSchema = z.object({
  textMaxLength: z.number().min(1).max(10000),
  teamTextMaxLength: z.number().min(1).max(10000).optional(),
  maxSizeImage: z.number().min(1),
  maxSizeVideo: z.number().min(1),
  maxSizeDocument: z.number().min(1),
  perDay: z.number().min(1),
  perMinute: z.number().min(1),
  perHour: z.number().min(1),
})
type LimitsInput = z.infer<typeof limitsSchema>

const securitySchema = z.object({
  loginMaxAttempts: z.number().int().positive(),
  loginWindowMinutes: z.number().int().positive(),
  loginLockoutMinutes: z.number().int().positive(),
  apiRequestsPerMinute: z.number().int().positive(),
  maxDevices: z.number().int().positive(),
  accessTokenDays: z.number().int().positive(),
})
type SecurityInput = z.infer<typeof securitySchema>

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToMB(bytes: number) { return (bytes / 1024 / 1024).toFixed(0) }

function DeviceIcon({ device }: { device: string }) {
  if (device?.toLowerCase().includes('mobile')) return <Smartphone className="h-4 w-4" />
  return <Monitor className="h-4 w-4" />
}

function SectionHeader({ icon: Icon, title, action }: { icon: typeof KeyRound; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 border-b bg-muted/30">
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
      </div>
      {action}
    </div>
  )
}

function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 py-3 px-3 sm:py-2 border-b last:border-0">
      <div className="sm:w-40 shrink-0">
        <p className="text-xs font-medium">{label}</p>
        {hint && <p className="text-[10px] text-muted-foreground">{hint}</p>}
      </div>
      <div className="flex-1 w-full min-w-0">{children}</div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export function SettingsPage() {
  const location = useLocation()
  const insideLayout = location.pathname.startsWith('/home') || location.pathname.startsWith('/admin')
  const user = useAuthStore((s) => s.user)
  const setUser = useAuthStore((s) => s.setUser)
  const queryClient = useQueryClient()

  const { data: configData } = useAppConfig()
  const { data: sessionsData, isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => auth.sessions(),
    staleTime: 30_000,
  })

  const revokeSession = useMutation({
    mutationFn: (sessionId: string) => auth.revokeSession(sessionId),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['sessions'] }); toast.success('Session revoked') },
    onError: () => toast.error('Failed to revoke session'),
  })
  const revokeAll = useMutation({
    mutationFn: () => auth.revokeAllSessions(),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['sessions'] }); toast.success('All other sessions revoked') },
    onError: () => toast.error('Failed'),
  })

  const [emailNotify, setEmailNotify] = useState(user?.emailNotifyOnMessage ?? true)
  const toggleEmail = useMutation({
    mutationFn: (enabled: boolean) => preferences.updateEmailNotifications(enabled),
    onMutate: (enabled) => { setEmailNotify(enabled); if (user) setUser({ ...user, emailNotifyOnMessage: enabled }) },
    onError: () => { setEmailNotify(!emailNotify); toast.error('Failed to update') },
    onSuccess: () => toast.success('Preference updated'),
  })

  // Password form
  const { register, handleSubmit, reset: resetPwd, formState: { errors, isSubmitting } } = useForm<ChangePasswordInput>({ resolver: zodResolver(changePasswordSchema) })
  const onPasswordSubmit = async (data: ChangePasswordInput) => {
    try { await auth.changePassword(data); toast.success('Password changed'); resetPwd() }
    catch (err) { toast.error(err instanceof ApiError ? err.message : 'Failed') }
  }

  // Track which settings section was last saved (for Saved indicator)
  const [lastSavedSection, setLastSavedSection] = useState<string | null>(null)
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markSaved = (section: string) => {
    setLastSavedSection(section)
    if (savedTimerRef.current) clearTimeout(savedTimerRef.current)
    savedTimerRef.current = setTimeout(() => setLastSavedSection(null), 2500)
  }

  // Brand form
  const { register: regBrand2, handleSubmit: hsBrand2, reset: resetBrand2, formState: { errors: eBrand2, isSubmitting: sBrand2 } } = useForm<BrandInput>({
    resolver: zodResolver(brandSchema),
    defaultValues: { siteName: '', tagline: '', company: '', supportEmail: '', logoUrl: '', primaryColor: '#000000' },
  })
  useEffect(() => { if (configData?.brand) resetBrand2({ ...configData.brand, logoUrl: configData.brand.logoUrl || '', primaryColor: configData.brand.primaryColor || '#000000' }) }, [configData?.brand, resetBrand2])
  const updateBrand2 = useMutation({
    mutationFn: (d: BrandInput) => appConfig.updateBrand(d),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('brand'); toast.success('Brand updated') },
    onError: () => toast.error('Failed'),
  })

  // Features — each toggle/field auto-saves individually
  const [featureValues, setFeatureValues] = useState({ userRegistration: true, mediaUpload: true, messageDelete: true, messageDeleteTimeLimit: 300 })
  useEffect(() => { if (configData?.features) setFeatureValues({ userRegistration: configData.features.userRegistration, mediaUpload: configData.features.mediaUpload, messageDelete: configData.features.messageDelete, messageDeleteTimeLimit: configData.features.messageDeleteTimeLimit }) }, [configData?.features])
  const [togglingFeature, setTogglingFeature] = useState<string | null>(null)
  const handleFeatureToggle = async (name: keyof typeof featureValues, value: boolean | number) => {
    const next = { ...featureValues, [name]: value }
    setFeatureValues(next)
    setTogglingFeature(name)
    try {
      await appConfig.updateFeatures(next as AppConfig['features'])
      queryClient.invalidateQueries({ queryKey: ['appConfig'] })
    } catch { toast.error('Failed to save') }
    finally { setTogglingFeature(null) }
  }

  const { register: regLimits, handleSubmit: hsLimits, reset: resetLimits, formState: { isSubmitting: sLimits } } = useForm<LimitsInput>({
    resolver: zodResolver(limitsSchema),
    defaultValues: { textMaxLength: 5000, teamTextMaxLength: 5000, maxSizeImage: 5242880, maxSizeVideo: 52428800, maxSizeDocument: 10485760, perDay: 50, perMinute: 20, perHour: 200 },
  })
  useEffect(() => {
    if (configData?.limits) {
      resetLimits({
        textMaxLength: configData.limits.message.textMaxLength,
        teamTextMaxLength: configData.limits.message.teamTextMaxLength ?? 5000,
        maxSizeImage: configData.limits.media.maxSizeImage,
        maxSizeVideo: configData.limits.media.maxSizeVideo,
        maxSizeDocument: configData.limits.media.maxSizeDocument,
        perDay: configData.limits.media.perDay ?? 50,
        perMinute: configData.limits.message.perMinute ?? 20,
        perHour: configData.limits.message.perHour ?? 200,
      })
    }
  }, [configData?.limits, resetLimits])
  const updateLimits = useMutation({
    mutationFn: (d: LimitsInput) => appConfig.updateLimits({
      message: { textMaxLength: d.textMaxLength, teamTextMaxLength: d.teamTextMaxLength, perMinute: d.perMinute, perHour: d.perHour },
      media: { maxSizeImage: d.maxSizeImage, maxSizeVideo: d.maxSizeVideo, maxSizeDocument: d.maxSizeDocument, perDay: d.perDay },
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('limits'); toast.success('Limits updated') },
    onError: () => toast.error('Failed'),
  })

  // Security form
  const { register: regSec, handleSubmit: hsSec, reset: resetSec, formState: { isSubmitting: sSec } } = useForm<SecurityInput>({
    resolver: zodResolver(securitySchema),
    defaultValues: { loginMaxAttempts: 5, loginWindowMinutes: 15, loginLockoutMinutes: 30, apiRequestsPerMinute: 60, maxDevices: 5, accessTokenDays: 30 },
  })
  useEffect(() => {
    if (configData) {
      resetSec({
        loginMaxAttempts: configData.rateLimit?.login?.maxAttempts ?? 5,
        loginWindowMinutes: configData.rateLimit?.login?.windowMinutes ?? 15,
        loginLockoutMinutes: configData.rateLimit?.login?.lockoutMinutes ?? 30,
        apiRequestsPerMinute: configData.rateLimit?.api?.requestsPerMinute ?? 60,
        maxDevices: configData.session?.maxDevices ?? 5,
        accessTokenDays: configData.session?.accessTokenDays ?? 30,
      })
    }
  }, [configData, resetSec])
  const updateSecurity = useMutation({
    mutationFn: (d: SecurityInput) => appConfig.updateSecurity({
      rateLimit: { login: { maxAttempts: d.loginMaxAttempts, windowMinutes: d.loginWindowMinutes, lockoutMinutes: d.loginLockoutMinutes }, api: { requestsPerMinute: d.apiRequestsPerMinute } },
      session: { maxDevices: d.maxDevices, accessTokenDays: d.accessTokenDays },
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('security'); toast.success('Security settings updated') },
    onError: () => toast.error('Failed'),
  })

  const sessions = sessionsData?.sessions ?? []
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'SUPER_ADMIN'
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const [saTab, setSaTab] = useState<'brand' | 'features' | 'limits' | 'security'>('brand')

  const SaveIndicator = ({ section }: { section: string }) => {
    if (lastSavedSection === section) return <span className="flex items-center gap-1 text-[10px] text-green-600"><Check className="h-3 w-3" />Saved</span>
    return null
  }

  const TABS = [
    { id: 'brand', label: 'Brand', icon: Palette },
    { id: 'features', label: 'Features', icon: Zap },
    { id: 'limits', label: 'Limits', icon: Sliders },
    { id: 'security', label: 'Security', icon: Lock },
  ] as const

  return (
    <div className={insideLayout ? 'flex flex-col h-full' : 'flex h-screen flex-col'}>
      {!insideLayout && <AppHeader />}
      <div className="flex-1 overflow-auto">
        <div className="max-w-5xl mx-auto p-4">

          {/* ── Top: Profile + Password side by side ── */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">

            {/* Profile Card */}
            <div className="rounded-xl border bg-card overflow-hidden">
              <SectionHeader icon={Shield} title="Profile" />
              <div className="p-3 flex items-center gap-3">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-sm font-bold">
                  {user?.name ? getInitials(user.name) : '?'}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold truncate">{user?.name}</p>
                  <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                  {isAdmin && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-medium text-primary bg-primary/10 px-2 py-0.5 rounded-full mt-0.5">
                      <Shield className="h-2.5 w-2.5" />
                      {isSuperAdmin ? 'Super Admin' : 'Admin'}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0 pl-3 border-l">
                  <Bell className="h-3.5 w-3.5 text-muted-foreground" />
                  <div>
                    <p className="text-xs font-medium">Email alerts</p>
                    <p className="text-[10px] text-muted-foreground">Messages</p>
                  </div>
                  <Switch checked={emailNotify} onCheckedChange={(v) => toggleEmail.mutate(v)} />
                </div>
              </div>
            </div>

            {/* Password Card */}
            <div className="rounded-xl border bg-card overflow-hidden">
              <SectionHeader icon={KeyRound} title="Change Password" />
              <form onSubmit={handleSubmit(onPasswordSubmit)} className="p-3 space-y-3">
                <div className="grid grid-cols-3 gap-2">
                  <div className="space-y-1">
                    <label className="text-[11px] text-muted-foreground">Current</label>
                    <PasswordInput placeholder="••••••••" autoComplete="current-password" className="h-8 text-sm" {...register('currentPassword')} />
                    {errors.currentPassword && <p className="text-[10px] text-destructive">{errors.currentPassword.message}</p>}
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] text-muted-foreground">New</label>
                    <PasswordInput placeholder="••••••••" autoComplete="new-password" className="h-8 text-sm" {...register('newPassword')} />
                    {errors.newPassword && <p className="text-[10px] text-destructive">{errors.newPassword.message}</p>}
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] text-muted-foreground">Confirm</label>
                    <PasswordInput placeholder="••••••••" autoComplete="new-password" className="h-8 text-sm" {...register('confirmPassword')} />
                    {errors.confirmPassword && <p className="text-[10px] text-destructive">{errors.confirmPassword.message}</p>}
                  </div>
                </div>
                <Button type="submit" size="sm" disabled={isSubmitting}>
                  {isSubmitting && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Update Password
                </Button>
              </form>
            </div>
          </div>

          {/* ── Super Admin Panel ── */}
          {isSuperAdmin && (
            <div className="rounded-xl border bg-card overflow-hidden mb-4">
              {/* Tabs */}
              <div className="flex border-b overflow-x-auto [&::-webkit-scrollbar]:hidden">
                {TABS.map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setSaTab(id)}
                    className={`flex-1 min-w-[100px] flex items-center justify-center gap-1.5 py-2.5 px-3 text-xs font-medium border-b-2 transition-colors ${saTab === id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
                  >
                    <Icon className="h-3.5 w-3.5" />{label}
                  </button>
                ))}
              </div>

              {/* Brand Tab */}
              {saTab === 'brand' && (
                <form onSubmit={hsBrand2((d) => updateBrand2.mutate(d))}>
                  <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x">
                    <div>
                      <FieldRow label="Site Name" hint="Shown in browser tab">
                        <Input className="h-8 text-sm" {...regBrand2('siteName')} />
                        {eBrand2.siteName && <p className="text-[10px] text-destructive mt-0.5">{eBrand2.siteName.message}</p>}
                      </FieldRow>
                      <FieldRow label="Company">
                        <Input className="h-8 text-sm" {...regBrand2('company')} />
                      </FieldRow>
                      <FieldRow label="Tagline">
                        <Input className="h-8 text-sm" {...regBrand2('tagline')} />
                      </FieldRow>
                    </div>
                    <div>
                      <FieldRow label="Support Email">
                        <Input type="email" className="h-8 text-sm" {...regBrand2('supportEmail')} />
                        {eBrand2.supportEmail && <p className="text-[10px] text-destructive mt-0.5">{eBrand2.supportEmail.message}</p>}
                      </FieldRow>
                      <FieldRow label="Logo URL" hint="Optional">
                        <Input className="h-8 text-sm" placeholder="https://..." {...regBrand2('logoUrl')} />
                      </FieldRow>
                      <FieldRow label="Primary Color">
                        <div className="flex gap-2">
                          <input type="color" {...regBrand2('primaryColor')} className="h-8 w-9 rounded border cursor-pointer p-0.5" />
                          <Input className="h-8 text-sm flex-1" {...regBrand2('primaryColor')} />
                        </div>
                      </FieldRow>
                    </div>
                  </div>
                  <div className="px-3 py-2 border-t bg-muted/20 flex items-center justify-between">
                    <SaveIndicator section="brand" />
                    <Button type="submit" size="sm" disabled={sBrand2 || updateBrand2.isPending}>
                      {(sBrand2 || updateBrand2.isPending) && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Brand
                    </Button>
                  </div>
                </form>
              )}

              {/* Features Tab — each switch auto-saves on toggle */}
              {saTab === 'features' && (
                <div>
                  {([
                    { name: 'userRegistration' as const, label: 'User Registration', desc: 'Allow new users to sign up via the register page' },
                    { name: 'mediaUpload' as const, label: 'Media Uploads', desc: 'Allow sending images, videos, and documents' },
                    { name: 'messageDelete' as const, label: 'Message Deletion', desc: 'Users can delete their own messages' },
                  ] as const).map(({ name, label, desc }) => (
                    <FieldRow key={name} label={label} hint={desc}>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={featureValues[name] as boolean}
                          onCheckedChange={(v) => handleFeatureToggle(name, v)}
                          disabled={togglingFeature === name}
                        />
                        {togglingFeature === name && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
                      </div>
                    </FieldRow>
                  ))}
                  <FieldRow label="Delete Window" hint="Seconds after send — blur to save">
                    <div className="flex items-center gap-2">
                      <Input
                        type="number" min={10}
                        className="h-8 w-24 text-sm"
                        value={featureValues.messageDeleteTimeLimit}
                        onChange={(e) => setFeatureValues((prev) => ({ ...prev, messageDeleteTimeLimit: Number(e.target.value) }))}
                        onBlur={() => handleFeatureToggle('messageDeleteTimeLimit', featureValues.messageDeleteTimeLimit)}
                      />
                      <span className="text-xs text-muted-foreground">seconds</span>
                      {togglingFeature === 'messageDeleteTimeLimit' && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
                    </div>
                  </FieldRow>
                </div>
              )}

              {/* Limits Tab */}
              {saTab === 'limits' && (
                <form onSubmit={hsLimits((d) => updateLimits.mutate(d))}>
                  <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x">
                    <div>
                      <FieldRow label="Max Text (Users)" hint="Characters per message">
                        <Input type="number" min={1} max={10000} className="h-8 text-sm" {...regLimits('textMaxLength', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Max Text (Team)" hint="Characters per internal message">
                        <Input type="number" min={1} max={10000} className="h-8 text-sm" {...regLimits('teamTextMaxLength', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Max Image" hint={`= ${bytesToMB(5242880)} MB default`}>
                        <div className="flex gap-2 items-center">
                          <Input type="number" min={1} className="h-8 text-sm flex-1" {...regLimits('maxSizeImage', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">bytes</span>
                        </div>
                      </FieldRow>
                      <FieldRow label="Max Video" hint={`= ${bytesToMB(52428800)} MB default`}>
                        <div className="flex gap-2 items-center">
                          <Input type="number" min={1} className="h-8 text-sm flex-1" {...regLimits('maxSizeVideo', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">bytes</span>
                        </div>
                      </FieldRow>
                    </div>
                    <div>
                      <FieldRow label="Max Document" hint={`= ${bytesToMB(10485760)} MB default`}>
                        <div className="flex gap-2 items-center">
                          <Input type="number" min={1} className="h-8 text-sm flex-1" {...regLimits('maxSizeDocument', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">bytes</span>
                        </div>
                      </FieldRow>
                      <FieldRow label="Uploads/Day" hint="Per user">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regLimits('perDay', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Messages/Min" hint="Per user rate limit">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regLimits('perMinute', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Messages/Hour" hint="Per user hourly cap">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regLimits('perHour', { valueAsNumber: true })} />
                      </FieldRow>
                    </div>
                  </div>
                  <div className="px-3 py-2 border-t bg-muted/20 flex items-center justify-between">
                    <SaveIndicator section="limits" />
                    <Button type="submit" size="sm" disabled={sLimits || updateLimits.isPending}>
                      {(sLimits || updateLimits.isPending) && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Limits
                    </Button>
                  </div>
                </form>
              )}

              {/* Security Tab */}
              {saTab === 'security' && (
                <form onSubmit={hsSec((d) => updateSecurity.mutate(d))}>
                  <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x">
                    <div>
                      <div className="px-3 py-1.5 bg-muted/30 border-b">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Login Protection</p>
                      </div>
                      <FieldRow label="Max Attempts" hint="Before lockout">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regSec('loginMaxAttempts', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Window" hint="Minutes to track attempts">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regSec('loginWindowMinutes', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Lockout Duration" hint="Minutes locked out">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regSec('loginLockoutMinutes', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="API Req/Min" hint="Per IP rate limit">
                        <Input type="number" min={1} className="h-8 text-sm w-24" {...regSec('apiRequestsPerMinute', { valueAsNumber: true })} />
                      </FieldRow>
                    </div>
                    <div>
                      <div className="px-3 py-1.5 bg-muted/30 border-b">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Sessions & Tokens</p>
                      </div>
                      <FieldRow label="Max Devices" hint="Concurrent sessions per user">
                        <Input type="number" min={1} max={20} className="h-8 text-sm w-24" {...regSec('maxDevices', { valueAsNumber: true })} />
                      </FieldRow>
                      <FieldRow label="Token Lifetime" hint="Days before re-login required">
                        <div className="flex items-center gap-2">
                          <Input type="number" min={1} max={365} className="h-8 text-sm w-24" {...regSec('accessTokenDays', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">days</span>
                        </div>
                      </FieldRow>
                    </div>
                  </div>
                  <div className="px-3 py-2 border-t bg-muted/20 flex items-center justify-between">
                    <SaveIndicator section="security" />
                    <Button type="submit" size="sm" disabled={sSec || updateSecurity.isPending}>
                      {(sSec || updateSecurity.isPending) && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Security
                    </Button>
                  </div>
                </form>
              )}
            </div>
          )}

          {/* ── Sessions ── */}
          <div className="rounded-xl border bg-card overflow-hidden">
            <SectionHeader
              icon={Globe}
              title="Active Sessions"
              action={sessions.length > 1 ? (
                <Button variant="ghost" size="sm" className="h-6 text-xs gap-1 text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => revokeAll.mutate()} disabled={revokeAll.isPending}>
                  <LogOut className="h-3 w-3" />Revoke others
                </Button>
              ) : undefined}
            />
            <div className="divide-y">
              {sessionsLoading ? (
                <div className="p-3 space-y-2">
                  {[1, 2].map(i => (
                    <div key={i} className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded bg-muted animate-pulse" />
                      <div className="flex-1 space-y-1"><div className="h-3 w-24 bg-muted animate-pulse rounded" /><div className="h-2.5 w-32 bg-muted animate-pulse rounded" /></div>
                    </div>
                  ))}
                </div>
              ) : sessions.length === 0 ? (
                <div className="p-4 text-center text-sm text-muted-foreground">No active sessions</div>
              ) : (
                sessions.map((session) => (
                  <div key={session.id} className="flex items-center gap-3 px-3 py-2.5 hover:bg-muted/30 transition-colors">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted shrink-0">
                      <DeviceIcon device={session.deviceInfo?.device ?? ''} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{session.deviceInfo?.browser ?? 'Unknown'}</span>
                        <span className="text-xs text-muted-foreground">{session.deviceInfo?.os ?? 'Unknown'}</span>
                        {session.isCurrent && <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">Current</span>}
                      </div>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <span>{session.ipAddress}</span><span>·</span>
                        <span>{format(parseTimestamp(session.lastActiveAt), 'MMM d, HH:mm')}</span>
                      </div>
                    </div>
                    {!session.isCurrent && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10" onClick={() => revokeSession.mutate(session.id)} disabled={revokeSession.isPending}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}