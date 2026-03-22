import { useState, useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { format } from 'date-fns'
import { parseTimestamp, getInitials, formatFileSize } from '@/lib/utils'
import {
  Monitor, Smartphone, Globe, Trash2, KeyRound, Bell, LogOut,
  Shield, Palette, Sliders, Zap, Lock, Check, Loader2, Cloud, Pencil,
  User, Mail, Phone, Image, FileText, FileImage, RefreshCw, Users2, Info,
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
import { auth, preferences, appConfig, users, ApiError, type AppConfig } from '@/lib/api'
import { changePasswordSchema, type ChangePasswordInput } from '@/lib/schemas'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTriggerMediaCleanup } from '@/hooks/useUsers'
import { useAppConfig } from '@/hooks/useConfig'
import { toast } from '@/components/ui/sonner'
import { LeafLogo } from '@/components/ui/LeafLogo'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog'

// ─── Schemas ─────────────────────────────────────────────────────────────────

const brandSchema = z.object({
  siteName: z.string().min(1, 'Required'),
  tagline: z.string(),
  company: z.string().min(1, 'Required'),
  supportEmail: z.string().email('Valid email required'),
  logoUrl: z.string().optional(),
})
type BrandInput = z.infer<typeof brandSchema>

const limitsSchema = z.object({
  textMaxLength: z.number().min(1).max(10000),
  teamTextMaxLength: z.number().min(1).max(10000).optional(),
  maxSizeImage: z.number().min(1),
  maxSizeDocument: z.number().min(1),
  perDay: z.number().min(1),
  perMinute: z.number().min(1),
  perHour: z.number().min(1),
  presignedUrlTTL: z.number().min(60).max(3600).optional(),
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

const storageSchema = z.object({
  imagekitPublicKey: z.string().optional(),
  imagekitUrlEndpoint: z.string().url('Must be a valid URL').optional().or(z.literal('')),
})
type StorageInput = z.infer<typeof storageSchema>

const profileSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name is too long'),
  email: z.string().email('Valid email required').max(255, 'Email is too long'),
  phone: z.string().max(50, 'Phone is too long').optional(),
})
type ProfileInput = z.infer<typeof profileSchema>

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
    staleTime: 0,
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
  // Sync local switch state when auth store is updated by socket (other session or preferences:updated)
  useEffect(() => { setEmailNotify(user?.emailNotifyOnMessage ?? true) }, [user?.emailNotifyOnMessage])
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

  // Profile edit form
  const [isEditProfileOpen, setIsEditProfileOpen] = useState(false)
  const { register: regProfile, handleSubmit: hsProfile, reset: resetProfile, formState: { errors: eProfile, isSubmitting: sProfile } } = useForm<ProfileInput>({
    resolver: zodResolver(profileSchema),
    defaultValues: { name: user?.name ?? '', email: user?.email ?? '', phone: (user as unknown as { phone?: string })?.phone ?? '' },
  })
  useEffect(() => {
    if (user) {
      resetProfile({ name: user.name, email: user.email, phone: (user as unknown as { phone?: string }).phone ?? '' })
    }
  }, [user, resetProfile])
  const updateProfile = useMutation({
    mutationFn: (data: ProfileInput) => users.updateProfile(data),
    onSuccess: (result) => {
      toast.success('Profile updated')
      setIsEditProfileOpen(false)
      // Update user in auth store with all changed fields including phone
      if (user) {
        const updated = (result as unknown as { user?: { name?: string; email?: string; phone?: string } }).user
        setUser({
          ...user,
          name: updated?.name ?? user.name,
          email: updated?.email ?? user.email,
          ...(updated?.phone !== undefined ? { phone: updated.phone } : {}),
        } as typeof user)
      }
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : 'Failed to update profile'),
  })

  // My Media
  const [isMediaOpen, setIsMediaOpen] = useState(false)
  const isUserRole = user?.role === 'USER'
  const { data: mediaData, isLoading: mediaLoading, refetch: refetchMedia } = useQuery({
    queryKey: ['myMedia'],
    queryFn: () => users.getMedia({ limit: 50 }),
    enabled: isMediaOpen && isUserRole,
  })
  const deleteMedia = useMutation({
    mutationFn: (mediaId: string) => users.deleteMedia(mediaId),
    onSuccess: () => { toast.success('Media deleted'); refetchMedia() },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : 'Failed to delete'),
  })

  // Track which settings section was last saved (for Saved indicator)
  const [lastSavedSection, setLastSavedSection] = useState<string | null>(null)
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const markSaved = (section: string) => {
    setLastSavedSection(section)
    if (savedTimerRef.current) clearTimeout(savedTimerRef.current)
    savedTimerRef.current = setTimeout(() => setLastSavedSection(null), 2500)
  }

  // Cleanup timer on unmount to prevent state update on unmounted component
  useEffect(() => {
    return () => { if (savedTimerRef.current) clearTimeout(savedTimerRef.current) }
  }, [])

  // Brand form
  const { register: regBrand2, handleSubmit: hsBrand2, reset: resetBrand2, formState: { errors: eBrand2, isSubmitting: sBrand2 } } = useForm<BrandInput>({
    resolver: zodResolver(brandSchema),
    defaultValues: { siteName: '', tagline: '', company: '', supportEmail: '', logoUrl: '' },
  })
  useEffect(() => { if (configData?.brand) resetBrand2({ ...configData.brand, logoUrl: configData.brand.logoUrl || '' }) }, [configData?.brand, resetBrand2])
  const updateBrand2 = useMutation({
    mutationFn: (d: BrandInput) => appConfig.updateBrand(d),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('brand'); toast.success('Brand updated') },
    onError: () => toast.error('Failed'),
  })

  // Features — each toggle/field auto-saves individually
  const [featureValues, setFeatureValues] = useState({ userRegistration: true, mediaUpload: true })
  useEffect(() => { if (configData?.features) setFeatureValues({ userRegistration: configData.features.userRegistration, mediaUpload: configData.features.mediaUpload }) }, [configData?.features])
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
  })
  useEffect(() => {
    if (configData?.limits) {
      resetLimits({
        textMaxLength: configData.limits.message.textMaxLength,
        teamTextMaxLength: configData.limits.message.teamTextMaxLength ?? 5000,
        maxSizeImage: configData.limits.media.maxSizeImage,
        maxSizeDocument: configData.limits.media.maxSizeDocument,
        perDay: configData.limits.media.perDay ?? 50,
        perMinute: configData.limits.message.perMinute ?? 20,
        perHour: configData.limits.message.perHour ?? 200,
        presignedUrlTTL: configData.limits.upload?.presignedUrlTTL ?? 1800,
      })
    }
  }, [configData?.limits, resetLimits])
  const updateLimits = useMutation({
    mutationFn: (d: LimitsInput) => appConfig.updateLimits({
      message: { textMaxLength: d.textMaxLength, teamTextMaxLength: d.teamTextMaxLength, perMinute: d.perMinute, perHour: d.perHour },
      ...(d.presignedUrlTTL !== undefined && { upload: { presignedUrlTTL: d.presignedUrlTTL } }),
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
  const [saTab, setSaTab] = useState<'brand' | 'features' | 'limits' | 'storage' | 'security' | 'assignment'>('brand')



  // Assignment settings state — initialise from config, stays in sync via cache:invalidate socket
  const [assignMaxLoad, setAssignMaxLoad] = useState<number>(25)
  const [assignThreshold, setAssignThreshold] = useState<number>(80) // displayed as %, stored as 0-1
  const [assignPreferOnline, setAssignPreferOnline] = useState<boolean>(true)
  useEffect(() => {
    if (configData?.assignment) {
      setAssignMaxLoad(configData.assignment.maxConversationsPerAdmin)
      setAssignThreshold(Math.round((configData.assignment.superAdminThreshold ?? 0.8) * 100))
      setAssignPreferOnline(configData.assignment.preferOnlineAdmins ?? true)
    }
  }, [configData?.assignment])
  const updateAssignment = useMutation({
    mutationFn: () => appConfig.updateAssignment({
      maxConversationsPerAdmin: assignMaxLoad,
      superAdminThreshold: assignThreshold / 100,
      preferOnlineAdmins: assignPreferOnline,
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('assignment'); toast.success('Assignment settings saved') },
    onError: () => toast.error('Failed to save assignment settings'),
  })

  // Storage form
  const { register: regStorage, handleSubmit: hsStorage, reset: resetStorage, formState: { errors: eStorage, isSubmitting: sStorage } } = useForm<StorageInput>({
    resolver: zodResolver(storageSchema),
    defaultValues: { imagekitPublicKey: '', imagekitUrlEndpoint: '' },
  })
  useEffect(() => {
    if (configData?.storage) {
      resetStorage({
        imagekitPublicKey: configData.storage.imagekitPublicKey || '',
        imagekitUrlEndpoint: configData.storage.imagekitUrlEndpoint || '',
      })
    }
  }, [configData?.storage, resetStorage])
  const updateStorage = useMutation({
    mutationFn: (d: StorageInput) => appConfig.updateStorage(d),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); markSaved('storage'); toast.success('Storage settings updated') },
    onError: () => toast.error('Failed to update storage'),
  })

  const triggerMediaCleanup = useTriggerMediaCleanup()

  const SaveIndicator = ({ section }: { section: string }) => {
    if (lastSavedSection === section) return <span className="flex items-center gap-1 text-[10px] text-green-600"><Check className="h-3 w-3" />Saved</span>
    return null
  }

  const TABS = [
    { id: 'brand', label: 'Brand', icon: Palette },
    { id: 'features', label: 'Features', icon: Zap },
    { id: 'limits', label: 'Limits', icon: Sliders },
    { id: 'storage', label: 'Storage', icon: Cloud },
    { id: 'security', label: 'Security', icon: Lock },

    { id: 'assignment', label: 'Assignment', icon: Users2 },
  ] as const

  return (
    <div className={insideLayout ? 'flex flex-col h-full' : 'flex h-screen flex-col'}>
      {!insideLayout && <AppHeader />}
      <div className="flex-1 overflow-auto">
        <div className="max-w-5xl mx-auto p-2 sm:p-4">

          {/* ── Top: Profile + Password side by side ── */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">

            {/* Profile Card */}
            <div className="rounded-xl border bg-card overflow-hidden">
              <SectionHeader
                icon={Shield}
                title="Profile"
                action={
                  <Button variant="ghost" size="sm" className="h-6 text-xs gap-1" onClick={() => setIsEditProfileOpen(true)}>
                    <Pencil className="h-3 w-3" />Edit
                  </Button>
                }
              />
              <div className="p-3 flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary text-sm font-bold">
                    {user?.name ? getInitials(user.name) : '?'}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold truncate">{user?.name}</p>
                    <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                    {(user as unknown as { phone?: string }).phone && (
                      <p className="text-xs text-muted-foreground truncate flex items-center gap-1 mt-0.5">
                        <Phone className="h-3 w-3 shrink-0" />
                        {(user as unknown as { phone?: string }).phone}
                      </p>
                    )}
                    {isAdmin && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-primary bg-primary/10 px-2 py-0.5 rounded-full mt-0.5">
                        <Shield className="h-2.5 w-2.5" />
                        {isSuperAdmin ? 'Super Admin' : 'Admin'}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0 sm:pl-3 sm:border-l">
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
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-muted-foreground">Current password</label>
                    <PasswordInput placeholder="Current password" autoComplete="current-password" className="h-10 text-sm" {...register('currentPassword')} />
                    {errors.currentPassword && <p className="text-[10px] text-destructive">{errors.currentPassword.message}</p>}
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-muted-foreground">New password</label>
                    <PasswordInput placeholder="New password" autoComplete="new-password" className="h-10 text-sm" {...register('newPassword')} />
                    {errors.newPassword && <p className="text-[10px] text-destructive">{errors.newPassword.message}</p>}
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-muted-foreground">Confirm password</label>
                    <PasswordInput placeholder="Confirm password" autoComplete="new-password" className="h-10 text-sm" {...register('confirmPassword')} />
                    {errors.confirmPassword && <p className="text-[10px] text-destructive">{errors.confirmPassword.message}</p>}
                  </div>
                </div>
                <Button type="submit" size="sm" className="h-9 px-4" disabled={isSubmitting}>
                  {isSubmitting && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Update Password
                </Button>
              </form>
            </div>
          </div>

          {/* ── Admin info: platform settings are managed by Super Admins ── */}
          {isAdmin && !isSuperAdmin && (
            <div className="rounded-xl border bg-muted/30 p-4 flex items-start gap-3 mb-4">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <div>
                <p className="text-sm font-semibold">Platform Configuration</p>
                <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                  Brand, features, limits, and security settings are managed by Super Admins. Contact your Super Admin if you need any platform-level changes. Subsidiaries are managed on the <strong>Brand & Storefront</strong> page.
                </p>
              </div>
            </div>
          )}

          {/* ── Super Admin Panel ── */}
          {isSuperAdmin && (
            <div className="rounded-xl border bg-card overflow-hidden mb-4">
              {/* Tabs */}
              <div className="flex border-b overflow-x-auto [&::-webkit-scrollbar]:hidden [-webkit-overflow-scrolling:touch]">
                {TABS.map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setSaTab(id)}
                    className={`shrink-0 flex items-center justify-center gap-1.5 py-3 px-3 sm:px-4 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${saTab === id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
                  >
                    <Icon className="h-3.5 w-3.5 shrink-0" />
                    <span className="hidden sm:inline">{label}</span>
                    <span className="sm:hidden text-[10px]">{label.slice(0, 4)}</span>
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
                    { name: 'mediaUpload' as const, label: 'Media Uploads', desc: 'Allow sending images and documents' },
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
                      <FieldRow label="Max Image" hint={`${bytesToMB(configData?.limits?.media?.maxSizeImage ?? 5242880)} MB current`}>
                        <div className="flex gap-2 items-center">
                          <Input type="number" min={1} className="h-8 text-sm flex-1" {...regLimits('maxSizeImage', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">bytes</span>
                        </div>
                      </FieldRow>
                    </div>
                    <div>
                      <FieldRow label="Max Document" hint={`${bytesToMB(configData?.limits?.media?.maxSizeDocument ?? 10485760)} MB current`}>
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
                      <FieldRow label="Upload Auth TTL" hint="ImageKit auth token window (60–3600 s)">
                        <div className="flex items-center gap-2">
                          <Input type="number" min={60} max={3600} className="h-8 text-sm w-24" {...regLimits('presignedUrlTTL', { valueAsNumber: true })} />
                          <span className="text-[10px] text-muted-foreground shrink-0">sec</span>
                        </div>
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

              {/* Storage Tab */}
              {saTab === 'storage' && (
                <>
                  <form onSubmit={hsStorage((d) => updateStorage.mutate(d))}>
                    <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x">
                      <div>
                        <div className="px-3 py-1.5 bg-muted/30 border-b">
                          <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">ImageKit Configuration</p>
                        </div>
                        <FieldRow label="Public Key" hint="Used for client-side uploads">
                          <Input className="h-8 text-sm w-full" {...regStorage('imagekitPublicKey')} />
                        </FieldRow>
                        <FieldRow label="URL Endpoint" hint="e.g. https://ik.imagekit.io/your_id">
                          <div className="flex flex-col w-full">
                            <Input className="h-8 text-sm w-full" {...regStorage('imagekitUrlEndpoint')} />
                            {eStorage.imagekitUrlEndpoint && <p className="text-[10px] text-destructive mt-0.5">{eStorage.imagekitUrlEndpoint.message}</p>}
                          </div>
                        </FieldRow>
                      </div>
                    </div>
                    <div className="px-3 py-2 border-t bg-muted/20 flex items-center justify-between">
                      <SaveIndicator section="storage" />
                      <Button type="submit" size="sm" disabled={sStorage || updateStorage.isPending}>
                        {(sStorage || updateStorage.isPending) && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Storage
                      </Button>
                    </div>
                  </form>

                  {/* Media Cleanup Section */}
                  <div className="border-t">
                    <div className="px-3 py-1.5 bg-muted/30 border-b">
                      <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Media Maintenance</p>
                    </div>
                    <div className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">Clean Orphaned Media</p>
                          <p className="text-[11px] text-muted-foreground mt-0.5">
                            Manually trigger cleanup of unconfirmed and orphaned media files
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => triggerMediaCleanup.mutate()}
                          disabled={triggerMediaCleanup.isPending}
                          className="gap-1.5"
                        >
                          {triggerMediaCleanup.isPending
                            ? <LeafLogo className="h-3.5 w-3.5 animate-spin" />
                            : <RefreshCw className="h-3.5 w-3.5" />}
                          Run Cleanup
                        </Button>
                      </div>
                    </div>
                  </div>
                </>
              )}


              {/* Assignment Tab */}
              {saTab === 'assignment' && (
                <div>
                  <div className="px-3 py-1.5 bg-muted/30 border-b">
                    <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Auto-Assignment Engine</p>
                  </div>

                  {!configData?.assignment ? (
                    <div className="p-6 flex items-center justify-center text-muted-foreground text-xs gap-2">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />Loading settings…
                    </div>
                  ) : (
                    <>

                  {/* How it works callout */}
                  <div className="mx-3 mt-3 flex items-start gap-2.5 rounded-lg border border-blue-200/60 dark:border-blue-800/40 bg-blue-50/60 dark:bg-blue-950/20 px-3 py-2.5">
                    <Info className="h-3.5 w-3.5 text-blue-500 shrink-0 mt-0.5" />
                    <p className="text-[11px] text-blue-700 dark:text-blue-300 leading-relaxed">
                      Conversations are auto-assigned to the least-loaded <strong>Admin</strong> who handles that subsidiary.
                      Super Admins only absorb overflow once all Admins hit the threshold below.
                      Changes apply to new assignments immediately — no restart needed.
                    </p>
                  </div>

                  <div className="divide-y">
                    {/* Max load per admin */}
                    <div className="px-3 py-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-xs font-medium">Max conversations per admin</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5">Hard cap — no admin receives more than this many active conversations.</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <button onClick={() => setAssignMaxLoad(v => Math.max(1, v - 1))}
                            className="flex h-9 w-9 items-center justify-center rounded-lg border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors text-sm font-bold">−</button>
                          <span className="w-8 text-center text-sm font-semibold tabular-nums">{assignMaxLoad}</span>
                          <button onClick={() => setAssignMaxLoad(v => Math.min(500, v + 1))}
                            className="flex h-9 w-9 items-center justify-center rounded-lg border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors text-sm font-bold">+</button>
                        </div>
                      </div>
                    </div>

                    {/* Super admin threshold */}
                    <div className="px-3 py-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-xs font-medium">Super admin overflow threshold</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5">
                            Super Admins only get assigned when <strong>all</strong> regular Admins are at or above this % of their max load.
                            Currently: {assignThreshold}% of {assignMaxLoad} = {Math.ceil(assignMaxLoad * assignThreshold / 100)} conversations.
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <button onClick={() => setAssignThreshold(v => Math.max(10, v - 5))}
                            className="flex h-9 w-9 items-center justify-center rounded-lg border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors text-sm font-bold">−</button>
                          <span className="w-10 text-center text-sm font-semibold tabular-nums">{assignThreshold}%</span>
                          <button onClick={() => setAssignThreshold(v => Math.min(100, v + 5))}
                            className="flex h-9 w-9 items-center justify-center rounded-lg border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors text-sm font-bold">+</button>
                        </div>
                      </div>
                      {/* Visual bar */}
                      <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
                        <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${assignThreshold}%` }} />
                      </div>
                    </div>

                    {/* Prefer online */}
                    <div className="px-3 py-3 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-medium">Prefer online admins</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">Always assign to an online admin first, even if they have more load than an offline one.</p>
                      </div>
                      <Switch checked={assignPreferOnline} onCheckedChange={setAssignPreferOnline} />
                    </div>
                  </div>

                  <div className="px-3 py-2 border-t bg-muted/20 flex items-center justify-between">
                    <SaveIndicator section="assignment" />
                    <Button type="button" size="sm" disabled={updateAssignment.isPending} onClick={() => updateAssignment.mutate()}>
                      {updateAssignment.isPending && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Assignment Settings
                    </Button>
                  </div>
                  </>)}
                </div>
              )}
            </div>
          )}

          {/* ── Sessions ── */}
          <div className="rounded-xl border bg-card overflow-hidden">
            <SectionHeader
              icon={Globe}
              title="Active Sessions"
              action={sessions.length > 1 ? (
                <Button variant="ghost" size="sm" className="h-6 text-xs gap-1 text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => revokeAll.mutate()} disabled={revokeAll.isPending || revokeSession.isPending}>
                  {revokeAll.isPending ? <LeafLogo className="h-3 w-3 animate-spin" /> : <LogOut className="h-3 w-3" />}Revoke others
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
                  <div key={session.id} className="flex items-center gap-3 px-3 py-3 hover:bg-muted/30 transition-colors min-h-[56px]">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted">
                      <DeviceIcon device={session.deviceInfo?.device ?? ''} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-sm font-medium truncate">{session.deviceInfo?.browser ?? 'Unknown'}</span>
                        <span className="text-xs text-muted-foreground hidden sm:inline">{session.deviceInfo?.os ?? 'Unknown'}</span>
                        {session.isCurrent && <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary shrink-0">Current</span>}
                      </div>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-0.5 flex-wrap">
                        <span className="truncate max-w-[120px] sm:max-w-none">{session.ipAddress}</span>
                        <span>·</span>
                        <span className="shrink-0">{format(parseTimestamp(session.lastActiveAt), 'MMM d, HH:mm')}</span>
                      </div>
                    </div>
                    {!session.isCurrent && (
                      <Button variant="ghost" size="icon" className="h-9 w-9 shrink-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10" onClick={() => revokeSession.mutate(session.id)} disabled={revokeSession.isPending}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* ── My Media ── */}
          <div className="rounded-xl border bg-card overflow-hidden mt-4">
            <SectionHeader
              icon={Image}
              title="My Media"
              action={
                <Button variant="ghost" size="sm" className="h-6 text-xs gap-1" onClick={() => setIsMediaOpen(true)}>
                  <Image className="h-3 w-3" />Manage
                </Button>
              }
            />
            <div className="p-3">
              <p className="text-xs text-muted-foreground">Manage your uploaded files and attachments</p>
            </div>
          </div>

        </div>
      </div>

      {/* Edit Profile Dialog */}
      <Dialog open={isEditProfileOpen} onOpenChange={setIsEditProfileOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Profile</DialogTitle>
            <DialogDescription>Update your name, email, and phone number</DialogDescription>
          </DialogHeader>
          <form onSubmit={hsProfile((d) => updateProfile.mutate(d))} className="space-y-4 pt-4">
            <div className="space-y-2">
              <label className="text-xs font-medium flex items-center gap-1">
                <User className="h-3 w-3" /> Name
              </label>
              <Input {...regProfile('name')} placeholder="Your name" />
              {eProfile.name && <p className="text-[10px] text-destructive">{eProfile.name.message}</p>}
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium flex items-center gap-1">
                <Mail className="h-3 w-3" /> Email
              </label>
              <Input type="email" {...regProfile('email')} placeholder="your@email.com" />
              {eProfile.email && <p className="text-[10px] text-destructive">{eProfile.email.message}</p>}
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium flex items-center gap-1">
                <Phone className="h-3 w-3" /> Phone <span className="text-muted-foreground">(optional)</span>
              </label>
              <Input {...regProfile('phone')} placeholder="+1 234 567 890" />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setIsEditProfileOpen(false)}>Cancel</Button>
              <Button type="submit" size="sm" disabled={sProfile || updateProfile.isPending}>
                {(sProfile || updateProfile.isPending) && <LeafLogo className="h-3.5 w-3.5 animate-spin mr-1.5" />}Save Changes
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* My Media Dialog */}
      <Dialog open={isMediaOpen} onOpenChange={setIsMediaOpen}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>My Media Files</DialogTitle>
            <DialogDescription>View and manage your uploaded files. Files attached to messages cannot be deleted.</DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-auto py-4">
            {mediaLoading ? (
              <div className="space-y-2">
                {[1, 2, 3].map(i => (
                  <div key={i} className="flex items-center gap-3 p-2">
                    <div className="h-10 w-10 rounded bg-muted animate-pulse" />
                    <div className="flex-1 space-y-1">
                      <div className="h-3 w-32 bg-muted animate-pulse rounded" />
                      <div className="h-2.5 w-20 bg-muted animate-pulse rounded" />
                    </div>
                  </div>
                ))}
              </div>
            ) : mediaData?.media && mediaData.media.length > 0 ? (
              <div className="space-y-1">
                {mediaData.media.map((item) => (
                  <div key={item.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-muted/50 group">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted shrink-0">
                      {item.type === 'IMAGE' && <FileImage className="h-5 w-5 text-blue-500" />}
                      {item.type === 'DOCUMENT' && <FileText className="h-5 w-5 text-orange-500" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{item.filename}</p>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{formatFileSize(item.size)}</span>
                        <span>·</span>
                        <span>{format(parseTimestamp(item.uploadedAt), 'MMM d, yyyy')}</span>
                        {item.messageId && <span className="text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded">Attached</span>}
                      </div>
                    </div>
                    {!item.messageId && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 opacity-100 sm:opacity-0 sm:group-hover:opacity-100"
                        onClick={() => deleteMedia.mutate(item.id)}
                        disabled={deleteMedia.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Image className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No media files found</p>
                <p className="text-xs mt-1">Files you upload will appear here</p>
              </div>
            )}
          </div>
          <div className="flex justify-end pt-2 border-t">
            <Button variant="outline" size="sm" onClick={() => setIsMediaOpen(false)}>Close</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}