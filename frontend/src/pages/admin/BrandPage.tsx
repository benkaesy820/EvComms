import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Palette, Globe, HelpCircle, Phone, Share2, FileText,
  Plus, Trash2, Check, Loader2, ChevronDown,
  Twitter, Linkedin, Instagram, Facebook, Youtube,
  Building2, Eye, ExternalLink,
  Info,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { cn } from '@/lib/utils'
import { useAppConfig } from '@/hooks/useConfig'
import { appConfig } from '@/lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from '@/components/ui/sonner'
import { useAuthStore } from '@/stores/authStore'
import type { Subsidiary } from '@/lib/schemas'

// ─── Types ────────────────────────────────────────────────────────────────────

type SectionId = 'brand' | 'subsidiaries' | 'landing' | 'contact' | 'faq' | 'social' | 'legal'

// ─── Schemas ──────────────────────────────────────────────────────────────────

const brandSchema = z.object({
  siteName: z.string().min(1, 'Required'),
  company: z.string().min(1, 'Required'),
  tagline: z.string(),
  supportEmail: z.string().email('Valid email required'),
  logoUrl: z.string().optional(),
  statResponseTime: z.string().optional(),
  statUptime: z.string().optional(),
  statAvailability: z.string().optional(),
})
const landingSchema = z.object({
  heroHeadline: z.string().max(120),
  heroSubheadline: z.string().max(300),
  ctaPrimary: z.string().max(40),
  ctaSecondary: z.string().max(40),
  showHowItWorks: z.boolean(),
  showFeatures: z.boolean(),
  showStats: z.boolean(),
})
const contactSchema = z.object({
  responseTime: z.string().max(100),
  officeHours: z.string().max(100),
  address: z.string().max(300),
  phone: z.string().max(50),
  showLiveChat: z.boolean(),
})
const socialSchema = z.object({
  twitter: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  linkedin: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  instagram: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  facebook: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  youtube: z.string().url('Must be a valid URL').optional().or(z.literal('')),
})
const legalSchema = z.object({
  companyLegalName: z.string().max(200).optional(),
  registrationNumber: z.string().max(100).optional(),
  vatNumber: z.string().max(100).optional(),
  termsLastUpdated: z.string().optional(),
  privacyLastUpdated: z.string().optional(),
})

type BrandInput = z.infer<typeof brandSchema>
type LandingInput = z.infer<typeof landingSchema>
type ContactInput = z.infer<typeof contactSchema>
type SocialInput = z.infer<typeof socialSchema>
type LegalInput = z.infer<typeof legalSchema>

// ─── Nav config ───────────────────────────────────────────────────────────────

const SECTIONS: { id: SectionId; label: string; icon: typeof Palette; description: string; group: string }[] = [
  { id: 'brand',        label: 'Brand Identity',    icon: Palette,     description: 'Name, logo, tagline, email',          group: 'Identity' },
  { id: 'subsidiaries', label: 'Subsidiaries',       icon: Building2,   description: 'Business units & divisions',          group: 'Identity' },
  { id: 'landing',      label: 'Landing Page',       icon: Globe,       description: 'Hero copy, CTAs, section toggles',    group: 'Storefront' },
  { id: 'contact',      label: 'Contact',            icon: Phone,       description: 'Hours, address, response time',        group: 'Storefront' },
  { id: 'faq',          label: 'FAQ',                icon: HelpCircle,  description: 'Questions shown on /faq',             group: 'Storefront' },
  { id: 'social',       label: 'Social Links',       icon: Share2,      description: 'Twitter, LinkedIn and more',          group: 'Storefront' },
  { id: 'legal',        label: 'Legal',              icon: FileText,    description: 'Registration, VAT, policy dates',     group: 'Storefront' },
]

// ─── Shared UI primitives ─────────────────────────────────────────────────────

function SavedPill() {
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-full px-2 py-0.5 animate-in fade-in slide-in-from-top-1 duration-300">
      <Check className="h-2.5 w-2.5" /> Saved
    </span>
  )
}

function SectionShell({ icon: Icon, title, description, saved, color = 'primary', children, footer }: {
  icon: typeof Palette
  title: string
  description: string
  saved: boolean
  color?: string
  children: React.ReactNode
  footer: React.ReactNode
}) {
  return (
    <div className="space-y-4">
      {/* Section hero */}
      <div className="flex items-start gap-3">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-${color}/10`}>
          <Icon className={`h-5 w-5 text-${color}`} />
        </div>
        <div className="flex-1 min-w-0 pt-0.5">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h2 className="text-lg font-bold tracking-tight">{title}</h2>
            {saved && <SavedPill />}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
        </div>
      </div>

      <div className="space-y-3">{children}</div>

      <div className="flex justify-end pt-3 border-t">{footer}</div>
    </div>
  )
}

function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border bg-card overflow-hidden">
      {title && (
        <div className="px-4 py-2.5 border-b bg-muted/30">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">{title}</p>
        </div>
      )}
      <div className="divide-y divide-border/50">{children}</div>
    </div>
  )
}

function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-4 px-4 py-3">
      <div className="sm:w-48 shrink-0">
        <p className="text-sm font-medium">{label}</p>
        {hint && <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{hint}</p>}
        {error && <p className="text-[11px] text-destructive mt-0.5">{error}</p>}
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  )
}

function ToggleField({ label, hint, checked, onChange }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <div>
        <p className="text-sm font-medium">{label}</p>
        {hint && <p className="text-[11px] text-muted-foreground mt-0.5">{hint}</p>}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  )
}

function SaveButton({ pending }: { pending: boolean }) {
  return (
    <Button type="submit" size="sm" disabled={pending} className="gap-2 px-5 h-9">
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
      Save changes
    </Button>
  )
}

// ─── Brand Section ────────────────────────────────────────────────────────────

function BrandSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<BrandInput>({
    resolver: zodResolver(brandSchema),
    defaultValues: { siteName: '', company: '', tagline: '', supportEmail: '', logoUrl: '', statResponseTime: '', statUptime: '', statAvailability: '' },
  })
  useEffect(() => {
    if (data?.brand) reset({ siteName: data.brand.siteName || '', company: data.brand.company || '', tagline: data.brand.tagline || '', supportEmail: data.brand.supportEmail || '', logoUrl: data.brand.logoUrl || '', statResponseTime: data.brand.statResponseTime || '', statUptime: data.brand.statUptime || '', statAvailability: data.brand.statAvailability || '' })
  }, [data?.brand, reset])
  const mut = useMutation({ mutationFn: (d: BrandInput) => appConfig.updateBrand(d), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Brand saved') }, onError: () => toast.error('Failed to save') })

  return (
    <form onSubmit={handleSubmit(d => mut.mutate(d))}>
      <SectionShell icon={Palette} title="Brand Identity" description="Core identity shown across every page of the platform" saved={saved} footer={<SaveButton pending={isSubmitting || mut.isPending} />}>

        <Card title="Core Details">
          <Field label="Site Name" hint="Shown in browser tab, sidebar header, and emails" error={errors.siteName?.message}>
            <Input className="h-10" placeholder="My Business" {...register('siteName')} />
          </Field>
          <Field label="Company" hint="Full legal or brand name used in page copy and emails" error={errors.company?.message}>
            <Input className="h-10" placeholder="My Company Ltd." {...register('company')} />
          </Field>
          <Field label="Tagline" hint="Short slogan — shown as the hero headline on the landing page">
            <Input className="h-10" placeholder="Support that actually feels human." {...register('tagline')} />
          </Field>
          <Field label="Support Email" hint="Displayed on the Contact page and included in outbound emails" error={errors.supportEmail?.message}>
            <Input type="email" className="h-10" placeholder="support@company.com" {...register('supportEmail')} />
          </Field>
          <Field label="Logo URL" hint="Paste a publicly-accessible URL to your logo image (PNG, SVG)">
            <div className="flex gap-2">
              <Input className="h-10 font-mono text-xs flex-1" placeholder="https://your-cdn.com/logo.png" {...register('logoUrl')} />
            </div>
          </Field>
        </Card>

        <Card title="Stats Bar  —  shown on the landing page">
          <Field label="Response Time" hint='E.g. "Under 2 hrs" or "Same day"'>
            <Input className="h-10" placeholder="< 2 hrs" {...register('statResponseTime')} />
          </Field>
          <Field label="Uptime" hint='E.g. "99.9%" — leave blank to hide'>
            <Input className="h-10" placeholder="99.9%" {...register('statUptime')} />
          </Field>
          <Field label="Availability" hint='E.g. "24/7" or "Mon–Fri"'>
            <Input className="h-10" placeholder="24/7" {...register('statAvailability')} />
          </Field>
        </Card>

      </SectionShell>
    </form>
  )
}

// ─── Subsidiaries Section ─────────────────────────────────────────────────────

function SubsidiariesSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const [subs, setSubs] = useState<Subsidiary[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => { if (data?.subsidiaries) setSubs(data.subsidiaries) }, [data?.subsidiaries])

  const mut = useMutation({
    mutationFn: (s: Subsidiary[]) => appConfig.updateSubsidiaries(s),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Subsidiaries saved') },
    onError: () => toast.error('Failed to save'),
  })

  const addSub = () => {
    const id = `sub_${Date.now()}`
    setSubs(p => [...p, { id, name: '' }])
    setExpanded(id)
  }
  const update = (id: string, field: keyof Subsidiary, value: string) => setSubs(p => p.map(s => s.id === id ? { ...s, [field]: value } : s))
  const remove = (id: string) => { setSubs(p => p.filter(s => s.id !== id)); if (expanded === id) setExpanded(null) }

  const handleSave = () => {
    const invalid = subs.some(s => !s.name.trim())
    if (invalid) { toast.error('Every subsidiary must have a name'); return }
    const normaliseUrl = (raw = '') => { const t = raw.trim(); return t && !t.includes('://') ? `https://${t}` : t }
    const cleaned = subs.map(s => ({
      id: s.id, name: s.name.trim(),
      ...(s.description?.trim() ? { description: s.description.trim() } : {}),
      ...(s.url?.trim() ? { url: normaliseUrl(s.url) } : {}),
      ...(s.industry?.trim() ? { industry: s.industry.trim() } : {}),
      ...(s.founded?.trim() ? { founded: s.founded.trim() } : {}),
    }))
    mut.mutate(cleaned)
  }

  return (
    <SectionShell
      icon={Building2}
      title="Subsidiaries"
      description="Business units or divisions — users can select these when starting a conversation"
      saved={saved}
      footer={
        <div className="flex items-center gap-3">
          <Button type="button" variant="outline" size="sm" className="gap-2" onClick={addSub}>
            <Plus className="h-3.5 w-3.5" /> Add Subsidiary
          </Button>
          <Button size="sm" className="gap-2 px-5 h-9" disabled={mut.isPending} onClick={handleSave}>
            {mut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Save changes
          </Button>
        </div>
      }
    >
      {subs.length === 0 ? (
        <div className="rounded-2xl border-2 border-dashed bg-muted/10 py-14 flex flex-col items-center gap-3 text-muted-foreground">
          <Building2 className="h-10 w-10 opacity-20" />
          <div className="text-center">
            <p className="text-sm font-medium">No subsidiaries yet</p>
            <p className="text-xs mt-1">Add your first business unit or division below.</p>
          </div>
          <Button variant="outline" size="sm" className="gap-2 mt-2" onClick={addSub}>
            <Plus className="h-3.5 w-3.5" /> Add Subsidiary
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {subs.map((sub) => {
            const isOpen = expanded === sub.id
            const isEmpty = !sub.name.trim()
            return (
              <div key={sub.id} className={cn('rounded-2xl border bg-card overflow-hidden transition-all', isEmpty && isOpen && 'border-amber-300 dark:border-amber-700')}>
                {/* Card header */}
                <div className="flex items-center gap-3 px-4 py-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary font-bold text-sm">
                    {sub.name ? sub.name.charAt(0).toUpperCase() : <Building2 className="h-4 w-4 opacity-50" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={cn('text-sm font-semibold truncate', !sub.name && 'text-muted-foreground italic')}>
                      {sub.name || 'Unnamed subsidiary'}
                    </p>
                    {sub.industry || sub.url ? (
                      <p className="text-[11px] text-muted-foreground truncate mt-0.5">
                        {[sub.industry, sub.url].filter(Boolean).join(' · ')}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {sub.url && (
                      <a href={sub.url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                        className="p-1.5 rounded-lg text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors">
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    )}
                    <button
                      type="button"
                      onClick={() => remove(sub.id)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => setExpanded(isOpen ? null : sub.id)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
                    >
                      <ChevronDown className={cn('h-4 w-4 transition-transform duration-200', isOpen && 'rotate-180')} />
                    </button>
                  </div>
                </div>

                {/* Expanded fields */}
                {isOpen && (
                  <div className="border-t bg-muted/20 px-4 py-3 space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Name *</Label>
                      <Input
                        className="h-10"
                        placeholder="Subsidiary name"
                        value={sub.name}
                        onChange={e => update(sub.id, 'name', e.target.value)}
                      />
                      {isEmpty && <p className="text-[11px] text-amber-600">Name is required</p>}
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Description</Label>
                      <Textarea
                        className="resize-none text-sm"
                        rows={2}
                        placeholder="What this business unit does..."
                        value={sub.description ?? ''}
                        onChange={e => update(sub.id, 'description', e.target.value)}
                      />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Website URL</Label>
                        <Input className="h-10 font-mono text-xs" placeholder="https://..." value={sub.url ?? ''} onChange={e => update(sub.id, 'url', e.target.value)} />
                      </div>
                      <div className="space-y-1.5">
                        <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Industry</Label>
                        <Input className="h-10" placeholder="E.g. Technology" value={sub.industry ?? ''} onChange={e => update(sub.id, 'industry', e.target.value)} />
                      </div>
                      <div className="space-y-1.5">
                        <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Founded Year</Label>
                        <Input className="h-10" placeholder="2020" value={sub.founded ?? ''} onChange={e => update(sub.id, 'founded', e.target.value)} />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {subs.length > 0 && (
        <div className="rounded-xl border bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800/50 p-3 flex items-start gap-2.5">
          <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
          <p className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed">
            Users see these as options when starting a new conversation. Each subsidiary can have its own dedicated support workflow.
          </p>
        </div>
      )}
    </SectionShell>
  )
}

// ─── Landing Section ──────────────────────────────────────────────────────────

function LandingSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const { register, handleSubmit, reset, watch, setValue, formState: { isSubmitting } } = useForm<LandingInput>({
    resolver: zodResolver(landingSchema),
    defaultValues: { heroHeadline: '', heroSubheadline: '', ctaPrimary: 'Get Started Free', ctaSecondary: 'Sign In', showHowItWorks: true, showFeatures: true, showStats: true },
  })
  useEffect(() => {
    const l = data?.storefront?.landing
    if (l) reset({ heroHeadline: l.heroHeadline || '', heroSubheadline: l.heroSubheadline || '', ctaPrimary: l.ctaPrimary || 'Get Started Free', ctaSecondary: l.ctaSecondary || 'Sign In', showHowItWorks: l.showHowItWorks !== false, showFeatures: l.showFeatures !== false, showStats: l.showStats !== false })
  }, [data?.storefront?.landing, reset])
  const mut = useMutation({ mutationFn: (d: LandingInput) => appConfig.updateStorefront({ landing: d }), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Landing page saved') }, onError: () => toast.error('Failed to save') })

  return (
    <form onSubmit={handleSubmit(d => mut.mutate(d))}>
      <SectionShell icon={Globe} title="Landing Page" description="Public homepage — what visitors see before they log in" saved={saved} footer={<SaveButton pending={isSubmitting || mut.isPending} />}>

        <Card title="Hero Copy">
          <Field label="Headline" hint="Main headline text — keep it punchy (max 120 chars)">
            <Input className="h-10" placeholder="Support that actually feels human." {...register('heroHeadline')} />
          </Field>
          <Field label="Subheadline" hint="Supporting paragraph below the headline">
            <Textarea className="resize-none text-sm" rows={3} placeholder="Get a direct line to your support team..." {...register('heroSubheadline')} />
          </Field>
          <Field label="Primary CTA" hint='Text on the main action button ("Get Started Free")'>
            <Input className="h-10" placeholder="Get Started Free" {...register('ctaPrimary')} />
          </Field>
          <Field label="Secondary CTA" hint='Text on the secondary button ("Sign In")'>
            <Input className="h-10" placeholder="Sign In" {...register('ctaSecondary')} />
          </Field>
        </Card>

        <Card title="Visible Sections">
          <ToggleField label="Stats Bar" hint="Response time, uptime, and availability numbers" checked={watch('showStats')} onChange={v => setValue('showStats', v)} />
          <ToggleField label="How It Works" hint="Step-by-step walkthrough of the registration process" checked={watch('showHowItWorks')} onChange={v => setValue('showHowItWorks', v)} />
          <ToggleField label="Features Grid" hint="Six feature cards highlighting platform capabilities" checked={watch('showFeatures')} onChange={v => setValue('showFeatures', v)} />
        </Card>

      </SectionShell>
    </form>
  )
}

// ─── Contact Section ──────────────────────────────────────────────────────────

function ContactSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const { register, handleSubmit, reset, watch, setValue, formState: { isSubmitting } } = useForm<ContactInput>({
    resolver: zodResolver(contactSchema),
    defaultValues: { responseTime: 'Typically within 1–24 hours', officeHours: '', address: '', phone: '', showLiveChat: true },
  })
  useEffect(() => {
    const c = data?.storefront?.contact
    if (c) reset({ responseTime: c.responseTime || '', officeHours: c.officeHours || '', address: c.address || '', phone: c.phone || '', showLiveChat: c.showLiveChat !== false })
  }, [data?.storefront?.contact, reset])
  const mut = useMutation({ mutationFn: (d: ContactInput) => appConfig.updateStorefront({ contact: d }), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Contact saved') }, onError: () => toast.error('Failed to save') })

  return (
    <form onSubmit={handleSubmit(d => mut.mutate(d))}>
      <SectionShell icon={Phone} title="Contact" description="Information shown on the public /contact page" saved={saved} footer={<SaveButton pending={isSubmitting || mut.isPending} />}>
        <Card title="Details">
          <Field label="Response Time" hint='Displayed under "Response Time" card e.g. "Within 24 hours"'>
            <Input className="h-10" {...register('responseTime')} />
          </Field>
          <Field label="Office Hours" hint='Optional e.g. "Monday – Friday, 9 AM – 6 PM"'>
            <Input className="h-10" placeholder="Monday – Friday, 9 AM – 6 PM" {...register('officeHours')} />
          </Field>
          <Field label="Phone" hint="Optional — shown as a clickable phone link">
            <Input className="h-10 font-mono" placeholder="+1 234 567 890" {...register('phone')} />
          </Field>
          <Field label="Address" hint="Office address — shown as a non-clickable info card">
            <Textarea className="resize-none text-sm font-mono" rows={3} placeholder={"123 Main St\nCity, Country"} {...register('address')} />
          </Field>
        </Card>
        <Card title="Options">
          <ToggleField label="Show Live Chat card" hint="Displays a direct link to the support chat on the contact page" checked={watch('showLiveChat')} onChange={v => setValue('showLiveChat', v)} />
        </Card>
      </SectionShell>
    </form>
  )
}

// ─── FAQ Section ──────────────────────────────────────────────────────────────

type FaqItem = { id: string; question: string; answer: string }

function FAQSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const [items, setItems] = useState<FaqItem[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    if (data?.storefront?.faq) setItems(data.storefront.faq.map(f => ({ id: f.id, question: f.question, answer: f.answer })))
  }, [data?.storefront?.faq])

  const mut = useMutation({
    mutationFn: (f: FaqItem[]) => appConfig.updateStorefront({ faq: f }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('FAQ saved') },
    onError: () => toast.error('Failed to save'),
  })

  const update = (id: string, field: keyof FaqItem, value: string) => {
    setItems(p => p.map(i => i.id === id ? { ...i, [field]: value } : i))
    setErrors(p => { const n = { ...p }; delete n[`${id}_${field}`]; return n })
  }

  const handleSave = () => {
    const errs: Record<string, string> = {}
    items.forEach(i => {
      if (!i.question.trim()) errs[`${i.id}_question`] = 'Required'
      if (!i.answer.trim()) errs[`${i.id}_answer`] = 'Required'
    })
    if (Object.keys(errs).length) { setErrors(errs); toast.error('Fill in all questions and answers'); return }
    mut.mutate(items)
  }

  const addItem = () => {
    const id = `faq_${Date.now()}`
    setItems(p => [...p, { id, question: '', answer: '' }])
    setExpanded(id)
  }

  return (
    <SectionShell
      icon={HelpCircle}
      title="FAQ"
      description={`${items.length} question${items.length !== 1 ? 's' : ''} — shown publicly on /faq`}
      saved={saved}
      footer={
        <div className="flex items-center gap-3">
          <Button type="button" variant="outline" size="sm" className="gap-2" onClick={addItem}>
            <Plus className="h-3.5 w-3.5" /> Add Question
          </Button>
          <Button size="sm" className="gap-2 px-5 h-9" disabled={mut.isPending} onClick={handleSave}>
            {mut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Save FAQ
          </Button>
        </div>
      }
    >
      {items.length === 0 ? (
        <div className="rounded-2xl border-2 border-dashed bg-muted/10 py-14 flex flex-col items-center gap-3 text-muted-foreground">
          <HelpCircle className="h-10 w-10 opacity-20" />
          <div className="text-center">
            <p className="text-sm font-medium">No FAQ items yet</p>
            <p className="text-xs mt-1">Add questions and answers that will appear on the /faq page.</p>
          </div>
          <Button variant="outline" size="sm" className="gap-2 mt-2" onClick={addItem}>
            <Plus className="h-3.5 w-3.5" /> Add Question
          </Button>
        </div>
      ) : (
        <div className="space-y-2">
          {items.map((item, idx) => {
            const isOpen = expanded === item.id
            const hasError = errors[`${item.id}_question`] || errors[`${item.id}_answer`]
            return (
              <div key={item.id} className={cn('rounded-2xl border bg-card overflow-hidden', hasError && 'border-destructive/40')}>
                <div className="flex items-center gap-3 px-4 py-3">
                  <span className="text-xs font-bold text-muted-foreground w-5 shrink-0 text-center">{idx + 1}</span>
                  <button
                    type="button"
                    className="flex-1 text-left min-w-0 cursor-pointer"
                    onClick={() => setExpanded(isOpen ? null : item.id)}
                  >
                    <p className={cn('text-sm font-medium truncate', !item.question && 'text-muted-foreground italic')}>
                      {item.question || 'Untitled question'}
                    </p>
                    {item.answer && !isOpen && (
                      <p className="text-[11px] text-muted-foreground truncate mt-0.5">{item.answer}</p>
                    )}
                  </button>
                  <div className="flex items-center gap-1 shrink-0">
                    <button type="button" onClick={() => { setItems(p => p.filter(i => i.id !== item.id)); if (expanded === item.id) setExpanded(null) }}
                      className="p-1.5 rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors cursor-pointer">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                    <button type="button" onClick={() => setExpanded(isOpen ? null : item.id)}
                      className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted transition-colors cursor-pointer">
                      <ChevronDown className={cn('h-4 w-4 transition-transform', isOpen && 'rotate-180')} />
                    </button>
                  </div>
                </div>
                {isOpen && (
                  <div className="border-t bg-muted/20 px-4 py-3 space-y-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Question</Label>
                      <Input className="h-10" placeholder="How do I...?" value={item.question} onChange={e => update(item.id, 'question', e.target.value)} />
                      {errors[`${item.id}_question`] && <p className="text-[11px] text-destructive">{errors[`${item.id}_question`]}</p>}
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Answer</Label>
                      <Textarea className="resize-none text-sm" rows={4} placeholder="The answer to this question..." value={item.answer} onChange={e => update(item.id, 'answer', e.target.value)} />
                      {errors[`${item.id}_answer`] && <p className="text-[11px] text-destructive">{errors[`${item.id}_answer`]}</p>}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </SectionShell>
  )
}

// ─── Social Section ───────────────────────────────────────────────────────────

function SocialSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<SocialInput>({
    resolver: zodResolver(socialSchema),
    defaultValues: { twitter: '', linkedin: '', instagram: '', facebook: '', youtube: '' },
  })
  useEffect(() => {
    const s = data?.storefront?.social
    if (s) reset({ twitter: s.twitter || '', linkedin: s.linkedin || '', instagram: s.instagram || '', facebook: s.facebook || '', youtube: s.youtube || '' })
  }, [data?.storefront?.social, reset])
  const mut = useMutation({ mutationFn: (d: SocialInput) => appConfig.updateStorefront({ social: d }), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Social links saved') }, onError: () => toast.error('Failed to save') })

  const socials = [
    { field: 'twitter' as const,   label: 'Twitter / X', Icon: Twitter,  placeholder: 'https://twitter.com/yourhandle', color: 'text-sky-500' },
    { field: 'linkedin' as const,  label: 'LinkedIn',    Icon: Linkedin,  placeholder: 'https://linkedin.com/company/...', color: 'text-blue-600' },
    { field: 'instagram' as const, label: 'Instagram',   Icon: Instagram, placeholder: 'https://instagram.com/yourhandle', color: 'text-pink-500' },
    { field: 'facebook' as const,  label: 'Facebook',    Icon: Facebook,  placeholder: 'https://facebook.com/yourpage', color: 'text-blue-500' },
    { field: 'youtube' as const,   label: 'YouTube',     Icon: Youtube,   placeholder: 'https://youtube.com/@yourchannel', color: 'text-red-500' },
  ]

  return (
    <form onSubmit={handleSubmit(d => mut.mutate(d))}>
      <SectionShell icon={Share2} title="Social Links" description="Displayed on the /contact page when filled in" saved={saved} footer={<SaveButton pending={isSubmitting || mut.isPending} />}>
        <Card>
          {socials.map(({ field, label, Icon, placeholder, color }) => (
            <Field key={field} label={label} error={errors[field]?.message}>
              <div className="relative">
                <Icon className={cn('absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4', color)} />
                <Input className="h-10 pl-9 font-mono text-xs" placeholder={placeholder} {...register(field)} />
              </div>
            </Field>
          ))}
        </Card>
      </SectionShell>
    </form>
  )
}

// ─── Legal Section ────────────────────────────────────────────────────────────

function LegalSection({ saved, onSave }: { saved: boolean; onSave: () => void }) {
  const { data } = useAppConfig()
  const queryClient = useQueryClient()
  const { register, handleSubmit, reset, formState: { isSubmitting } } = useForm<LegalInput>({
    resolver: zodResolver(legalSchema),
    defaultValues: { companyLegalName: '', registrationNumber: '', vatNumber: '', termsLastUpdated: '', privacyLastUpdated: '' },
  })
  useEffect(() => {
    const l = data?.storefront?.legal
    if (l) reset({ companyLegalName: l.companyLegalName || '', registrationNumber: l.registrationNumber || '', vatNumber: l.vatNumber || '', termsLastUpdated: l.termsLastUpdated || '', privacyLastUpdated: l.privacyLastUpdated || '' })
  }, [data?.storefront?.legal, reset])
  const mut = useMutation({ mutationFn: (d: LegalInput) => appConfig.updateStorefront({ legal: d }), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['appConfig'] }); onSave(); toast.success('Legal details saved') }, onError: () => toast.error('Failed to save') })

  return (
    <form onSubmit={handleSubmit(d => mut.mutate(d))}>
      <SectionShell icon={FileText} title="Legal" description="Company registration details and policy update dates" saved={saved} footer={<SaveButton pending={isSubmitting || mut.isPending} />}>
        <Card title="Company Details">
          <Field label="Legal Name" hint="Full registered company name">
            <Input className="h-10" placeholder="Ev Network Ltd." {...register('companyLegalName')} />
          </Field>
          <Field label="Company No." hint="Companies House or equivalent registration number">
            <Input className="h-10 font-mono" placeholder="12345678" {...register('registrationNumber')} />
          </Field>
          <Field label="VAT Number" hint="Tax / VAT registration number">
            <Input className="h-10 font-mono" placeholder="GB123456789" {...register('vatNumber')} />
          </Field>
        </Card>
        <Card title="Policy Dates">
          <Field label="Terms Updated" hint="Shown in the footer of /terms">
            <Input type="date" className="h-10 w-48" {...register('termsLastUpdated')} />
          </Field>
          <Field label="Privacy Updated" hint="Shown in the footer of /privacy">
            <Input type="date" className="h-10 w-48" {...register('privacyLastUpdated')} />
          </Field>
        </Card>
      </SectionShell>
    </form>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function BrandPage() {
  const user = useAuthStore(s => s.user)
  const isSuperAdmin = user?.role === 'SUPER_ADMIN'
  const [active, setActive] = useState<SectionId>('brand')
  const [savedSet, setSavedSet] = useState<Set<SectionId>>(new Set())

  const markSaved = (id: SectionId) => {
    setSavedSet(p => new Set(p).add(id))
    setTimeout(() => setSavedSet(p => { const n = new Set(p); n.delete(id); return n }), 3000)
  }

  if (!isSuperAdmin) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="text-center text-muted-foreground">
          <Palette className="h-12 w-12 mx-auto mb-3 opacity-20" />
          <p className="font-medium">Super Admin access required</p>
          <p className="text-sm mt-1">Brand & Storefront settings can only be managed by Super Admins.</p>
        </div>
      </div>
    )
  }

  // Group sections for nav
  const groups = ['Identity', 'Storefront']

  const renderSection = () => {
    const props = { saved: savedSet.has(active), onSave: () => markSaved(active) }
    switch (active) {
      case 'brand':        return <BrandSection {...props} />
      case 'subsidiaries': return <SubsidiariesSection {...props} />
      case 'landing':      return <LandingSection {...props} />
      case 'contact':      return <ContactSection {...props} />
      case 'faq':          return <FAQSection {...props} />
      case 'social':       return <SocialSection {...props} />
      case 'legal':        return <LegalSection {...props} />
    }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden bg-background">

      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 shrink-0">
          <Palette className="h-4.5 w-4.5 text-primary" />
        </div>
        <div className="flex-1 min-w-0">
          <h1 className="text-sm font-bold leading-none">Brand & Storefront</h1>
          <p className="text-[11px] text-muted-foreground mt-0.5">Manage your public-facing content and identity</p>
        </div>
        <a href="/" target="_blank" rel="noopener noreferrer" title="Opens the live public landing page">
          <Button variant="outline" size="sm" className="gap-1.5 text-xs">
            <Eye className="h-3.5 w-3.5" /> Preview Site
          </Button>
        </a>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* Sidebar */}
        <aside className="hidden sm:flex flex-col w-60 shrink-0 border-r bg-muted/10 overflow-y-auto">
          <div className="p-2 space-y-4">
            {groups.map(group => {
              const groupItems = SECTIONS.filter(s => s.group === group)
              return (
                <div key={group}>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/60 px-3 mb-1.5">{group}</p>
                  <div className="space-y-0.5">
                    {groupItems.map(s => {
                      const isActive = active === s.id
                      const isSaved = savedSet.has(s.id)
                      return (
                        <button
                          key={s.id}
                          onClick={() => setActive(s.id)}
                          className={cn(
                            'w-full flex items-start gap-3 px-3 py-2.5 rounded-xl text-left transition-all cursor-pointer group',
                            isActive ? 'bg-primary text-primary-foreground shadow-sm' : 'hover:bg-accent text-foreground'
                          )}
                        >
                          <s.icon className={cn('h-4 w-4 shrink-0 mt-0.5', isActive ? 'text-primary-foreground' : 'text-muted-foreground group-hover:text-foreground')} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className={cn('text-sm font-medium truncate', isActive ? 'text-primary-foreground' : '')}>{s.label}</span>
                              {isSaved && <span className="h-1.5 w-1.5 rounded-full bg-green-400 shrink-0" />}
                            </div>
                            <p className={cn('text-[10px] mt-0.5 truncate', isActive ? 'text-primary-foreground/70' : 'text-muted-foreground')}>{s.description}</p>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        </aside>

        {/* Mobile top nav */}
        <div className="sm:hidden fixed bottom-[calc(60px+env(safe-area-inset-bottom))] left-0 right-0 z-40 bg-background border-t overflow-x-auto flex gap-1 p-2">
          {SECTIONS.map(s => (
            <button key={s.id} onClick={() => setActive(s.id)}
              className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer',
                active === s.id ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground hover:bg-accent'
              )}>
              <s.icon className="h-3.5 w-3.5" />{s.label}
              {savedSet.has(s.id) && <span className="h-1.5 w-1.5 rounded-full bg-green-400" />}
            </button>
          ))}
        </div>

        {/* Content */}
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-3xl mx-auto px-4 sm:px-6 py-5 pb-32 sm:pb-6">
            {renderSection()}
          </div>
        </main>

      </div>
    </div>
  )
}
