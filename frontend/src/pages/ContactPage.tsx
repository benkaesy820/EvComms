import { useNavigate } from 'react-router-dom'
import { Mail, MessageSquare, HelpCircle, Clock, ArrowRight, MapPin, Phone, Twitter, Linkedin, Instagram, Facebook, Youtube } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { useAuthStore } from '@/stores/authStore'
import { useAppConfig } from '@/hooks/useConfig'

export function ContactPage() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const { data } = useAppConfig()
  const supportEmail = data?.brand?.supportEmail
  const contact = data?.storefront?.contact
  const social = data?.storefront?.social
  const responseTime = contact?.responseTime || 'Typically within 1–24 hours'
  const officeHours = contact?.officeHours
  const address = contact?.address
  const phone = contact?.phone
  const showLiveChat = contact?.showLiveChat !== false

  const hasSocial = social && (social.twitter || social.linkedin || social.instagram || social.facebook || social.youtube)

  return (
    <StaticLayout>
      <div className="mx-auto w-full max-w-2xl px-4 py-12 sm:px-6 sm:py-16">
        {/* Page header */}
        <div className="mb-10">
          <p className="text-xs font-bold uppercase tracking-widest text-primary mb-2">Get in touch</p>
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">Contact Us</h1>
          <p className="text-muted-foreground">
            We're here to help. Choose the option that works best for you.
          </p>
        </div>

        {/* Primary contact options */}
        <div className="grid sm:grid-cols-2 gap-4 mb-8">
          {supportEmail && (
            <a
              href={`mailto:${supportEmail}`}
              className="group flex flex-col gap-3 rounded-2xl border bg-card p-6 hover:border-primary/30 hover:shadow-md hover:shadow-primary/5 transition-all cursor-pointer"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary group-hover:bg-primary/15 transition-colors">
                <Mail className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold mb-0.5">Email Support</p>
                <p className="text-sm text-muted-foreground mb-3">{supportEmail}</p>
                <p className="text-xs text-muted-foreground">We respond to all emails within 24 hours, usually much faster.</p>
              </div>
              <span className="mt-auto text-xs font-semibold text-primary flex items-center gap-1 group-hover:gap-2 transition-all">
                Send email <ArrowRight className="h-3.5 w-3.5" />
              </span>
            </a>
          )}

          {showLiveChat && (!user || user.role === 'USER') && (
            <div
              className="group flex flex-col gap-3 rounded-2xl border bg-card p-6 hover:border-primary/30 hover:shadow-md hover:shadow-primary/5 transition-all cursor-pointer"
              onClick={() => user ? navigate('/home/chat') : navigate('/login')}
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary group-hover:bg-primary/15 transition-colors">
                <MessageSquare className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold mb-0.5">Live Chat</p>
                <p className="text-sm text-muted-foreground mb-3">Real-time messaging with our team</p>
                <p className="text-xs text-muted-foreground">
                  {user ? 'Pick up where you left off.' : 'Sign in to start a conversation with our support team.'}
                </p>
              </div>
              <span className="mt-auto text-xs font-semibold text-primary flex items-center gap-1 group-hover:gap-2 transition-all">
                {user ? 'Go to chat' : 'Sign in to chat'} <ArrowRight className="h-3.5 w-3.5" />
              </span>
            </div>
          )}

          {/* Phone */}
          {phone && (
            <a
              href={`tel:${phone}`}
              className="group flex flex-col gap-3 rounded-2xl border bg-card p-6 hover:border-primary/30 hover:shadow-md transition-all cursor-pointer"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                <Phone className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold mb-0.5">Phone</p>
                <p className="text-sm text-muted-foreground">{phone}</p>
              </div>
            </a>
          )}

          {/* Address */}
          {address && (
            <div className="flex flex-col gap-3 rounded-2xl border bg-card p-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                <MapPin className="h-5 w-5" />
              </div>
              <div>
                <p className="font-semibold mb-0.5">Office</p>
                <p className="text-sm text-muted-foreground whitespace-pre-line">{address}</p>
              </div>
            </div>
          )}
        </div>

        {/* Divider */}
        <div className="relative my-8">
          <div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div>
          <div className="relative flex justify-center"><span className="bg-background px-3 text-xs text-muted-foreground">Before you reach out</span></div>
        </div>

        {/* Secondary options */}
        <div className="grid sm:grid-cols-2 gap-3">
          <Link to="/faq" className="group flex items-start gap-4 rounded-xl border bg-muted/30 p-4 hover:bg-accent/50 transition-colors cursor-pointer">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-background border">
              <HelpCircle className="h-4 w-4 text-muted-foreground" />
            </div>
            <div>
              <p className="text-sm font-semibold">Browse our FAQ</p>
              <p className="text-xs text-muted-foreground mt-0.5">Answers to the most common questions</p>
            </div>
          </Link>

          <div className="flex items-start gap-4 rounded-xl border bg-muted/30 p-4">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-background border">
              <Clock className="h-4 w-4 text-muted-foreground" />
            </div>
            <div>
              <p className="text-sm font-semibold">Response Time</p>
              <p className="text-xs text-muted-foreground mt-0.5">{responseTime}</p>
              {officeHours && <p className="text-xs text-muted-foreground mt-0.5">{officeHours}</p>}
            </div>
          </div>
        </div>

        {/* Social links */}
        {hasSocial && (
          <div className="mt-8 rounded-xl border bg-muted/20 p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Follow us</p>
            <div className="flex flex-wrap gap-3">
              {social?.twitter && (
                <a href={social.twitter} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors cursor-pointer">
                  <Twitter className="h-3.5 w-3.5" /> Twitter
                </a>
              )}
              {social?.linkedin && (
                <a href={social.linkedin} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors cursor-pointer">
                  <Linkedin className="h-3.5 w-3.5" /> LinkedIn
                </a>
              )}
              {social?.instagram && (
                <a href={social.instagram} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors cursor-pointer">
                  <Instagram className="h-3.5 w-3.5" /> Instagram
                </a>
              )}
              {social?.facebook && (
                <a href={social.facebook} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors cursor-pointer">
                  <Facebook className="h-3.5 w-3.5" /> Facebook
                </a>
              )}
              {social?.youtube && (
                <a href={social.youtube} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs font-medium hover:bg-muted transition-colors cursor-pointer">
                  <Youtube className="h-3.5 w-3.5" /> YouTube
                </a>
              )}
            </div>
          </div>
        )}

        {/* Not registered yet */}
        {!user && (
          <div className="mt-10 rounded-2xl border bg-primary/5 border-primary/20 p-6 flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <div className="flex-1">
              <p className="text-sm font-semibold">Don't have an account yet?</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Create a free account to access our full support chat — no credit card required.
              </p>
            </div>
            <Button size="sm" className="rounded-full px-5 shrink-0 gap-1.5" onClick={() => navigate('/register')}>
              Get started <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}
      </div>
    </StaticLayout>
  )
}
