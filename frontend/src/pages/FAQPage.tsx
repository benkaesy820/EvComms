import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { HelpCircle, ChevronDown, ChevronUp, Mail } from 'lucide-react'
import { cn } from '@/lib/utils'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAppConfig } from '@/hooks/useConfig'

const FAQS = [
  {
    q: 'How do I create an account?',
    a: 'Click "Get Started" on the homepage and fill in your name, email, and a strong password. Your account will be reviewed by our team before activation.',
  },
  {
    q: 'Why is my account pending approval?',
    a: "All new accounts go through a brief review to ensure platform security. Our team typically approves accounts within a few hours. You'll receive a notification once your account is active.",
  },
  {
    q: 'How do I start a conversation?',
    a: 'Once your account is approved, navigate to the Chat section from your home screen. A support conversation will be automatically created for you.',
  },
  {
    q: 'What file types can I send?',
    a: 'You can send images (JPG, PNG, GIF, WebP), videos (MP4, WebM), and documents (PDF, DOC, DOCX). File size limits depend on the type: images up to 5 MB, video up to 50 MB, documents up to 10 MB.',
  },
  {
    q: 'Can I delete messages I sent?',
    a: 'Yes, you can delete your messages within a certain time window. Long-press or hover over a message and select Delete. Admins can delete any message at any time.',
  },
  {
    q: 'How do I change my password?',
    a: "Go to Settings → Security → Change Password. You'll need to enter your current password and then set a new one meeting the security requirements.",
  },
  {
    q: 'What are announcements?',
    a: 'Announcements are broadcasts sent by the admin team to inform all or specific groups of users about important news, updates, or alerts. They appear in your Announcements section.',
  },
  {
    q: 'Is my conversation private?',
    a: 'Yes. Each user has their own dedicated conversation with the support team. Other users cannot see your messages. All data is transmitted over encrypted connections.',
  },
  {
    q: 'How do I report a problem?',
    a: 'Use the Contact page to get in touch with our team, or send a message directly in your chat. We aim to respond to all support requests promptly.',
  },
]

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left hover:bg-muted/50 transition-colors"
      >
        <span className="text-sm font-medium">{q}</span>
        {open
          ? <ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
          : <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />}
      </button>
      <div className={cn('overflow-hidden transition-all duration-200', open ? 'max-h-96' : 'max-h-0')}>
        <p className="px-5 pb-4 text-sm text-muted-foreground leading-relaxed">{a}</p>
      </div>
    </div>
  )
}

export function FAQPage() {
  const { data } = useAppConfig()
  const company = data?.brand?.company || 'Acme Corporation'
  const supportEmail = data?.brand?.supportEmail

  useEffect(() => {
    const body = document.body
    const root = document.getElementById('root')
    body.classList.remove('overflow-hidden')
    root?.classList.remove('overflow-hidden')
    root?.style.setProperty('height', 'auto')
    return () => {
      body.classList.add('overflow-hidden')
      root?.classList.add('overflow-hidden')
      root?.style.removeProperty('height')
    }
  }, [])

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <StaticPageHeader />

      <main className="flex-1">
        <div className="mx-auto max-w-3xl px-6 py-12">
          <div className="flex items-center gap-3 mb-8">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <HelpCircle className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight">Frequently Asked Questions</h1>
              <p className="text-sm text-muted-foreground">Everything you need to know about the platform</p>
            </div>
          </div>

          <div className="space-y-2">
            {FAQS.map((item) => <FAQItem key={item.q} q={item.q} a={item.a} />)}
          </div>

          {supportEmail && (
            <div className="mt-10 rounded-xl border bg-muted/30 p-6 text-center">
              <p className="text-sm font-medium">Still have questions?</p>
              <p className="text-sm text-muted-foreground mt-1">
                Reach out to us at{' '}
                <a href={`mailto:${supportEmail}`} className="text-primary underline">{supportEmail}</a>
                {' '}or use the{' '}
                <Link to="/contact" className="text-primary underline">Contact page</Link>.
              </p>
            </div>
          )}
        </div>
      </main>

      <footer className="border-t border-border/40 bg-background py-8">
        <div className="mx-auto max-w-6xl px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">© {new Date().getFullYear()} {company}. All rights reserved.</p>
          <div className="flex flex-wrap items-center gap-6 text-sm font-medium text-muted-foreground">
            <Link to="/terms" className="hover:text-primary transition-colors">Terms</Link>
            <Link to="/privacy" className="hover:text-primary transition-colors">Privacy</Link>
            <Link to="/contact" className="hover:text-primary transition-colors">Contact</Link>
            {supportEmail && (
              <a href={`mailto:${supportEmail}`} className="flex items-center gap-1.5 hover:text-primary transition-colors">
                <Mail className="h-4 w-4" />
                Support
              </a>
            )}
          </div>
        </div>
      </footer>
    </div>
  )
}
