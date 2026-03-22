import { useState } from 'react'
import { Link } from 'react-router-dom'
import { HelpCircle, ChevronDown, Mail, MessageSquare } from 'lucide-react'
import { cn } from '@/lib/utils'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { useAppConfig } from '@/hooks/useConfig'
import { FAQ_DATA, DEFAULTS } from '@/lib/constants'
import { Skeleton } from '@/components/ui/skeleton'

function FAQItem({ q, a, id }: { q: string; a: string; id: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={cn(
      'rounded-xl border overflow-hidden transition-colors cursor-pointer',
      open ? 'bg-card border-primary/20' : 'bg-card hover:border-border'
    )}>
      <button
        id={`faq-btn-${id}`}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left cursor-pointer"
        aria-expanded={open}
        aria-controls={`faq-panel-${id}`}
      >
        <span className="text-sm font-semibold">{q}</span>
        <ChevronDown className={cn(
          'h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200',
          open && 'rotate-180 text-primary'
        )} />
      </button>
      <div
        id={`faq-panel-${id}`}
        role="region"
        aria-labelledby={`faq-btn-${id}`}
        className={cn('overflow-hidden transition-all duration-200 ease-in-out', open ? 'max-h-96' : 'max-h-0')}
      >
        <p className="px-5 pb-5 text-sm text-muted-foreground leading-relaxed border-t border-border/50 pt-3">{a}</p>
      </div>
    </div>
  )
}

export function FAQPage() {
  const { data, isLoading } = useAppConfig()
  const company = data?.brand?.company || DEFAULTS.company
  const supportEmail = data?.brand?.supportEmail

  // Use FAQ from config if available, otherwise fall back to hardcoded constants
  const faqItems = (data?.storefront?.faq && data.storefront.faq.length > 0)
    ? data.storefront.faq.map(f => ({ q: f.question, a: f.answer, id: f.id }))
    : FAQ_DATA.map((item, i) => ({ q: item.q, a: item.a, id: String(i) }))

  return (
    <StaticLayout>
      <div className="mx-auto w-full max-w-2xl px-4 py-12 sm:px-6 sm:py-16">
        {/* Header */}
        <div className="mb-10">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 mb-4">
            <HelpCircle className="h-6 w-6 text-primary" />
          </div>
          <p className="text-xs font-bold uppercase tracking-widest text-primary mb-2">FAQ</p>
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">Frequently Asked Questions</h1>
          <p className="text-muted-foreground">
            Everything you need to know about {company}'s support platform.
          </p>
        </div>

        {/* Questions */}
        <div className="space-y-2 mb-12">
          {isLoading
            ? Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-14 w-full rounded-xl" />)
            : faqItems.map(item => <FAQItem key={item.id} id={item.id} q={item.q} a={item.a} />)
          }
        </div>

        {/* Still have questions */}
        <div className="rounded-2xl border bg-muted/30 p-6">
          <p className="font-semibold mb-1">Still have questions?</p>
          <p className="text-sm text-muted-foreground mb-5">
            Our team is happy to help with anything not covered above.
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            {supportEmail && (
              <a
                href={`mailto:${supportEmail}`}
                className="flex items-center gap-2 rounded-full border bg-background px-4 py-2 text-sm font-medium hover:bg-muted transition-colors cursor-pointer"
              >
                <Mail className="h-4 w-4 text-primary" />
                Email us
              </a>
            )}
            <Link
              to="/contact"
              className="flex items-center gap-2 rounded-full border bg-background px-4 py-2 text-sm font-medium hover:bg-muted transition-colors cursor-pointer"
            >
              <MessageSquare className="h-4 w-4 text-primary" />
              Contact page
            </Link>
          </div>
        </div>
      </div>
    </StaticLayout>
  )
}
