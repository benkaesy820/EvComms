import { FileText } from 'lucide-react'
import { StaticLayout } from '@/components/layout/StaticLayout'
import { useAppConfig } from '@/hooks/useConfig'
import { DEFAULTS } from '@/lib/constants'

function Section({ n, title, children }: { n: string; title: string; children: React.ReactNode }) {
  return (
    <section className="pb-6 border-b border-border/50 last:border-0 last:pb-0">
      <h2 className="text-base font-bold text-foreground mb-2">
        <span className="text-primary mr-1">{n}.</span> {title}
      </h2>
      <div className="text-sm text-muted-foreground leading-relaxed space-y-2">{children}</div>
    </section>
  )
}

export function TermsPage() {
  const { data } = useAppConfig()
  const company = data?.brand?.company || DEFAULTS.company
  const supportEmail = data?.brand?.supportEmail

  return (
    <StaticLayout>
      <div className="mx-auto w-full max-w-2xl px-4 py-12 sm:px-6 sm:py-16">
        {/* Header */}
        <div className="mb-10">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 mb-4">
            <FileText className="h-6 w-6 text-primary" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">Terms of Service</h1>
          <p className="text-sm text-muted-foreground">
            Last updated: January 2025
          </p>
        </div>

        <div className="space-y-6">
          <Section n="1" title="Acceptance of Terms">
            <p>By accessing or using the {company} messaging platform ("Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not use the Service.</p>
          </Section>

          <Section n="2" title="Use of Service">
            <p>You agree to use the Service only for lawful purposes and in a manner consistent with all applicable laws and regulations. You must not use the Service to transmit any unlawful, harmful, threatening, or abusive content.</p>
          </Section>

          <Section n="3" title="Account Registration">
            <p>To access certain features, you must create an account. You are responsible for maintaining the confidentiality of your credentials and for all activities under your account. Notify us immediately of any unauthorized access.</p>
          </Section>

          <Section n="4" title="Privacy">
            <p>Your privacy is important to us. Please review our Privacy Policy, which governs the collection and use of your personal information as part of the Service.</p>
          </Section>

          <Section n="5" title="Intellectual Property">
            <p>The Service and its original content, features, and functionality are owned by {company} and are protected by applicable intellectual property laws. You may not reproduce, distribute, or create derivative works without our express written consent.</p>
          </Section>

          <Section n="6" title="Termination">
            <p>We reserve the right to suspend or terminate your access to the Service at our sole discretion, without notice, for conduct that we believe violates these Terms or is harmful to other users, us, or third parties.</p>
          </Section>

          <Section n="7" title="Disclaimer of Warranties">
            <p>The Service is provided "as is" and "as available" without warranties of any kind, either express or implied. We do not warrant that the Service will be uninterrupted, error-free, or free of viruses or other harmful components.</p>
          </Section>

          <Section n="8" title="Limitation of Liability">
            <p>To the fullest extent permitted by law, {company} shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising from your use of the Service.</p>
          </Section>

          <Section n="9" title="Changes to Terms">
            <p>We reserve the right to modify these Terms at any time. Changes will be posted on this page with an updated date. Continued use of the Service after changes constitutes acceptance of the new Terms.</p>
          </Section>

          <Section n="10" title="Contact">
            <p>
              For questions about these Terms, please contact us
              {supportEmail ? <> at <a href={`mailto:${supportEmail}`} className="text-primary underline underline-offset-2">{supportEmail}</a></> : ' through the Contact page'}.
            </p>
          </Section>
        </div>
      </div>
    </StaticLayout>
  )
}
