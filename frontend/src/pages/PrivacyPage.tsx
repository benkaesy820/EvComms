import { ShieldCheck } from 'lucide-react'
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

export function PrivacyPage() {
  const { data } = useAppConfig()
  const company = data?.brand?.company || DEFAULTS.company
  const supportEmail = data?.brand?.supportEmail

  return (
    <StaticLayout>
      <div className="mx-auto w-full max-w-2xl px-4 py-12 sm:px-6 sm:py-16">
        {/* Header */}
        <div className="mb-10">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 mb-4">
            <ShieldCheck className="h-6 w-6 text-primary" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">Privacy Policy</h1>
          <p className="text-sm text-muted-foreground">
            Last updated: January 2025
          </p>
        </div>

        <div className="space-y-6">
          <Section n="1" title="Information We Collect">
            <p>When you register and use the {company} messaging platform, we collect:</p>
            <ul className="list-disc pl-5 space-y-1 mt-2">
              <li><strong className="text-foreground">Account information:</strong> name, email address, and phone number (optional).</li>
              <li><strong className="text-foreground">Messages:</strong> content of messages you send and receive through the Service.</li>
              <li><strong className="text-foreground">Usage data:</strong> IP address, device type, browser, and interaction logs for security and debugging.</li>
              <li><strong className="text-foreground">Media files:</strong> images and documents you upload.</li>
            </ul>
          </Section>

          <Section n="2" title="How We Use Your Information">
            <p>We use your information to:</p>
            <ul className="list-disc pl-5 space-y-1 mt-2">
              <li>Provide and operate the messaging Service.</li>
              <li>Assign your conversations to appropriate support agents.</li>
              <li>Send transactional emails (account status, message notifications).</li>
              <li>Detect and prevent fraudulent or abusive activity.</li>
              <li>Improve the quality and performance of our Service.</li>
            </ul>
          </Section>

          <Section n="3" title="Data Sharing">
            <p>We do not sell, rent, or trade your personal information to third parties. We may share information with trusted service providers (such as cloud storage or email delivery services) solely to operate the Service, and only under strict confidentiality obligations.</p>
          </Section>

          <Section n="4" title="Data Retention">
            <p>We retain your personal information for as long as your account is active or as needed to provide the Service. You may request deletion of your account and associated data at any time by contacting us.</p>
          </Section>

          <Section n="5" title="Security">
            <p>We implement industry-standard security measures including encrypted data transmission, httpOnly session cookies, CSRF protection, and role-based access controls to protect your information from unauthorized access or disclosure.</p>
          </Section>

          <Section n="6" title="Cookies and Sessions">
            <p>We use httpOnly cookies to manage authenticated sessions. These cookies are essential for the Service to function and cannot be disabled while using the platform. We do not use third-party advertising cookies.</p>
          </Section>

          <Section n="7" title="Your Rights">
            <p>Depending on your location, you may have the right to access, correct, or delete your personal information, or to restrict or object to its processing. To exercise these rights, please contact us.</p>
          </Section>

          <Section n="8" title="Changes to This Policy">
            <p>We may update this Privacy Policy from time to time. Changes will be posted on this page with an updated date. Your continued use of the Service after changes constitutes acceptance of the updated policy.</p>
          </Section>

          <Section n="9" title="Contact">
            <p>
              For privacy-related questions or requests, contact us
              {supportEmail ? <> at <a href={`mailto:${supportEmail}`} className="text-primary underline underline-offset-2">{supportEmail}</a></> : ' through the Contact page'}.
            </p>
          </Section>
        </div>
      </div>
    </StaticLayout>
  )
}
