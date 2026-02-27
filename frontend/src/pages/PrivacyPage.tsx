import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck, Mail } from 'lucide-react'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAppConfig } from '@/hooks/useConfig'

export function PrivacyPage() {
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
              <ShieldCheck className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight">Privacy Policy</h1>
              <p className="text-sm text-muted-foreground">
                Last updated: {new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
              </p>
            </div>
          </div>

          <div className="space-y-6 text-muted-foreground leading-relaxed text-sm">
            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">1. Information We Collect</h2>
              <p>When you register and use the {company} messaging platform, we collect:</p>
              <ul className="list-disc pl-5 mt-2 space-y-1">
                <li><strong className="text-foreground">Account information:</strong> name, email address, and phone number (optional).</li>
                <li><strong className="text-foreground">Messages:</strong> the content of messages you send and receive through the Service.</li>
                <li><strong className="text-foreground">Usage data:</strong> IP address, device type, browser, and interaction logs for security and debugging.</li>
                <li><strong className="text-foreground">Media files:</strong> images, audio, video, and documents you upload.</li>
              </ul>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">2. How We Use Your Information</h2>
              <p>We use your information to:</p>
              <ul className="list-disc pl-5 mt-2 space-y-1">
                <li>Provide and operate the messaging Service.</li>
                <li>Authenticate your identity and secure your account.</li>
                <li>Send transactional notifications (e.g., email alerts for new messages).</li>
                <li>Monitor for abuse, fraud, and security threats.</li>
                <li>Improve the Service through aggregated, anonymized analytics.</li>
              </ul>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">3. Data Sharing</h2>
              <p>We do not sell your personal data. We may share data with trusted third-party service providers (e.g., cloud storage, email delivery) solely to operate the Service, under strict confidentiality agreements. We may disclose data if required by law or to protect rights and safety.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">4. Data Retention</h2>
              <p>We retain your account data and messages for as long as your account is active. You may request deletion of your account and associated data by contacting us. Some data may be retained for legal or audit purposes for up to 90 days after deletion.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">5. Security</h2>
              <p>We use industry-standard security measures including encryption in transit (TLS), secure session management, and rate limiting to protect your data. No system is completely secure; you are responsible for maintaining the confidentiality of your password.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">6. Cookies & Storage</h2>
              <p>We use secure HTTP-only cookies for session authentication and CSRF protection. We use browser local storage for user interface preferences and draft messages. We do not use tracking cookies or third-party advertising cookies.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">7. Your Rights</h2>
              <p>Depending on your jurisdiction, you may have the right to access, correct, or delete your personal data, and to object to or restrict certain processing. Contact us to exercise these rights.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">8. Contact Us</h2>
              <p>
                For privacy questions or requests:{' '}
                {supportEmail
                  ? <a href={`mailto:${supportEmail}`} className="text-primary underline">{supportEmail}</a>
                  : 'use our Contact page.'}
              </p>
            </section>
          </div>
        </div>
      </main>

      <footer className="border-t border-border/40 bg-background py-8">
        <div className="mx-auto max-w-6xl px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">© {new Date().getFullYear()} {company}. All rights reserved.</p>
          <div className="flex flex-wrap items-center gap-6 text-sm font-medium text-muted-foreground">
            <Link to="/terms" className="hover:text-primary transition-colors">Terms</Link>
            <Link to="/privacy" className="text-primary">Privacy</Link>
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
