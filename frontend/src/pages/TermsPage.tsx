import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Mail } from 'lucide-react'
import { StaticPageHeader } from '@/components/layout/StaticPageHeader'
import { useAppConfig } from '@/hooks/useConfig'

export function TermsPage() {
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
              <FileText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight">Terms of Service</h1>
              <p className="text-sm text-muted-foreground">
                Last updated: {new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
              </p>
            </div>
          </div>

          <div className="space-y-6 text-muted-foreground leading-relaxed text-sm">
            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">1. Acceptance of Terms</h2>
              <p>By accessing or using the {company} messaging platform ("Service"), you agree to be bound by these Terms of Service. If you do not agree, you may not use the Service.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">2. Use of Service</h2>
              <p>You agree to use the Service only for lawful purposes and in a manner consistent with all applicable laws and regulations. You must not use the Service to transmit any unlawful, harmful, threatening, or abusive content.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">3. Account Registration</h2>
              <p>To access certain features, you must create an account. You are responsible for maintaining the confidentiality of your account credentials and for all activities under your account. You must notify us immediately of any unauthorized access.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">4. Content</h2>
              <p>You retain ownership of content you submit through the Service. By submitting content, you grant {company} a non-exclusive, royalty-free license to use and display that content solely for operating the Service. You are solely responsible for the content you submit.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">5. Privacy</h2>
              <p>Your use of the Service is subject to our <Link to="/privacy" className="text-primary underline">Privacy Policy</Link>, which is incorporated into these Terms by reference.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">6. Termination</h2>
              <p>We reserve the right to suspend or terminate your access to the Service at any time, with or without notice, for conduct that we determine violates these Terms or is harmful to other users, the Service, or third parties.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">7. Disclaimer of Warranties</h2>
              <p>The Service is provided "as is" without warranties of any kind, express or implied. We do not warrant that the Service will be uninterrupted, secure, or error-free.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">8. Limitation of Liability</h2>
              <p>To the fullest extent permitted by law, {company} shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising from your use of the Service.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">9. Changes to Terms</h2>
              <p>We may update these Terms from time to time. Continued use of the Service after changes become effective constitutes your acceptance of the updated Terms.</p>
            </section>

            <section>
              <h2 className="text-base font-semibold text-foreground mb-2">10. Contact</h2>
              <p>
                Questions about these Terms? Contact us{' '}
                {supportEmail
                  ? <><a href={`mailto:${supportEmail}`} className="text-primary underline">{supportEmail}</a>.</>
                  : 'through our contact page.'}
              </p>
            </section>
          </div>
        </div>
      </main>

      <footer className="border-t border-border/40 bg-background py-8">
        <div className="mx-auto max-w-6xl px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">© {new Date().getFullYear()} {company}. All rights reserved.</p>
          <div className="flex flex-wrap items-center gap-6 text-sm font-medium text-muted-foreground">
            <Link to="/terms" className="text-primary">Terms</Link>
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
