import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { AlertCircle, CheckCircle, ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { forgotPasswordSchema, type ForgotPasswordInput } from '@/lib/schemas'
import { auth, ApiError } from '@/lib/api'
import { LeafLogo } from '@/components/ui/LeafLogo'

export function ForgotPasswordPage() {
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordInput>({
    resolver: zodResolver(forgotPasswordSchema),
  })

  const onSubmit = async (data: ForgotPasswordInput) => {
    setError(null)
    try {
      await auth.forgotPassword(data.email)
      setSuccess(true)
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError('Too many requests. Please try again later.')
      } else {
        setError('Failed to send reset email. Please try again.')
      }
    }
  }

  if (success) {
    return (
      <AuthLayout title="Check your email" subtitle="We sent you a password reset link">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/20 ring-8 ring-green-50 dark:ring-green-900/10">
            <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Email Sent</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              If an account exists with that email, you&apos;ll receive a password reset link shortly.
            </p>
          </div>
          <Link to="/login">
            <Button variant="outline" className="h-11 rounded-xl gap-2 px-6">
              <ArrowLeft className="h-4 w-4" />
              Back to Sign In
            </Button>
          </Link>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Forgot password?"
      subtitle="Enter your email and we'll send you a reset link"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-destructive/20 bg-destructive/5 px-4 py-3">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        <div className="space-y-1.5">
          <Label htmlFor="email" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Email Address
          </Label>
          <Input
            id="email"
            type="email"
            placeholder="you@company.com"
            autoComplete="email"
            className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            {...register('email')}
          />
          {errors.email && (
            <p className="text-xs text-destructive pl-1">{errors.email.message}</p>
          )}
        </div>

        <Button
          type="submit"
          className="h-11 w-full rounded-xl text-sm font-semibold gap-2"
          disabled={isSubmitting}
        >
          {isSubmitting ? (
            <LeafLogo className="h-4 w-4 animate-spin" />
          ) : (
            'Send Reset Link'
          )}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Remember your password?{' '}
          <Link to="/login" className="font-semibold text-primary hover:underline underline-offset-4">
            Sign in
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
