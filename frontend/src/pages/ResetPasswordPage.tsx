import { useState } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { AlertCircle, CheckCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { PasswordInput } from '@/components/ui/password-input'
import { Label } from '@/components/ui/label'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { resetPasswordSchema, type ResetPasswordInput } from '@/lib/schemas'
import { auth, ApiError } from '@/lib/api'
import { LeafLogo } from '@/components/ui/LeafLogo'

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ResetPasswordInput>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { token },
  })

  const onSubmit = async (data: ResetPasswordInput) => {
    setError(null)
    try {
      await auth.resetPassword(data.token, data.newPassword)
      setSuccess(true)
      setTimeout(() => navigate('/login'), 3000)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 400) {
          setError('Invalid or expired reset token. Please request a new one.')
        } else if (err.status === 429) {
          setError('Too many requests. Please try again later.')
        } else {
          setError(err.message)
        }
      } else {
        setError('Failed to reset password. Please try again.')
      }
    }
  }

  if (!token) {
    return (
      <AuthLayout title="Invalid link" subtitle="This password reset link is invalid">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10 ring-8 ring-destructive/5">
            <AlertCircle className="h-8 w-8 text-destructive" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Invalid Link</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              This password reset link is invalid or has expired. Please request a new one.
            </p>
          </div>
          <Link to="/forgot-password">
            <Button className="h-11 rounded-xl px-6">
              Request New Link
            </Button>
          </Link>
        </div>
      </AuthLayout>
    )
  }

  if (success) {
    return (
      <AuthLayout title="Password reset" subtitle="Your password has been changed">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/20 ring-8 ring-green-50 dark:ring-green-900/10">
            <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Password Reset</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              Your password has been successfully reset. Redirecting to login...
            </p>
          </div>
          <Link to="/login">
            <Button variant="outline" className="h-11 rounded-xl px-6">
              Sign In Now
            </Button>
          </Link>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Reset your password"
      subtitle="Enter a new password for your account"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-destructive/20 bg-destructive/5 px-4 py-3">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        <input type="hidden" {...register('token')} />

        <div className="space-y-1.5">
          <Label htmlFor="newPassword" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            New Password
          </Label>
          <PasswordInput
            id="newPassword"
            placeholder="Min 8 characters"
            autoComplete="new-password"
            className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            {...register('newPassword')}
          />
          {errors.newPassword && (
            <p className="text-xs text-destructive pl-1">{errors.newPassword.message}</p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="confirmPassword" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Confirm Password
          </Label>
          <PasswordInput
            id="confirmPassword"
            placeholder="Confirm your password"
            autoComplete="new-password"
            className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
            {...register('confirmPassword')}
          />
          {errors.confirmPassword && (
            <p className="text-xs text-destructive pl-1">{errors.confirmPassword.message}</p>
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
            'Reset Password'
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
