import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { CheckCircle, AlertCircle, ArrowRight, ArrowLeft, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/ui/password-input'
import { Label } from '@/components/ui/label'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { registerSchema, type RegisterInput } from '@/lib/schemas'
import { useAuthStore } from '@/stores/authStore'
import { ApiError } from '@/lib/api'
import { useAppConfig } from '@/hooks/useConfig'
import { LeafLogo } from '@/components/ui/LeafLogo'

export function RegisterPage() {
  const registerUser = useAuthStore((s) => s.register)
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  const { data: configData } = useAppConfig()
  const registrationDisabled = configData !== undefined && configData.features?.userRegistration === false

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
  })

  const onSubmit = async (data: RegisterInput) => {
    setError(null)
    try {
      const message = await registerUser(data)
      setSuccessMessage(message)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          setError('An account with this email already exists.')
        } else if (err.status === 429) {
          setError('Too many registration attempts. Please try again later.')
        } else {
          setError(err.message)
        }
      } else {
        setError('An unexpected error occurred.')
      }
    }
  }

  if (registrationDisabled) {
    return (
      <AuthLayout title="Registration closed" subtitle="New registrations are not currently accepted">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted ring-8 ring-muted/30">
            <ShieldOff className="h-8 w-8 text-muted-foreground" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Registration Disabled</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              New account registration is temporarily closed. Please contact the support team for access.
            </p>
          </div>
          <Button onClick={() => navigate('/login')} variant="outline" className="h-11 rounded-xl gap-2 px-6">
            <ArrowLeft className="h-4 w-4" />
            Back to Sign In
          </Button>
        </div>
      </AuthLayout>
    )
  }

  if (successMessage) {
    return (
      <AuthLayout title="You're all set!" subtitle="Your registration was submitted successfully.">
        <div className="flex flex-col items-center gap-5 rounded-2xl border bg-card p-8 text-center shadow-sm">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/20 ring-8 ring-green-50 dark:ring-green-900/10">
            <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold">Account Created</h2>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-xs mx-auto">
              {successMessage}
            </p>
          </div>
          <Button onClick={() => navigate('/login')} className="h-11 rounded-xl gap-2 px-6">
            <ArrowLeft className="h-4 w-4" />
            Back to Sign In
          </Button>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="Get started with a free account"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-destructive/20 bg-destructive/5 px-4 py-3">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="text-sm text-destructive">{error}</p>
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="name" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Full Name
            </Label>
            <Input
              id="name"
              placeholder="John Doe"
              autoComplete="name"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('name')}
            />
            {errors.name && (
              <p className="text-xs text-destructive pl-1">{errors.name.message}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="phone" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Phone <span className="font-normal normal-case">(optional)</span>
            </Label>
            <Input
              id="phone"
              type="tel"
              placeholder="+1 234 567 890"
              autoComplete="tel"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('phone')}
            />
          </div>
        </div>

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

        <div className="space-y-1.5">
          <Label htmlFor="password" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Password
          </Label>
          <PasswordInput
              id="password"
              placeholder="Min 8 characters"
              autoComplete="new-password"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('password')}
            />
          {errors.password && (
            <p className="text-xs text-destructive pl-1">{errors.password.message}</p>
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
            <>
              Create Account
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-primary hover:underline underline-offset-4">
            Sign in
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
