import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { AlertCircle, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { PasswordInput } from '@/components/ui/password-input'
import { Label } from '@/components/ui/label'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { loginSchema, type LoginInput } from '@/lib/schemas'
import { useAuthStore } from '@/stores/authStore'
import { ApiError } from '@/lib/api'
import { LeafLogo } from '@/components/ui/LeafLogo'

export function LoginPage() {
  const navigate = useNavigate()
  const login = useAuthStore((s) => s.login)
  const [error, setError] = useState<string | null>(null)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
  })

  const onSubmit = async (data: LoginInput) => {
    setError(null)
    try {
      await login(data.email, data.password)
      navigate('/')
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setError('Account not approved or suspended. Check your email for details.')
        } else if (err.status === 401) {
          setError('Invalid email or password.')
        } else if (err.status === 429) {
          setError('Too many login attempts. Please try again later.')
        } else {
          setError(err.message)
        }
      } else {
        setError('An unexpected error occurred.')
      }
    }
  }

  return (
    <AuthLayout
      title="Welcome back"
      subtitle="Sign in to your account to continue"
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

        <div className="space-y-1.5">
          <Label htmlFor="password" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Password
          </Label>
          <PasswordInput
              id="password"
              placeholder="Enter your password"
              autoComplete="current-password"
              className="h-11 rounded-xl bg-muted/50 border-0 focus-visible:bg-background focus-visible:ring-2"
              {...register('password')}
            />
          {errors.password && (
            <p className="text-xs text-destructive pl-1">{errors.password.message}</p>
          )}
        </div>

        <div className="flex justify-end">
          <Link to="/forgot-password" className="text-sm text-primary hover:underline underline-offset-4">
            Forgot password?
          </Link>
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
              Sign In
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Don&apos;t have an account?{' '}
          <Link to="/register" className="font-semibold text-primary hover:underline underline-offset-4">
            Create one
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
