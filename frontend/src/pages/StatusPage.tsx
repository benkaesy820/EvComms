import { useEffect } from 'react'
import { Clock, XCircle, ShieldOff, LogOut, RefreshCw, Mail } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { useAuthStore } from '@/stores/authStore'

export function StatusPage() {
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const refreshUser = useAuthStore((s) => s.refreshUser)
  const navigate = useNavigate()

  useEffect(() => {
    if (user?.status === 'APPROVED') {
      navigate(user.role === 'USER' ? '/home' : '/admin', { replace: true })
    }
  }, [user?.status, user?.role, navigate])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const statusConfig = {
    PENDING: {
      icon: Clock,
      iconColor: 'text-amber-600 dark:text-amber-400',
      ringColor: 'ring-amber-100 dark:ring-amber-900/20',
      bgColor: 'bg-amber-50 dark:bg-amber-900/10',
      accentBar: 'bg-amber-500',
      title: 'Awaiting Approval',
      description: 'Your account is being reviewed by our team. This usually takes less than 24 hours.',
      hint: 'You will receive an email notification once your account is approved.',
    },
    REJECTED: {
      icon: XCircle,
      iconColor: 'text-red-600 dark:text-red-400',
      ringColor: 'ring-red-100 dark:ring-red-900/20',
      bgColor: 'bg-red-50 dark:bg-red-900/10',
      accentBar: 'bg-red-500',
      title: 'Registration Declined',
      description: 'Unfortunately, your account registration was not approved at this time.',
      hint: 'If you believe this is a mistake, please reach out to our support team.',
    },
    SUSPENDED: {
      icon: ShieldOff,
      iconColor: 'text-red-600 dark:text-red-400',
      ringColor: 'ring-red-100 dark:ring-red-900/20',
      bgColor: 'bg-red-50 dark:bg-red-900/10',
      accentBar: 'bg-red-500',
      title: 'Account Suspended',
      description: 'Your account has been temporarily suspended due to a policy violation.',
      hint: 'Contact our support team to learn more and resolve this issue.',
    },
  } as const

  const status = user?.status ?? 'PENDING'
  const config = statusConfig[status as keyof typeof statusConfig] ?? statusConfig.PENDING
  const Icon = config.icon

  return (
    <AuthLayout>
      <div className="overflow-hidden rounded-2xl border bg-card shadow-sm w-full max-w-sm mx-auto">
        <div className={`h-1.5 ${config.accentBar}`} />
        <div className="flex flex-col items-center gap-4 px-6 py-6">
          <div className={`flex h-16 w-16 items-center justify-center rounded-full ${config.bgColor} ring-8 ${config.ringColor}`}>
            <Icon className={`h-8 w-8 ${config.iconColor}`} />
          </div>

          <div className="text-center space-y-2">
            <h2 className="text-lg font-bold tracking-tight">{config.title}</h2>
            <p className="text-[13px] text-muted-foreground leading-relaxed max-w-xs mx-auto">
              {config.description}
            </p>
          </div>

          <div className="flex items-start gap-2.5 rounded-xl bg-muted/50 px-4 py-3 w-full">
            <Mail className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <p className="text-xs text-muted-foreground leading-relaxed">{config.hint}</p>
          </div>

          <Separator />

          {user && (
            <p className="text-xs text-muted-foreground">
              Signed in as <span className="font-semibold text-foreground">{user.email}</span>
            </p>
          )}

          <div className="flex items-center gap-3 w-full">
            {status === 'PENDING' && (
              <Button
                variant="outline"
                className="flex-1 h-10 rounded-xl gap-2 text-sm"
                onClick={() => refreshUser()}
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Check Status
              </Button>
            )}
            <Button
              variant={status === 'PENDING' ? 'ghost' : 'outline'}
              className="flex-1 h-10 rounded-xl gap-2 text-sm"
              onClick={handleLogout}
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign Out
            </Button>
          </div>
        </div>
      </div>
    </AuthLayout>
  )
}
