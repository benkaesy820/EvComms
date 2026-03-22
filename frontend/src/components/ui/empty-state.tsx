import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  subtitle?: string
  className?: string
}

export function EmptyState({ icon: Icon, title, subtitle, className }: EmptyStateProps) {
  return (
    <div className={`flex flex-col items-center gap-4 py-24 text-muted-foreground ${className ?? ''}`}>
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted">
        <Icon className="h-8 w-8" />
      </div>
      <div className="text-center space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {subtitle && <p className="text-xs">{subtitle}</p>}
      </div>
    </div>
  )
}
