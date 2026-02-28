import { Info, AlertTriangle, AlertCircle } from 'lucide-react'
import type { AnnouncementType } from '@/lib/schemas'

export const ANNOUNCEMENT_TYPE_CONFIG: Record<AnnouncementType, {
  icon: typeof Info
  color: string
  bg: string
  border: string
  label: string
}> = {
  INFO: {
    icon: Info,
    color: 'text-blue-700 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-900/15',
    border: 'border-blue-200 dark:border-blue-800',
    label: 'Info',
  },
  WARNING: {
    icon: AlertTriangle,
    color: 'text-amber-700 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-900/15',
    border: 'border-amber-200 dark:border-amber-800',
    label: 'Warning',
  },
  IMPORTANT: {
    icon: AlertCircle,
    color: 'text-red-700 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-900/15',
    border: 'border-red-200 dark:border-red-800',
    label: 'Important',
  },
}
