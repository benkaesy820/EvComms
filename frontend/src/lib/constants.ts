import { Info, AlertTriangle, AlertCircle } from 'lucide-react'
import type { AnnouncementType } from '@/lib/schemas'

// Default fallback values
export const DEFAULTS = {
 company: 'Acme Corporation',
} as const

// FAQ Data
export const FAQ_DATA = [
  {
    q: 'How do I get access to the platform?',
    a: 'Click "Get Started Free" on the homepage and register with your email address. Your account will be reviewed and approved by our team — this typically takes a few hours. You\'ll receive an email confirmation once you\'re approved.',
  },
  {
    q: 'How does the support chat work?',
    a: 'Once your account is approved, you\'ll have a dedicated conversation with our support team. You can send text messages, share images, documents, and videos. Your messages are delivered in real-time and your assigned agent will respond as quickly as possible.',
  },
  {
    q: 'Can I upload files and images in my messages?',
    a: 'Yes — media uploads are available to users who have been granted upload permission by a support agent. Supported formats include JPEG, PNG, GIF, MP4, PDF, Word, and Excel files. If you need to share files and the option isn\'t available, ask your support agent to enable it.',
  },
  {
    q: 'What happens if my conversation is closed?',
    a: 'When a support agent closes (archives) a conversation, you\'ll see a banner in the chat with a note from the agent. You can reopen the conversation at any time by clicking "Reopen conversation" — your full message history is always preserved.',
  },
  {
    q: 'How do I reset my password?',
    a: 'Go to the login page and click "Forgot Password". Enter your registered email address and follow the instructions in the email you receive. If you don\'t see the email, check your spam folder. Password reset links expire after 1 hour.',
  },
  {
    q: 'Is my data secure?',
    a: 'Yes. All data is transmitted over HTTPS with encrypted connections. Sessions are managed with httpOnly cookies (inaccessible to JavaScript), and we implement CSRF protection, rate limiting, and role-based access controls. Your messages are only visible to you and your assigned support agent.',
  },
  {
    q: 'Can I use the platform on my phone?',
    a: 'Absolutely. The platform is fully responsive and designed for mobile use. It works on any modern browser on iOS and Android without needing to install an app.',
  },
  {
    q: 'How do I report a problem with the platform?',
    a: 'Use the "User Reports" section in your account to submit a bug report or platform issue. For urgent matters, send a message directly in your support chat or email us at our support address listed on the Contact page.',
  },
] as const

// Template configurations
export const ANNOUNCEMENT_TEMPLATES = {
 default: {
    title: '',
    content: '',
    type: 'INFO' as AnnouncementType,
    isActive: true,
 },
} as const

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
