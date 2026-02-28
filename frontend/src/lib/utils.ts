import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import { formatDistanceToNow } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getInitials(name: string): string {
  return name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2)
}

/**
 * Safely parse any timestamp format into a JS Date.
 * Handles: ISO string, unix seconds, unix milliseconds, Date object, null/undefined.
 */
export function formatRelativeTime(value: unknown): string {
  return formatDistanceToNow(parseTimestamp(value), { addSuffix: true })
}

export function parseTimestamp(value: unknown): Date {
  if (value instanceof Date) return value

  // Convert stringified numbers to actual numbers first
  let numVal = typeof value === 'string' && !isNaN(Number(value)) ? Number(value) : value

  if (typeof numVal === 'number') {
    // Unix seconds are < 1e12 (before year ~2001 in ms), ms are >= 1e12
    if (numVal < 1e12) return new Date(numVal * 1000)
    return new Date(numVal)
  }

  if (typeof value === 'string') {
    const d = new Date(value)
    if (!isNaN(d.getTime())) return d
  }

  return new Date() // fallback to now for null/undefined/invalid
}
