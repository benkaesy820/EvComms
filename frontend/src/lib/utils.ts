import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import { formatDistanceToNow } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getInitials(name: string): string {
  if (!name || !name.trim()) return '?'
  return name.split(' ').filter(Boolean).map((n) => n[0]).join('').toUpperCase().slice(0, 2)
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

  if (value === null || value === undefined) return new Date() // fallback to now — avoids "55 years ago" in UI
  return new Date() // truly invalid input — fallback to now
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}
