import { useQuery } from '@tanstack/react-query'
import { adminQueue, type QueueData } from '../lib/api'

export function useQueue() {
  return useQuery<QueueData>({
    queryKey: ['admin', 'queue'],
    queryFn: async () => {
      const res = await adminQueue.get()
      return res.queue
    },
    refetchInterval: 30_000, // refresh every 30s — live enough without hammering the DB
    staleTime: 15_000,
  })
}

/** Format a wait/idle duration in ms into a human-readable string */
export function formatWaitDuration(ms: number): string {
  if (ms < 60_000) return '<1m'
  const minutes = Math.floor(ms / 60_000)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  const remainingMins = minutes % 60
  if (remainingMins === 0) return `${hours}h`
  return `${hours}h ${remainingMins}m`
}
