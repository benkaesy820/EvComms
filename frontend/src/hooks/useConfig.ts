import { useQuery } from '@tanstack/react-query'
import { appConfig } from '@/lib/api'

export function useAppConfig() {
  return useQuery({
    queryKey: ['appConfig'],
    queryFn: () => appConfig.get(),
    // Cache for 5 minutes — config rarely changes and a stale value of `false`
    // for registrationDisabled is always safe (shows the form; the backend enforces it).
    // This prevents blocking the RegisterPage UI on every mount.
    staleTime: 5 * 60 * 1000,
  })
}
