import { useQuery } from '@tanstack/react-query'
import { appConfig } from '@/lib/api'

export function useAppConfig() {
  return useQuery({
    queryKey: ['appConfig'],
    queryFn: () => appConfig.get(),
    // Cache is invalidated in real-time via:
    // 1. socket.on('cache:invalidate') → queryClient.invalidateQueries(['appConfig'])
    // 2. Explicit queryClient.invalidateQueries() after every config save mutation
    staleTime: 60 * 1000,
    gcTime: 5 * 60 * 1000,
  })
}
