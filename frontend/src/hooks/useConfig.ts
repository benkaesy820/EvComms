import { useQuery } from '@tanstack/react-query'
import { appConfig } from '@/lib/api'

export function useAppConfig() {
  return useQuery({
    queryKey: ['appConfig'],
    queryFn: () => appConfig.get(),
    staleTime: 60_000,
  })
}
