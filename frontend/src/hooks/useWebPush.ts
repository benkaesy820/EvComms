import { useState, useEffect, useCallback } from 'react'
import {
  isPushSupported,
  getNotificationPermission,
  subscribeToPush,
  unsubscribeFromPush,
  getActiveSubscription,
  registerServiceWorker,
} from '@/lib/webPush'

export type PushState = 'unsupported' | 'denied' | 'subscribed' | 'unsubscribed' | 'loading'

export function useWebPush() {
  const [state, setState] = useState<PushState>('loading')

  const refresh = useCallback(async () => {
    if (!isPushSupported()) {
      setState('unsupported')
      return
    }
    if (getNotificationPermission() === 'denied') {
      setState('denied')
      return
    }
    const sub = await getActiveSubscription()
    setState(sub ? 'subscribed' : 'unsubscribed')
  }, [])

  useEffect(() => {
    // Register SW on mount silently — no permission prompt yet
    registerServiceWorker().catch(() => {})
    refresh()
  }, [refresh])

  const enable = useCallback(async (): Promise<boolean> => {
    setState('loading')
    const ok = await subscribeToPush()
    await refresh()
    return ok
  }, [refresh])

  const disable = useCallback(async (): Promise<boolean> => {
    setState('loading')
    const ok = await unsubscribeFromPush()
    await refresh()
    return ok
  }, [refresh])

  return { state, enable, disable, refresh }
}
