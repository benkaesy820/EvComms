import { useState, useEffect, useCallback, useRef } from 'react'
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
  const [subscription, setSubscription] = useState<PushSubscription | null>(null)
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null)

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
    setSubscription(sub)
    setState(sub ? 'subscribed' : 'unsubscribed')
  }, [])

  useEffect(() => {
    let cancelled = false

    const init = async () => {
      if (!isPushSupported()) {
        setState('unsupported')
        return
      }

      // Try to register the SW. Retry once after 3 s on failure (common on
      // first load before the browser has fully parsed the SW script).
      let reg = await registerServiceWorker()

      if (!reg && !cancelled) {
        retryRef.current = setTimeout(async () => {
          if (!cancelled) {
            reg = await registerServiceWorker()
            if (!cancelled) refresh()
          }
        }, 3000)
      } else if (!cancelled) {
        refresh()
      }

      // If a new SW version is waiting, activate it immediately so the push
      // handler stays current — no stale SW serving old notification logic.
      if (reg?.waiting) {
        reg.waiting.postMessage({ type: 'SKIP_WAITING' })
      }
    }

    init()

    // Re-check state when the tab re-gains focus — the user may have changed
    // browser notification permissions in the OS settings since last visit.
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') refresh()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      cancelled = true
      if (retryRef.current) clearTimeout(retryRef.current)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
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

  return { state, subscription, enable, disable, refresh }
}
