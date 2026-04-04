/**
 * Web Push Notification Registration
 *
 * Handles: SW registration, VAPID key conversion,
 * permission request, subscribe/unsubscribe, and
 * graceful degradation when push is not supported.
 *
 * Key reliability strategies:
 * - Coalesced SW registration (never registers twice)
 * - Retry on AbortError (Chrome-specific transient failure)
 * - Existing subscription reuse (no re-subscribe if already active)
 * - ArrayBuffer → Uint8Array for VAPID key (avoids buffer offset bugs)
 * - Server subscription sync on every subscribe call
 */

const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY as string
import { notifications } from './api'

/**
 * Converts a VAPID base64url public key to a Uint8Array.
 * This is the safest format for applicationServerKey — avoids the
 * ArrayBuffer offset bug where bytes.buffer.slice(0) returns the
 * wrong underlying buffer when the TypedArray doesn't start at 0.
 */
function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/')
  const rawData = window.atob(base64)
  const bytes = new Uint8Array(rawData.length)
  for (let i = 0; i < rawData.length; i++) {
    bytes[i] = rawData.charCodeAt(i)
  }
  return bytes
}

export function isPushSupported(): boolean {
  return (
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    'Notification' in window &&
    !!VAPID_PUBLIC_KEY
  )
}

export function getNotificationPermission(): NotificationPermission {
  return Notification.permission
}

let swRegistration: ServiceWorkerRegistration | null = null
// In-flight promise deduplicator — prevents a second concurrent call from
// bypassing the `if (swRegistration)` guard before the first await resolves.
let swRegistrationPromise: Promise<ServiceWorkerRegistration | null> | null = null

/**
 * Register the service worker and wait for it to be fully active.
 * Safe to call multiple times — returns the cached registration if already done.
 * Concurrent calls are coalesced into a single in-flight promise so the SW is
 * never registered twice on cold load.
 */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!isPushSupported()) return null
  if (swRegistration) return swRegistration
  if (swRegistrationPromise) return swRegistrationPromise  // coalesce concurrent callers

  swRegistrationPromise = (async () => {
    try {
      const reg = await navigator.serviceWorker.register('/sw.js', {
        scope: '/',
        updateViaCache: 'none', // Ensure SW updates are always fetched fresh
      })
      // Wait for the SW to be fully active before returning
      if (reg.installing) {
        await new Promise<void>((resolve) => {
          reg.installing!.addEventListener('statechange', () => {
            if (reg.installing?.state === 'activated') resolve()
          })
        })
      }
      swRegistration = reg
      console.log('[WebPush] Service Worker registered:', reg.scope)
      return swRegistration
    } catch (err) {
      console.warn('[WebPush] SW registration failed:', err)
      return null
    } finally {
      // Clear so retries work after failure (don't cache a failed promise)
      swRegistrationPromise = null
    }
  })()

  return swRegistrationPromise
}

/**
 * Request notification permission and subscribe to Web Push.
 * Returns true on success, false on denial / error.
 *
 * Reliability:
 * - Checks for existing subscription first (reuses it, saves to server)
 * - Retries up to 3 times on AbortError (Chrome transient failure)
 * - Syncs subscription to server on every successful subscribe
 */
export async function subscribeToPush(): Promise<boolean> {
  if (!isPushSupported()) {
    console.warn('[WebPush] Push not supported in this browser')
    return false
  }

  const reg = await registerServiceWorker()
  if (!reg) {
    console.warn('[WebPush] Service Worker not available')
    return false
  }

  // Check permission first — don't prompt if already denied
  const permission = getNotificationPermission()
  if (permission === 'denied') {
    console.warn('[WebPush] Notification permission denied by user')
    return false
  }

  // Request permission if not yet granted
  if (permission === 'default') {
    const result = await Notification.requestPermission()
    if (result !== 'granted') {
      console.warn('[WebPush] Notification permission not granted:', result)
      return false
    }
  }

  try {
    // Check for existing subscription — reuse if found
    const existingSubscription = await reg.pushManager.getSubscription()
    if (existingSubscription) {
      console.log('[WebPush] Found existing subscription, syncing to server')
      return sendSubscriptionToServer(existingSubscription)
    }

    const key = urlBase64ToUint8Array(VAPID_PUBLIC_KEY) as unknown as BufferSource

    // Retry subscription up to 3 times with exponential backoff
    // Chrome frequently throws AbortError on first attempt, especially
    // after SW registration or on cold load.
    let lastError: Error | null = null
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const subscription = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: key,
        })
        console.log(`[WebPush] Subscription successful on attempt ${attempt}`)
        return sendSubscriptionToServer(subscription)
      } catch (err: any) {
        lastError = err
        if (err.name === 'AbortError' && attempt < 3) {
          console.warn(`[WebPush] Attempt ${attempt} failed (AbortError), retrying in ${attempt}s...`)
          await new Promise(r => setTimeout(r, 1000 * attempt))
        } else {
          throw err
        }
      }
    }

    console.error('[WebPush] All subscription attempts failed:', lastError)
    return false
  } catch (err: any) {
    console.warn('[WebPush] Subscribe failed:', err?.message ?? err)
    return false
  }
}

/**
 * Unsubscribe from Web Push and remove from server.
 */
export async function unsubscribeFromPush(): Promise<boolean> {
  if (!isPushSupported()) return false

  const reg = await registerServiceWorker()
  if (!reg) return false

  try {
    const subscription = await reg.pushManager.getSubscription()
    if (!subscription) return true

    // Browser-unsubscribe first. If this fails we abort so the server record
    // stays intact — avoids a ghost subscription where the browser still holds
    // the endpoint but the DB has no matching record.
    const unsubscribed = await subscription.unsubscribe()
    if (!unsubscribed) {
      console.warn('[WebPush] Browser unsubscribe returned false')
      return false
    }

    await deleteSubscriptionFromServer(subscription)
    console.log('[WebPush] Successfully unsubscribed')
    return true
  } catch (err) {
    console.warn('[WebPush] Unsubscribe failed:', err)
    return false
  }
}

/**
 * Check if the current browser is actively subscribed.
 *
 * Uses the cached swRegistration or navigator.serviceWorker.ready directly —
 * does NOT go through registerServiceWorker() which would trigger a full
 * SW registration path just to read the push subscription state.
 */
export async function getActiveSubscription(): Promise<PushSubscription | null> {
  if (!isPushSupported()) return null
  try {
    // Prefer cached registration; fall back to the browser's ready promise.
    const reg = swRegistration ?? await navigator.serviceWorker.ready
    return reg.pushManager.getSubscription()
  } catch {
    return null
  }
}

// ──────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────

async function sendSubscriptionToServer(subscription: PushSubscription): Promise<boolean> {
  const raw = subscription.toJSON()
  try {
    const res = await notifications.subscribe({
      endpoint: raw.endpoint!,
      keys: { p256dh: raw.keys?.p256dh!, auth: raw.keys?.auth! },
    })
    if (!res.success) throw new Error('Server returned success: false')
    console.log('[WebPush] Subscription synced to server')
    return true
  } catch (err) {
    console.error('[WebPush] Failed to save subscription:', err)
    return false
  }
}

async function deleteSubscriptionFromServer(subscription: PushSubscription): Promise<void> {
  const raw = subscription.toJSON()
  try {
    await notifications.unsubscribe({ endpoint: raw.endpoint! })
    console.log('[WebPush] Subscription removed from server')
  } catch (err) {
    console.warn('[WebPush] Failed to remove subscription from server:', err)
  }
}
