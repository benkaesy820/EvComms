/**
 * Web Push Notification Registration
 *
 * Handles: SW registration, VAPID key conversion,
 * permission request, subscribe/unsubscribe, and
 * graceful degradation when push is not supported.
 */

const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY as string
import { notifications } from './api'

// Converts a VAPID base64url public key to an ArrayBuffer.
// Returning ArrayBuffer (not Uint8Array) is the safest choice:
// applicationServerKey accepts BufferSource which includes ArrayBuffer,
// and we avoid the Uint8Array<ArrayBufferLike> vs Uint8Array<ArrayBuffer>
// generic mismatch that TypeScript 5.x introduced.
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
      await navigator.serviceWorker.register('/sw.js', { scope: '/' })
      swRegistration = await navigator.serviceWorker.ready
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
 */
export async function subscribeToPush(): Promise<boolean> {
  if (!isPushSupported()) return false

  const reg = await registerServiceWorker()
  if (!reg) return false

  const permission = await Notification.requestPermission()
  if (permission !== 'granted') return false

  try {
    const existingSubscription = await reg.pushManager.getSubscription()
    if (existingSubscription) {
      return sendSubscriptionToServer(existingSubscription)
    }

    const key = urlBase64ToUint8Array(VAPID_PUBLIC_KEY) as BufferSource
    
    // Retry subscription up to 3 times with a short delay
    // Chrome sometimes throws AbortError on first attempt
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
          console.warn(`[WebPush] Subscription attempt ${attempt} failed, retrying...`)
          await new Promise(r => setTimeout(r, 1000 * attempt))
        } else {
          throw err
        }
      }
    }
    
    // All retries failed
    console.error('[WebPush] All subscription attempts failed:', lastError)
    return false
  } catch (err) {
    console.warn('[WebPush] Subscribe failed:', err)
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
    await subscription.unsubscribe()
    await deleteSubscriptionFromServer(subscription)
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
    if (!res.success) throw new Error('Update failed')
    console.log('[WebPush] Subscription saved to server')
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
