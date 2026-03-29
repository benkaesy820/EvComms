/**
 * Web Push Notification Registration
 *
 * Handles: SW registration, VAPID key conversion,
 * permission request, subscribe/unsubscribe, and
 * graceful degradation when push is not supported.
 */

const VAPID_PUBLIC_KEY = import.meta.env.VITE_VAPID_PUBLIC_KEY as string
const API_BASE = import.meta.env.VITE_API_URL || ''

// Converts a VAPID base64url public key string to a Uint8Array backed by a plain ArrayBuffer
// (not SharedArrayBuffer) so it satisfies the applicationServerKey type constraint.
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

/**
 * Register the service worker. Safe to call multiple times — returns the
 * existing registration if already registered.
 */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!isPushSupported()) return null
  if (swRegistration) return swRegistration

  try {
    swRegistration = await navigator.serviceWorker.register('/sw.js', { scope: '/' })
    return swRegistration
  } catch (err) {
    console.warn('[WebPush] SW registration failed:', err)
    return null
  }
}

/**
 * Request notification permission and subscribe to Web Push.
 * Returns true on success, false on denial / error.
 */
export async function subscribeToPush(): Promise<boolean> {
  if (!isPushSupported()) return false

  const reg = await registerServiceWorker()
  if (!reg) return false

  // Request permission — browsers only allow this in response to a user gesture
  const permission = await Notification.requestPermission()
  if (permission !== 'granted') return false

  try {
    const existingSubscription = await reg.pushManager.getSubscription()
    if (existingSubscription) {
      // Already subscribed — ensure the server has this subscription
      await sendSubscriptionToServer(existingSubscription)
      return true
    }

    const key = urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
    const subscription = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: key,
    })

    await sendSubscriptionToServer(subscription)
    return true
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
    if (!subscription) return true // Already unsubscribed

    await deleteSubscriptionFromServer(subscription)
    await subscription.unsubscribe()
    return true
  } catch (err) {
    console.warn('[WebPush] Unsubscribe failed:', err)
    return false
  }
}

/**
 * Check if the current browser is actively subscribed.
 */
export async function getActiveSubscription(): Promise<PushSubscription | null> {
  if (!isPushSupported()) return null
  const reg = await registerServiceWorker()
  if (!reg) return null
  return reg.pushManager.getSubscription()
}

// ──────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────

async function sendSubscriptionToServer(subscription: PushSubscription): Promise<void> {
  const raw = subscription.toJSON()
  await fetch(`${API_BASE}/api/notifications/subscribe`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      endpoint: raw.endpoint,
      keys: { p256dh: raw.keys?.p256dh, auth: raw.keys?.auth },
    }),
  })
}

async function deleteSubscriptionFromServer(subscription: PushSubscription): Promise<void> {
  const raw = subscription.toJSON()
  await fetch(`${API_BASE}/api/notifications/unsubscribe`, {
    method: 'DELETE',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ endpoint: raw.endpoint }),
  })
}
