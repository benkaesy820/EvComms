// EvComms Service Worker — Web Push + Offline Shell
// Served from the root of the site (/sw.js)

const CACHE_NAME = 'evcomms-shell-v1'

self.addEventListener('install', () => {
  // Skip waiting so a newly deployed SW activates immediately on all tabs
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  // Claim all open clients so the SW controls every tab right away —
  // required for push to work on first page load without a reload.
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  )
})

// A minimal fetch handler is required on some browsers (Firefox, older Chrome)
// to fully activate the SW and keep it eligible to receive push events.
// We pass everything straight through — no caching of API or socket traffic.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  const isSameOrigin = url.origin === self.location.origin
  const isNavigation = event.request.mode === 'navigate'
  const isApi = url.pathname.startsWith('/api') || url.pathname.startsWith('/socket.io')

  if (isSameOrigin && isNavigation && !isApi) {
    // SPA fallback: serve index.html if the network is unavailable
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/index.html'))
    )
    return
  }
  // Everything else (API, assets, socket) — pass through untouched
})

// ── Push notification handler ──────────────────────────────────────────────

self.addEventListener('push', (event) => {
  console.log('[WebPush SW] Push event received:', event)
  if (!event.data) {
    console.warn('[WebPush SW] No event data found')
    return
  }

  let payload
  try {
    payload = event.data.json()
    console.log('[WebPush SW] Parsed payload:', payload)
  } catch (err) {
    console.warn('[WebPush SW] Payload is not JSON, falling back to text:', err)
    payload = { title: 'EvComms', body: event.data.text() }
  }

  const {
    title = 'EvComms',
    body = 'You have a new message',
    icon,
    badge,
    tag,
    data,
  } = payload

  const options = {
    body,
    icon: icon || '/icon-192.png',
    badge: badge || '/icon-192.png',
    tag: tag || 'evcomms-notification',
    data: data || {},
    vibrate: [100, 50, 100],
    renotify: true,
    requireInteraction: false,
  }

  console.log('[WebPush SW] Showing notification with options:', options)
  event.waitUntil(
    self.registration.showNotification(title, options)
      .then(() => console.log('[WebPush SW] Notification shown successfully'))
      .catch((err) => console.error('[WebPush SW] Failed to show notification:', err))
  )
})

// ── Notification click handler ─────────────────────────────────────────────

self.addEventListener('notificationclick', (event) => {
  event.notification.close()

  const targetUrl = event.notification.data?.url || '/'

  event.waitUntil(
    self.clients
      .matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if ('focus' in client) {
            client.focus()
            if ('navigate' in client) client.navigate(targetUrl)
            return
          }
        }
        if (self.clients.openWindow) return self.clients.openWindow(targetUrl)
      })
  )
})
