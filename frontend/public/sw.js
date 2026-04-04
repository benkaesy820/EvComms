// EvComms Service Worker — Web Push + Offline Shell
// Served from the root of the site (/sw.js)

const SW_VERSION = '2.0.0'
const CACHE_NAME = `evcomms-shell-v${SW_VERSION}`

// ── SW Version Tracking (for debugging via postMessage) ──────────────────────
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'GET_VERSION') {
    event.source.postMessage({
      type: 'SW_VERSION_RESPONSE',
      version: SW_VERSION,
      cacheName: CACHE_NAME,
    })
  }
})

// ── Install & Activate ──────────────────────────────────────────────────────
self.addEventListener('install', (event) => {
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
  console.log(`[SW v${SW_VERSION}] Activated and claimed all clients`)
})

// ── Fetch Handler (minimal — pass through, SPA fallback) ────────────────────
// A minimal fetch handler is required on some browsers (Firefox, older Chrome)
// to fully activate the SW and keep it eligible to receive push events.
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

// ── Push Notification Handler ───────────────────────────────────────────────

self.addEventListener('push', (event) => {
  console.log(`[SW v${SW_VERSION}] Push event received`)

  if (!event.data) {
    console.warn('[SW] No push data — showing fallback notification')
    event.waitUntil(showDefaultNotification())
    return
  }

  let payload
  try {
    payload = event.data.json()
    console.log('[SW] Parsed payload:', payload)
  } catch {
    // Payload is not valid JSON — try plain text
    try {
      const text = event.data.text()
      payload = { title: 'EvComms', body: text }
      console.log('[SW] Fallback to text payload:', text)
    } catch {
      console.warn('[SW] Failed to parse push data')
      event.waitUntil(showDefaultNotification())
      return
    }
  }

  const {
    title = 'EvComms',
    body = 'You have a new message',
    icon,
    badge,
    tag,
    data,
    silent,
    actions,
  } = payload

  // Generate a unique tag if not provided — prevents notification stacking
  // but allows grouping of related notifications
  const notificationTag = tag || `evcomms-${Date.now()}`

  const options = {
    body,
    // Use provided icon or fallback to 192px PNG (best for OS notifications)
    icon: icon || '/icon-192.png',
    // Badge is shown in the system tray when notification is collapsed
    badge: badge || '/icon-192.png',
    tag: notificationTag,
    // Custom data passed to notificationclick handler
    data: data || { url: '/' },
    // Vibration pattern: short-long-short (works on Android)
    vibrate: [100, 50, 100],
    // Replace previous notification with same tag (prevents spam)
    renotify: true,
    // Keep notification visible until user interacts with it
    requireInteraction: false,
    // Silent mode — no sound/vibration (respects user preferences)
    silent: silent || false,
    // Action buttons (optional — defined in payload from server)
    actions: actions || [
      { action: 'view', title: 'View', icon: '/icon-192.png' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
    // Timestamp for notification ordering
    timestamp: Date.now(),
    // Direction for RTL languages
    dir: 'auto',
    // Language
    lang: 'en',
  }

  event.waitUntil(
    self.registration.showNotification(title, options)
      .then(() => console.log('[SW] Notification shown:', title))
      .catch((err) => console.error('[SW] Failed to show notification:', err))
  )
})

// ── Notification Click Handler ──────────────────────────────────────────────

self.addEventListener('notificationclick', (event) => {
  console.log('[SW] Notification clicked:', event.action)

  // Always close the notification
  event.notification.close()

  const targetUrl = event.notification.data?.url || '/'
  const action = event.action

  // Handle action buttons
  if (action === 'dismiss') {
    console.log('[SW] Notification dismissed by user')
    return
  }

  // For 'view' action or default click — focus existing window or open new one
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Try to focus an existing window
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus().then((focusedClient) => {
            if (focusedClient && 'navigate' in focusedClient) {
              return focusedClient.navigate(targetUrl)
            }
            // focus() succeeded but client lacks navigate — open new window as fallback
            if (self.clients.openWindow) {
              return self.clients.openWindow(targetUrl)
            }
          })
        }
      }
      // No existing window — open a new one
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl)
      }
    }).catch((err) => console.error('[SW] Failed to handle notification click:', err))
  )
})

// ── Notification Close Handler ──────────────────────────────────────────────

self.addEventListener('notificationclose', (event) => {
  console.log('[SW] Notification closed by user without interaction')
  // Could track dismissal analytics here
})

// ── Helpers ─────────────────────────────────────────────────────────────────

function showDefaultNotification() {
  return self.registration.showNotification('EvComms', {
    body: 'You have a new message',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: 'evcomms-default',
    data: { url: '/' },
    vibrate: [100, 50, 100],
    renotify: true,
    requireInteraction: false,
    actions: [
      { action: 'view', title: 'View' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  })
}
