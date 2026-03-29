// EvComms Service Worker — Web Push Notification Handler
// This file must be served from the root of the site (public/sw.js)

self.addEventListener('install', (event) => {
  // Skip waiting so the new SW activates immediately
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  // Claim all open clients immediately
  event.waitUntil(self.clients.claim())
})

self.addEventListener('push', (event) => {
  if (!event.data) return

  let payload
  try {
    payload = event.data.json()
  } catch {
    payload = { title: 'EvComms', body: event.data.text() }
  }

  const { title = 'EvComms', body = 'You have a new message', icon, badge, tag, data } = payload

  const options = {
    body,
    icon: icon || '/vite.svg',
    badge: badge || '/vite.svg',
    tag: tag || 'evcomms-notification',
    data: data || {},
    // Vibrate pattern: native mobile feel
    vibrate: [100, 50, 100],
    // Show notification even if the app is open in another tab
    renotify: true,
    requireInteraction: false,
  }

  event.waitUntil(
    self.registration.showNotification(title, options)
  )
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()

  const targetUrl = event.notification.data?.url || '/'

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // If an app window is already open, focus it and navigate to the target
      for (const client of clientList) {
        if ('focus' in client) {
          client.focus()
          if ('navigate' in client) {
            client.navigate(targetUrl)
          }
          return
        }
      }
      // No open window — open a new one
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl)
      }
    })
  )
})
