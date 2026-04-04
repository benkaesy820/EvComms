/**
 * Show a native OS notification banner via the direct Notification API.
 *
 * Works whenever the browser tab is backgrounded or the window is out of focus.
 * No service worker, no push subscription, no VAPID keys required.
 * Falls back silently if the user has not granted permission.
 *
 * When the tab IS focused, in-app toasts/sounds already alert the user, so
 * we guard with `document.hidden` to avoid double-alerting.
 */
export function showOsNotification(
  title: string,
  body: string,
  tag: string,
  url?: string,
): void {
  if (!document.hidden) return
  if (!('Notification' in window)) return
  if (Notification.permission !== 'granted') return

  try {
    const n = new Notification(title, {
      body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag, // same tag collapses duplicate banners instead of stacking
    })
    if (url) {
      n.onclick = () => {
        window.focus()
        window.location.href = url
        n.close()
      }
    }
  } catch {
    // Some browsers throw if called outside a user gesture context.
    // Swallow — the in-app socket toast already handled the alert.
  }
}
