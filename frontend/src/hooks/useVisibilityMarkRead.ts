import { useEffect, useRef, useCallback } from 'react'

/**
 * useVisibilityMarkRead
 *
 * Returns a `sentinelRef` to attach to the last (newest) message element.
 * When that element enters the viewport, `onRead` fires — but ONLY when
 * `hasUnread` is true, preventing wasteful socket emissions on every scroll.
 *
 * Also fires once immediately if the element is already in view on mount
 * (covers the case where the user is already at the bottom when a new
 * message arrives).
 *
 * Cleans up the observer on unmount or when conversationId changes.
 */
export function useVisibilityMarkRead({
  hasUnread,
  onRead,
  conversationId,
}: {
  hasUnread: boolean
  onRead: () => void
  conversationId: string | undefined
}) {
  const sentinelRef = useRef<HTMLDivElement | null>(null)
  const onReadRef = useRef(onRead)
  const hasUnreadRef = useRef(hasUnread)
  const firedRef = useRef(false)
  const observerRef = useRef<IntersectionObserver | null>(null)

  // Keep refs up-to-date without re-creating the observer
  useEffect(() => { onReadRef.current = onRead }, [onRead])
  useEffect(() => { hasUnreadRef.current = hasUnread }, [hasUnread])

  // Reset fired flag when conversation changes or new unreads arrive
  useEffect(() => {
    firedRef.current = false
  }, [conversationId, hasUnread])

  const attachObserver = useCallback((el: HTMLDivElement | null) => {
    // Disconnect any previous observer
    if (observerRef.current) {
      observerRef.current.disconnect()
      observerRef.current = null
    }

    sentinelRef.current = el
    if (!el) return

    observerRef.current = new IntersectionObserver(
      (entries) => {
        const entry = entries[0]
        if (entry?.isIntersecting && hasUnreadRef.current && !firedRef.current) {
          firedRef.current = true
          onReadRef.current()
        }
      },
      {
        // 50% of the sentinel must be visible — prevents triggering while the
        // message is barely peeking into view (e.g. partially behind the input bar)
        threshold: 0.5,
      }
    )

    observerRef.current.observe(el)
  }, []) // stable — uses refs only

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      observerRef.current?.disconnect()
    }
  }, [])

  return { sentinelRef: attachObserver }
}
