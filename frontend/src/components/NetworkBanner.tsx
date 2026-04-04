import { useEffect, useState } from 'react'
import { WifiOff, RefreshCw, AlertTriangle } from 'lucide-react'

export function NetworkBanner() {
  const [isOnline, setIsOnline] = useState(navigator.onLine)
  const [isDegraded, setIsDegraded] = useState(false)

  useEffect(() => {
    const onOnline = () => {
      setIsOnline(true)
      setIsDegraded(false)
    }
    const onOffline = () => setIsOnline(false)
    const onDegraded = () => {
      if (navigator.onLine) setIsDegraded(true)
    }
    const onRestored = () => {
      setIsDegraded(false)
      setIsOnline(true)
    }

    window.addEventListener('online', onOnline)
    window.addEventListener('offline', onOffline)
    window.addEventListener('network:degraded', onDegraded)
    window.addEventListener('network:restored', onRestored)

    return () => {
      window.removeEventListener('online', onOnline)
      window.removeEventListener('offline', onOffline)
      window.removeEventListener('network:degraded', onDegraded)
      window.removeEventListener('network:restored', onRestored)
    }
  }, [])

  if (isOnline && !isDegraded) return null

  if (!isOnline) {
    return (
      <div className="fixed inset-x-0 top-0 z-[9999] flex items-center justify-center gap-2 bg-red-600 px-4 py-2 text-sm font-medium text-white shadow-lg">
        <WifiOff className="h-4 w-4 shrink-0" />
        <span>No internet connection</span>
        <span className="text-white/70">&middot;</span>
        <span className="text-white/80">Reconnecting when available</span>
        <button
          onClick={() => window.location.reload()}
          className="ml-2 flex items-center gap-1 rounded-md bg-white/20 px-2 py-0.5 text-xs font-semibold hover:bg-white/30 transition-colors"
        >
          <RefreshCw className="h-3 w-3" />
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="fixed inset-x-0 top-0 z-[9999] flex items-center justify-center gap-2 bg-amber-500 px-4 py-2 text-sm font-medium text-white shadow-lg">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span>Unstable connection</span>
      <span className="text-white/70">&middot;</span>
      <span className="text-white/80">Some features may be slow or unavailable</span>
      <button
        onClick={() => window.location.reload()}
        className="ml-2 flex items-center gap-1 rounded-md bg-white/20 px-2 py-0.5 text-xs font-semibold hover:bg-white/30 transition-colors"
      >
        <RefreshCw className="h-3 w-3" />
        Retry
      </button>
    </div>
  )
}
