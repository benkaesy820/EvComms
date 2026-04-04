import { Component, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw, WifiOff } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

function isNetworkError(error: Error | null): boolean {
  if (!error) return false
  const msg = error.message.toLowerCase()
  return (
    msg.includes('failed to fetch') ||
    msg.includes('network') ||
    msg.includes('load failed') ||
    msg.includes('err_name_not_resolved') ||
    msg.includes('err_internet_disconnected') ||
    msg.includes('err_connection') ||
    msg.includes('dynamic import')
  )
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback

      const networkError = isNetworkError(this.state.error)

      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-4">
          <div className={`flex h-14 w-14 items-center justify-center rounded-full ${networkError ? 'bg-amber-500/10' : 'bg-destructive/10'}`}>
            {networkError
              ? <WifiOff className="h-7 w-7 text-amber-500" />
              : <AlertTriangle className="h-7 w-7 text-destructive" />
            }
          </div>
          <div className="text-center space-y-1">
            <h2 className="text-lg font-semibold">
              {networkError ? 'Connection issue' : 'Something went wrong'}
            </h2>
            <p className="text-sm text-muted-foreground max-w-sm">
              {networkError
                ? 'Your internet connection seems unstable. Please check your network and try again.'
                : this.state.error?.message || 'An unexpected error occurred'
              }
            </p>
          </div>
          <Button
            variant="outline"
            className="gap-2"
            onClick={() => {
              this.setState({ hasError: false, error: null })
              window.location.reload()
            }}
          >
            <RefreshCw className="h-4 w-4" />
            Reload Page
          </Button>
        </div>
      )
    }

    return this.props.children
  }
}
