import {
  CircleCheckIcon,
  InfoIcon,
  OctagonXIcon,
  TriangleAlertIcon,
} from "lucide-react"
import { Toaster as Sonner, type ToasterProps } from "sonner"
import { LeafLogo } from '@/components/ui/LeafLogo'
import { useThemeStore } from '@/stores/themeStore'

import { toast as sonnerToast } from "sonner"

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = "system" } = useThemeStore()

  return (
    <Sonner
      theme={theme as ToasterProps["theme"]}
      className="toaster group"
      closeButton
      duration={4000}
      gap={10}
      offset={16}
      position="top-center"
      icons={{
        success: <CircleCheckIcon className="size-4 shrink-0 text-emerald-500" />,
        info: <InfoIcon className="size-4 shrink-0 text-blue-500" />,
        warning: <TriangleAlertIcon className="size-4 shrink-0 text-amber-500" />,
        error: <OctagonXIcon className="size-4 shrink-0 text-destructive" />,
        loading: <LeafLogo className="size-4 animate-spin text-primary" />,
      }}
      toastOptions={{
        className:
          "group-[.toaster]:border-border/60 group-[.toaster]:bg-popover/95 group-[.toaster]:backdrop-blur-xl group-[.toaster]:shadow-lg group-[.toaster]:rounded-xl group-[.toaster]:px-4 group-[.toaster]:py-3",
      }}
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
          "--border-radius": "var(--radius)",
          "--success-bg": "var(--popover)",
          "--success-border": "var(--border)",
          "--error-bg": "var(--popover)",
          "--error-border": "var(--border)",
        } as React.CSSProperties
      }
      {...props}
    />
  )
}

export const toast = sonnerToast

export { Toaster }
