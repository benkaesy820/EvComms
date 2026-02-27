import { Trash2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface BulkDeleteBarProps {
    count: number
    onDelete: () => void
    onCancel: () => void
    isDeleting?: boolean
    className?: string
}

export function BulkDeleteBar({ count, onDelete, onCancel, isDeleting, className }: BulkDeleteBarProps) {
    if (count === 0) return null

    return (
        <div
            className={cn(
                'flex items-center justify-between gap-3 px-4 py-2.5 bg-destructive/10 border-t border-destructive/20 shrink-0 animate-in slide-in-from-bottom-1 duration-150',
                className,
            )}
        >
            <span className="text-sm font-medium text-destructive">
                {count} message{count !== 1 ? 's' : ''} selected
            </span>
            <div className="flex items-center gap-2">
                <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 gap-1.5 text-muted-foreground hover:text-foreground"
                    onClick={onCancel}
                    disabled={isDeleting}
                >
                    <X className="h-4 w-4" />
                    Cancel
                </Button>
                <Button
                    variant="destructive"
                    size="sm"
                    className="h-8 gap-1.5"
                    onClick={onDelete}
                    disabled={isDeleting || count === 0}
                >
                    <Trash2 className="h-4 w-4" />
                    {isDeleting ? 'Deleting…' : 'Delete'}
                </Button>
            </div>
        </div>
    )
}
