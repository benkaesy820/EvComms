import * as React from 'react'
import { Trash2, X, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'

interface BulkDeleteBarProps {
    count: number
    onDelete: (permanent?: boolean) => void
    onCancel: () => void
    isDeleting?: boolean
    className?: string
    isSuperAdmin?: boolean
}

export function BulkDeleteBar({ count, onDelete, onCancel, isDeleting, className, isSuperAdmin }: BulkDeleteBarProps) {
    const [permanent, setPermanent] = React.useState(false)

    if (count === 0) return null

    return (
        <div
            className={cn(
                'flex flex-col sm:flex-row sm:items-center justify-between gap-2 sm:gap-3 px-4 py-3 bg-destructive/10 border-t border-destructive/20 shrink-0 animate-in slide-in-from-bottom-1 duration-150',
                className,
            )}
        >
            <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-destructive">
                    {count} message{count !== 1 ? 's' : ''} selected
                </span>
                {isSuperAdmin && (
                    <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
                        <Checkbox
                            checked={permanent}
                            onCheckedChange={(checked: boolean | 'indeterminate') => setPermanent(checked === true)}
                            className="h-3.5 w-3.5 border-destructive/50 data-[state=checked]:bg-destructive data-[state=checked]:border-destructive"
                        />
                        <span className="flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" />
                            Delete permanently
                        </span>
                    </label>
                )}
            </div>
            <div className="flex items-center gap-2 self-end sm:self-auto">
                <Button
                    variant="ghost"
                    size="sm"
                    className="h-9 gap-1.5 text-muted-foreground hover:text-foreground"
                    onClick={onCancel}
                    disabled={isDeleting}
                >
                    <X className="h-4 w-4" />
                    Cancel
                </Button>
                <AlertDialog>
                    <AlertDialogTrigger asChild>
                        <Button
                            variant="destructive"
                            size="sm"
                            className="h-9 gap-1.5"
                            disabled={isDeleting || count === 0}
                        >
                            <Trash2 className="h-4 w-4" />
                            {isDeleting ? 'Deleting…' : permanent ? 'Delete Forever' : isSuperAdmin ? 'Delete' : 'Delete for everyone'}
                        </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                        <AlertDialogHeader>
                            <AlertDialogTitle>Delete {count} message{count !== 1 ? 's' : ''}?</AlertDialogTitle>
                            <AlertDialogDescription>
                                {permanent
                                    ? `This will permanently delete ${count} message${count !== 1 ? 's' : ''} for all users. This cannot be undone.`
                                    : `This will delete ${count} message${count !== 1 ? 's' : ''} for everyone in this conversation. This cannot be undone.`}
                            </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                                onClick={() => onDelete(permanent)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                                Delete {count} message{count !== 1 ? 's' : ''}
                            </AlertDialogAction>
                        </AlertDialogFooter>
                    </AlertDialogContent>
                </AlertDialog>
            </div>
        </div>
    )
}
