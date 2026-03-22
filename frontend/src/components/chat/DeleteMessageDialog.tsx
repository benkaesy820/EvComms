import {
    AlertDialog,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/stores/authStore'
import type { Message, InternalMessage, DirectMessage } from '@/lib/schemas'

type GenericMessage = Pick<Message | InternalMessage | DirectMessage, 'id' | 'createdAt' | 'senderId'>

interface DeleteMessageDialogProps {
    open: boolean
    onOpenChange: (open: boolean) => void
    message: GenericMessage | null
    onDelete: (scope: 'me' | 'all') => void
}

export function DeleteMessageDialog({ open, onOpenChange, message, onDelete }: DeleteMessageDialogProps) {
    const user = useAuthStore((s) => s.user)

    if (!message || !user) {
        return null
    }
    const isAdmin = user.role === 'ADMIN' || user.role === 'SUPER_ADMIN'

    // "Delete for everyone" is allowed for any admin
    const canDeleteForEveryone = isAdmin

    return (
        <AlertDialog open={open} onOpenChange={onOpenChange}>
            <AlertDialogContent className="sm:max-w-[425px]">
                <AlertDialogHeader>
                    <AlertDialogTitle>Delete message?</AlertDialogTitle>
                    <AlertDialogDescription>
                        Are you sure you want to delete this message?
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter className="sm:flex-col gap-2 mt-4 items-stretch">
                    {canDeleteForEveryone && (
                        <Button
                            variant="destructive"
                            onClick={() => {
                                onDelete('all')
                                onOpenChange(false)
                            }}
                        >
                            Delete for everyone
                        </Button>
                    )}
                    <Button
                        variant="outline"
                        className="border-destructive/30 text-destructive hover:bg-destructive/10"
                        onClick={() => {
                            onDelete('me')
                            onOpenChange(false)
                        }}
                    >
                        Delete for me
                    </Button>
                    <AlertDialogCancel className="mt-2">Cancel</AlertDialogCancel>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    )
}
