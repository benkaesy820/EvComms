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
import { parseTimestamp } from '@/lib/utils'
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

    const isMine = message.senderId === user.id
    const isSuperAdmin = user.role === 'SUPER_ADMIN'
    const messageAge = Date.now() - parseTimestamp(message.createdAt).getTime()
    // 5 minutes timer
    const withinTimeLimit = messageAge < 300_000

    // "Delete for everyone" is allowed if:
    // 1. You are super admin
    // 2. Or, it's your message and it's less than 5 minutes old
    const canDeleteForEveryone = isSuperAdmin || (isMine && withinTimeLimit)

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
