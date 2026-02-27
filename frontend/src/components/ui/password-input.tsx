import { useState, forwardRef } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Input } from '@/components/ui/input'

type PasswordInputProps = Omit<React.ComponentProps<typeof Input>, 'type'>

export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(
  (props, ref) => {
    const [show, setShow] = useState(false)
    return (
      <div className="relative">
        <Input
          {...props}
          ref={ref}
          type={show ? 'text' : 'password'}
          className={`pr-10 ${props.className ?? ''}`}
        />
        <button
          type="button"
          tabIndex={-1}
          onClick={() => setShow((v) => !v)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    )
  }
)
PasswordInput.displayName = 'PasswordInput'
