import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { Loader2 } from 'lucide-react'
import { cn } from '@/lib/cn'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  loading?: boolean
}

const VARIANT_CLASSES: Record<Variant, string> = {
  // Выключенная главная кнопка не приглушается прозрачностью: на светлой
  // теме синий на 40% даёт бледную заливку, на которой белая подпись
  // пропадает. Приглушённая пара токенов читается в обеих темах.
  primary:
    'bg-primary text-primary-text hover:bg-primary/90 disabled:bg-row-selected disabled:text-text-secondary',
  secondary:
    'bg-transparent text-text border border-border hover:bg-row-hover disabled:opacity-40 disabled:hover:bg-transparent',
  ghost: 'bg-transparent text-text-secondary hover:bg-row-hover hover:text-text disabled:opacity-40',
  danger: 'bg-transparent text-kind-1 border border-kind-1/50 hover:bg-kind-1/10 disabled:opacity-40',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', loading, disabled, className, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={props.type ?? 'button'}
      disabled={disabled || loading}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium transition-[transform,opacity] duration-150 active:scale-[0.98]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2 focus-visible:ring-offset-app-bg',
        'disabled:cursor-not-allowed',
        VARIANT_CLASSES[variant],
        className,
      )}
      {...props}
    >
      {loading && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  )
})
