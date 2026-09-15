import { Loader2 } from 'lucide-react'
import { cn } from '@/lib/cn'

export function Spinner({ className, size = 20 }: { className?: string; size?: number }) {
  return <Loader2 size={size} className={cn('animate-spin text-text-secondary', className)} aria-hidden />
}

export function FullPageSpinner() {
  return (
    <div className="flex h-full min-h-[40vh] items-center justify-center">
      <Spinner size={28} />
    </div>
  )
}
