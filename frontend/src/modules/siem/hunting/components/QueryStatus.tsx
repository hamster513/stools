import { cn } from '@/lib/cn'
import type { HuntQueryStatus } from '../api/types'

const TITLES: Record<HuntQueryStatus, string> = { ok: 'успешно', failed: 'ошибка', skipped: 'пропущен', aborted: 'прерван' }

const TONES: Record<HuntQueryStatus, string> = {
  ok: 'text-kind-accepted',
  failed: 'text-kind-1',
  aborted: 'text-kind-1',
  skipped: 'text-text-secondary',
}

/** Исход запуска запроса словом, а не цветом: цвет только усиливает. */
export function QueryStatus({ status, className }: { status: HuntQueryStatus; className?: string }) {
  return <span className={cn('whitespace-nowrap', TONES[status], className)}>{TITLES[status]}</span>
}
