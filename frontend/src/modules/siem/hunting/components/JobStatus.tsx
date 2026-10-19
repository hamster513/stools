import { cn } from '@/lib/cn'
import type { DeepView, RunStatus } from '../api/types'

const DEEP_TONES: Record<DeepView['status'], string> = {
  queued: 'text-text-secondary',
  running: 'text-text',
  paused: 'text-text-secondary',
  done: 'text-kind-accepted',
  failed: 'text-kind-1',
  cancelled: 'text-text-secondary',
}

/** Состояние большого ханта словом; у идущего — сколько кусков пройдено. */
function deepStatusText(d: Pick<DeepView, 'status' | 'slices_done' | 'slices_total'>): string {
  switch (d.status) {
    case 'queued': return 'в очереди'
    case 'running': return `идёт ${d.slices_done} из ${d.slices_total} кусков`
    case 'paused': return `пауза, ${d.slices_done} из ${d.slices_total} кусков`
    case 'done': return 'готово'
    case 'failed': return 'ошибка'
    case 'cancelled': return 'отменён'
  }
}

export function DeepStatus({ deep, className }: { deep: Pick<DeepView, 'status' | 'slices_done' | 'slices_total'>; className?: string }) {
  return <span className={cn('whitespace-nowrap', DEEP_TONES[deep.status], className)}>{deepStatusText(deep)}</span>
}

const RUN_TITLES: Record<RunStatus, string> = {
  queued: 'в очереди',
  running: 'идёт',
  done: 'готов',
  failed: 'ошибка',
  aborted: 'прерван',
  cancelled: 'отменён',
  superseded: 'заменён повтором',
}

const RUN_TONES: Record<RunStatus, string> = {
  queued: 'text-text-secondary',
  running: 'text-text',
  done: 'text-kind-accepted',
  failed: 'text-kind-1',
  aborted: 'text-kind-1',
  cancelled: 'text-text-secondary',
  superseded: 'text-text-secondary',
}

export function RunStatusText({ status, className }: { status: RunStatus; className?: string }) {
  return <span className={cn('whitespace-nowrap', RUN_TONES[status], className)}>{RUN_TITLES[status]}</span>
}

/** Тонкая полоса хода: доля пройденного словами рядом пишет вызывающий. */
export function ProgressBar({ done, total, label }: { done: number; total: number; label: string }) {
  const share = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0
  return (
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={total} aria-valuenow={done} className="h-1.5 w-full overflow-hidden rounded bg-grid">
      <div className="h-full bg-primary" style={{ width: `${share}%` }} />
    </div>
  )
}
