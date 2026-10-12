import { useEffect, useState } from 'react'
import { cn } from '@/lib/cn'
import { MB, type ScrubJob } from '../api/types'

/** Без новых цифр дольше этого — предупреждение: задание, похоже, подвисло. */
const STALE_S = 60
/** Стадии, у которых processed и total — байты входа (или результата при проверке). */
const BYTE_STAGES = new Set(['scan', 'apply', 'verify'])

/**
 * Когда ход задания менялся последний раз — по часам браузера: сервер времени отметки не отдаёт.
 * Общая на страницы: из списка в карточку задание переходит со своей отметкой.
 */
const lastChange = new Map<number, { stamp: string; at: number }>()

function changedAt(job: ScrubJob): number {
  const stamp = `${job.stage}|${job.processed}|${job.message}`
  const seen = lastChange.get(job.id)
  if (seen && seen.stamp === stamp) return seen.at
  const at = Date.now()
  lastChange.set(job.id, { stamp, at })
  return at
}

/** Текущее время, раз в секунду: «идёт» и «обновлено … назад» тикают и между опросами. */
function useNow(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function seconds(s: number): string {
  return s < 60 ? `${s} с` : `${Math.floor(s / 60)} мин ${s % 60} с`
}

function mb(bytes: number): string {
  return (bytes / MB).toLocaleString('ru-RU', { minimumFractionDigits: 1, maximumFractionDigits: 1 })
}

/**
 * Ход идущего задания: полоса по байтам входа, сколько идёт и когда менялись цифры. «Нет обновлений»
 * дольше минуты — знак, что задание подвисло (отметка считается с момента, как страница его увидела).
 */
export function JobRun({ job, large = false }: { job: ScrubJob; large?: boolean }) {
  const now = useNow()
  const quiet = Math.max(0, Math.round((now - changedAt(job)) / 1000))
  const elapsed = Math.max(0, Math.round((now - Date.parse(job.started_at)) / 1000))
  const amount = job.total
    ? BYTE_STAGES.has(job.stage)
      ? `${mb(job.processed)} / ${mb(job.total)} МБ`
      : `${job.processed.toLocaleString('ru-RU')} / ${job.total.toLocaleString('ru-RU')}`
    : null
  const line = cn('font-mono tabular-nums text-text-secondary', large ? 'text-xs' : 'text-[11px]')
  return (
    <div>
      <div className={cn('w-full overflow-hidden rounded-full bg-grid', large ? 'h-2' : 'h-1.5')}>
        <div className={cn('h-full rounded-full bg-primary transition-[width] duration-300', !job.total && 'animate-pulse')} style={{ width: job.total ? `${job.progress}%` : '100%' }} />
      </div>
      {amount && <div className={cn('mt-1', line)}>{amount} · {job.progress}%</div>}
      <div className={cn('flex flex-wrap gap-x-2', line)}>
        <span className="whitespace-nowrap">идёт {seconds(elapsed)}</span>
        {quiet > STALE_S
          ? <span className="whitespace-nowrap text-kind-2">нет обновлений {seconds(quiet)}</span>
          : <span className="whitespace-nowrap">обновлено {seconds(quiet)} назад</span>}
      </div>
    </div>
  )
}
