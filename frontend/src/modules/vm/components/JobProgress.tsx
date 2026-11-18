import type { Job } from '@/modules/vm/api/types'
import { bytes } from '@/platform/settings/storage'

export function ElapsedTime({ seconds }: { seconds: number }) {
  if (seconds < 60) return `${seconds} с`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин ${seconds % 60} с`
  return `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин`
}

export function RunningStatus({ job }: { job: Job }) {
  switch (job.sql_activity?.state) {
    case 'lock': return 'ждёт блокировку'
    case 'io': return 'ожидает ввода-вывода'
    case 'wait': return 'ожидание в PostgreSQL'
    default: return 'идёт'
  }
}

export function SqlQueryStatus({ job }: { job: Job }) {
  const sql = job.sql_activity
  if (job.status !== 'running' || !sql) return null
  return <div className="mt-1 text-[11px] tabular-nums text-text-secondary">Запрос PostgreSQL · <ElapsedTime seconds={sql.seconds} /> · PID {sql.pid}</div>
}

export function JobProgress({ job }: { job: Job }) {
  const { processed, total } = job
  const isImport = job.kind === 'import_vm' || job.kind === 'import_file'
  const showBytes = isImport && (job.stage === 'parsing' || job.stage === 'fetching')
  const format = (n: number) => showBytes ? bytes(n) : n.toLocaleString('ru-RU')
  const cls = 'font-mono text-[11px] tabular-nums text-text-secondary'
  if (job.status === 'done') return <span className={cls}>{processed ? format(processed) : '—'}</span>
  if (total == null || total <= 0) {
    const label = processed ? `${showBytes ? 'Прочитано' : 'Обработано'} ${format(processed)}`
      : job.status === 'running' ? 'Без счётчика' : '—'
    return <span className={cls}>{label}</span>
  }
  const steps = isImport && job.stage === 'writing'
  const label = steps ? `Шаг ${Math.min(processed + 1, total)} из ${total}` : `${format(processed)} / ${format(total)}`
  return (
    <div className={cls}>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-grid" role="progressbar"
        aria-label={steps ? 'Шаг записи снимка' : 'Прогресс стадии'} aria-valuemin={0}
        aria-valuemax={100} aria-valuenow={job.progress} aria-valuetext={label}>
        <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${job.progress}%` }} />
      </div>
      <div className="mt-1">{label}</div>
    </div>
  )
}
