import { useState } from 'react'
import { Eraser, Plus } from 'lucide-react'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useRouter } from '@/lib/router'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { useScrubJobs } from '../api/queries'
import { JOB_KIND_LABELS, STAGE_LABELS, STATUS_CLASS, STATUS_LABELS, type ScrubJob } from '../api/types'

const CELL = 'px-3 py-2 align-top'

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

/**
 * Список заданий очистки. Общий роутер задач отдаёт только ход задания: в сообщении — счётчики
 * («находок: N», «заменено вхождений: N»), имя файла и размер — на карточке. Фильтры — на клиенте:
 * сервер отдаёт идущие и последние 50.
 */
export function ScrubJobsPage() {
  const { write } = useCan()
  const me = useMe()
  const { navigate } = useRouter()
  const jobs = useScrubJobs()
  const filtersPanel = useFiltersPanel('toolbox-jobs')
  const [status, setStatus] = useState('')
  const [kind, setKind] = useState('')
  const [mine, setMine] = useState(false)
  const login = me.data?.login

  const chips: FilterChip[] = []
  if (status) chips.push({ label: `статус: ${STATUS_LABELS[status as ScrubJob['status']]}`, clear: () => setStatus('') })
  if (kind) chips.push({ label: `вид: ${JOB_KIND_LABELS[kind]}`, clear: () => setKind('') })
  if (mine && login) chips.push({ label: 'только мои', clear: () => setMine(false) })

  const rows = (jobs.data ?? []).filter((j) => (!status || j.status === status) && (!kind || j.kind === kind) && (!mine || !login || j.started_by === login))

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Очистка файлов</h1>
            <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Адреса, имена хостов и доменов, учётные записи и секреты заменяются устойчивыми псевдонимами: перед заменой — предпросмотр находок, после — файл, отчёт и таблица соответствий. Идущие задания сверху, затем последние 50.
          </p>
        </div>
        {write && <Button variant="primary" onClick={() => navigate('/toolbox/scrub/new')}><Plus size={14} aria-hidden />Новое задание</Button>}
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>

      {filtersPanel.open && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Статус">
            <select className={FIELD} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">все</option>
              {Object.entries(STATUS_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </Field>
          <Field label="Вид">
            <select className={FIELD} value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">все</option>
              {Object.entries(JOB_KIND_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </Field>
          {login && (
            <label className="flex items-end gap-2 pb-2 text-xs text-text">
              <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />
              <span>Только мои</span>
            </label>
          )}
        </div>
      )}

      {jobs.isLoading ? (
        <FullPageSpinner />
      ) : jobs.isError || !jobs.data ? (
        <ErrorState message={jobs.error?.message ?? 'Не удалось загрузить задания'} onRetry={() => jobs.refetch()} />
      ) : jobs.data.length === 0 ? (
        <EmptyState icon={Eraser} title="Заданий ещё не было" description={write ? 'Загрузите файл или вставьте текст — «Новое задание».' : 'Задания запускают аналитики и администраторы.'} />
      ) : rows.length === 0 ? (
        <EmptyState icon={Eraser} title="Под фильтры ничего не попало" description="Снимите часть фильтров." />
      ) : (
        <div className="overflow-x-auto rounded border border-grid">
          <table className="w-full min-w-[800px] text-xs">
            <thead className="bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              <tr>
                <th className="px-3 py-2 text-left">Задание</th>
                <th className="px-3 py-2 text-left">Статус</th>
                <th className="w-44 px-3 py-2 text-left">Ход</th>
                <th className="px-3 py-2 text-left">Итог</th>
                <th className="px-3 py-2 text-left">Кто</th>
                <th className="px-3 py-2 text-left">Когда</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((j) => (
                <tr key={j.id} {...clickableRow(() => navigate(`/toolbox/scrub/${j.id}`))} className={cn('cursor-pointer border-t border-grid hover:bg-row-hover', ROW_FOCUS)}>
                  <td className={cn(CELL, 'whitespace-nowrap text-text')}><span className="font-mono text-text-secondary">#{j.id}</span> {JOB_KIND_LABELS[j.kind] ?? j.kind}</td>
                  <td className={cn(CELL, STATUS_CLASS[j.status])}>{STATUS_LABELS[j.status]}{j.status === 'running' && <span className="text-text-secondary"> · {STAGE_LABELS[j.stage] ?? j.stage}</span>}</td>
                  <td className={CELL}>
                    {j.status === 'running' && j.total ? (
                      <div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-grid"><div className="h-full rounded-full bg-primary" style={{ width: `${j.progress}%` }} /></div>
                        <div className="mt-1 font-mono text-[11px] tabular-nums text-text-secondary">{j.processed} / {j.total}</div>
                      </div>
                    ) : null}
                  </td>
                  <td className={cn(CELL, 'max-w-[360px] text-text-secondary')}>{j.error ? <span className="text-kind-1">{j.error}</span> : j.message}</td>
                  <td className={cn(CELL, 'font-mono text-text-secondary')}>{j.started_by}</td>
                  <td className={cn(CELL, 'whitespace-nowrap text-text-secondary')}>{when(j.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
