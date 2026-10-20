import { useState, type CSSProperties } from 'react'
import { ArrowLeft, History, RotateCw } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link, useRouter } from '@/lib/router'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { TH_RUNS_KEY, useCancelRun, useExpectedNights, useRerun, useRerunDate, useRun, useRuns } from '../api/queries'
import type { RerunOut, RunView } from '../api/types'
import { ProgressBar, RunStatusText } from '../components/JobStatus'
import { QueryStatus } from '../components/QueryStatus'
import { apiMessage, ruDay, ruSpan, ruStamp } from '../format'

const LINK = 'inline-flex items-center gap-1 rounded text-xs text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const SECTION_TITLE = 'mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'
const ROW_HEIGHT = 40
const TH = 'px-2 py-2 text-left text-[11px] tracking-wide text-text-secondary uppercase'
const TD = 'truncate px-2 py-1.5'

const COLUMNS: ColumnDef[] = [
  { key: 'night', label: 'Ночь', width: 96 },
  { key: 'started', label: 'Шёл с', width: 136 },
  { key: 'duration', label: 'Длительность', width: 120, align: 'right' },
  { key: 'queries', label: 'Запросов', width: 128 },
  { key: 'findings', label: 'Находок', width: 80, align: 'right' },
  { key: 'errors', label: 'Ошибок', width: 72, align: 'right' },
  { key: 'status', label: 'Статус', width: 136, flex: true },
  { key: 'actions', label: '', width: 280, resizable: false },
]

const QUERY_COLUMNS: ColumnDef[] = [
  { key: 'hunt', label: 'Хант', width: 144 },
  { key: 'query', label: 'Запрос', width: 80 },
  { key: 'status', label: 'Исход', width: 104 },
  { key: 'started', label: 'Начало', width: 144 },
  { key: 'duration', label: 'Длительность', width: 128, align: 'right' },
  { key: 'events', label: 'Событий', width: 96, align: 'right' },
  { key: 'note', label: 'Находка или ошибка', width: 320, flex: true },
]

const isActive = (r: Pick<RunView, 'status'>) => r.status === 'queued' || r.status === 'running'
const seconds = (ms: number | null) => (ms === null ? '—' : `${(ms / 1000).toFixed(1)} с`)

/** Дата `YYYY-MM-DD` на день раньше; считается в UTC, чтобы пояс браузера не сдвигал день. */
function dayBefore(date: string): string {
  const d = new Date(`${date}T00:00:00Z`)
  d.setUTCDate(d.getUTCDate() - 1)
  return d.toISOString().slice(0, 10)
}

/**
 * Пропущенные ночи — даты без единой строки прогона в диапазоне ожидаемых. Нижняя граница — самая
 * старая загруженная ночь: дальше список обрезан, и пробел там был бы ложным.
 */
function missingNights(items: RunView[], from: string, to: string): string[] {
  const have = new Set(items.map((r) => r.target_date))
  const oldest = items.reduce((m, r) => (r.target_date < m ? r.target_date : m), to)
  const lo = items.length > 0 && oldest > from ? oldest : from
  const out: string[] = []
  for (let d = to; d >= lo; d = dayBefore(d)) if (!have.has(d)) out.push(d)
  return out
}

type ListRow = { kind: 'run'; run: RunView } | { kind: 'gap'; date: string }
const rowDate = (r: ListRow) => (r.kind === 'run' ? r.run.target_date : r.date)

/** Ночные прогоны: список ночей (без `id`) или карточка прогона с построчной историей запросов. */
export function RunsPage({ id }: { id?: number }) {
  return id === undefined ? <RunsList /> : <RunCard id={id} />
}

/**
 * Кнопки «Отменить» и «Повторить за дату» с общими ошибками и пояснением. Повтор ждёт, пока раздел занят
 * другой задачей: `job_id` пуст — прогон стоит в очереди.
 */
function useRunActions(onRerun?: (out: RerunOut) => void) {
  const qc = useQueryClient()
  const cancel = useCancelRun()
  const rerun = useRerun()
  const rerunDate = useRerunDate()
  const [notice, setNotice] = useState<string | null>(null)

  const started = (out: RerunOut) => {
    setNotice(out.job_id === null ? 'Раздел занят другой задачей — прогон встал в очередь и начнётся, когда она закончится.' : 'Прогон запущен.')
    onRerun?.(out)
  }

  return {
    cancel: (runId: number) => {
      setNotice(null)
      // 409 — прогон успел завершиться: данные обновляются, чтобы показать итог.
      cancel.mutate(runId, { onError: () => qc.invalidateQueries({ queryKey: TH_RUNS_KEY }) })
    },
    rerun: (runId: number) => {
      setNotice(null)
      rerun.mutate(runId, { onSuccess: started, onError: () => qc.invalidateQueries({ queryKey: TH_RUNS_KEY }) })
    },
    runDate: (date: string) => {
      setNotice(null)
      rerunDate.mutate({ target_date: date }, { onSuccess: started, onError: () => qc.invalidateQueries({ queryKey: TH_RUNS_KEY }) })
    },
    cancelling: cancel.isPending ? cancel.variables : undefined,
    rerunning: rerun.isPending ? rerun.variables : undefined,
    runningDate: rerunDate.isPending ? rerunDate.variables.target_date : undefined,
    notice,
    error: [cancel.error, rerun.error, rerunDate.error].filter((e) => e instanceof Error).map((e) => apiMessage(e, 'Не удалось выполнить')).join('; ') || null,
  }
}

type Actions = ReturnType<typeof useRunActions>

function RunButtons({ run, actions, others }: { run: RunView; actions: Actions; others: RunView[] }) {
  const { write } = useCan()
  if (!write) return null
  // Повтор за дату, на которую прогон уже идёт или ждёт, сервер отклонит (409): не предлагаем.
  const dateBusy = others.some((r) => r.target_date === run.target_date && isActive(r))
  return (
    <div className="flex items-center gap-2">
      {isActive(run) && (
        <Button onClick={(e) => { e.stopPropagation(); actions.cancel(run.id) }} loading={actions.cancelling === run.id} className="px-2 py-0.5 text-xs" aria-label={`Отменить прогон за ${ruDay(run.target_date)}`}>
          Отменить
        </Button>
      )}
      {run.status !== 'superseded' && (
        <Button
          onClick={(e) => { e.stopPropagation(); actions.rerun(run.id) }}
          loading={actions.rerunning === run.id}
          disabled={dateBusy}
          title={dateBusy ? 'За эту дату прогон уже идёт или ждёт' : 'Новый прогон за те же сутки; этот помечается заменённым'}
          className="px-2 py-0.5 text-xs"
          aria-label={`Повторить за ${ruDay(run.target_date)}`}
        >
          <RotateCw size={12} aria-hidden /> Повторить за дату
        </Button>
      )}
    </div>
  )
}

/** Ночь без прогона: нечего открыть, можно только запустить за дату. */
function GapRow({ date, actions, style }: { date: string; actions: Actions; style: CSSProperties }) {
  const { write } = useCan()
  return (
    <div className="grid items-center border-b border-grid bg-kind-1/5 text-xs" style={style}>
      <div className="min-w-0 truncate px-2 tabular-nums text-text">{ruDay(date)}</div>
      <div className="min-w-0 px-2 text-text-secondary">—</div>
      <div className="min-w-0 px-2 text-right text-text-secondary">—</div>
      <div className="min-w-0 px-2 text-text-secondary">—</div>
      <div className="min-w-0 px-2 text-right text-text-secondary">—</div>
      <div className="min-w-0 px-2 text-right text-text-secondary">—</div>
      <div className="min-w-0 truncate px-2 text-kind-1">нет прогона</div>
      <div className="min-w-0 px-2">
        {write && (
          <Button onClick={() => actions.runDate(date)} loading={actions.runningDate === date} title="Прогон за эти сутки: ночь была пропущена" className="px-2 py-0.5 text-xs" aria-label={`Запустить за ${ruDay(date)}`}>
            <RotateCw size={12} aria-hidden /> Запустить за дату
          </Button>
        )}
      </div>
    </div>
  )
}

function Messages({ actions }: { actions: Actions }) {
  return (
    <>
      {actions.error && <p className="text-xs text-kind-1" role="alert">{actions.error}</p>}
      {actions.notice && !actions.error && <p className="text-xs text-text-secondary" role="status">{actions.notice}</p>}
    </>
  )
}

// --- Список -------------------------------------------------------------------

function RunsList() {
  const { navigate } = useRouter()
  const runs = useRuns()
  const expected = useExpectedNights()
  const cols = useColumnWidths('siem-th-runs-columns', COLUMNS)
  const actions = useRunActions()

  const items = runs.data ?? []
  const gaps = runs.data && expected.data ? missingNights(items, expected.data.from, expected.data.to) : []
  // Сортировка устойчивая: прогоны одной даты остаются в порядке сервера (новый выше заменённого).
  const rows: ListRow[] = [
    ...items.map((run): ListRow => ({ kind: 'run', run })),
    ...gaps.map((date): ListRow => ({ kind: 'gap', date })),
  ].sort((a, b) => (rowDate(a) < rowDate(b) ? 1 : rowDate(a) > rowDate(b) ? -1 : 0))

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Ночные прогоны</h1>
        {runs.data && <div className="font-mono text-xs tabular-nums text-text-secondary">всего: {items.length}</div>}
        {gaps.length > 0 && <div className="font-mono text-xs tabular-nums text-kind-1">пропущено ночей: {gaps.length}</div>}
        <div className="flex basis-full flex-col gap-1 empty:hidden"><Messages actions={actions} /></div>
      </header>

      <div className="min-h-0 flex-1 overflow-auto bg-app-bg p-4">
        {runs.isLoading && <FullPageSpinner />}
        {runs.isError && <ErrorState message={apiMessage(runs.error, 'Не удалось загрузить прогоны')} onRetry={() => runs.refetch()} />}
        {runs.data && rows.length === 0 && (
          <EmptyState icon={History} title="Прогонов ещё не было" description="Ночной прогон стартует в окне из настроек Threat Hunting; пропущенная ночь появится здесь пробелом с кнопкой «Запустить за дату»." />
        )}
        {runs.data && rows.length > 0 && (
          <div data-col-resize-root className="overflow-x-auto rounded border border-grid bg-surface">
            <div className="grid border-b border-grid text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
              <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
            </div>
            {rows.map((row) => {
              if (row.kind === 'gap') return <GapRow key={`gap-${row.date}`} date={row.date} actions={actions} style={{ ...cols.gridStyle, height: ROW_HEIGHT }} />
              const r = row.run
              return (
                <div
                  key={r.id}
                  {...clickableRow(() => navigate(`/siem/hunting/runs/${r.id}`))}
                  className={cn(ROW_FOCUS, 'grid cursor-pointer items-center border-b border-grid text-xs hover:bg-row-hover', r.status === 'superseded' && 'opacity-60')}
                  style={{ ...cols.gridStyle, height: ROW_HEIGHT }}
                >
                  <div className="min-w-0 truncate px-2 tabular-nums text-text">{ruDay(r.target_date)}</div>
                  <div className="min-w-0 truncate px-2 tabular-nums text-text-secondary">{ruStamp(r.started_at)}</div>
                  <div className="min-w-0 truncate px-2 text-right tabular-nums text-text-secondary">{r.started_at ? ruSpan(r.started_at, r.finished_at) : '—'}</div>
                  <div className="flex min-w-0 flex-col gap-1 px-2">
                    <span className="font-mono tabular-nums text-text">{r.queries_done} из {r.queries_total}</span>
                    {r.status === 'running' && <ProgressBar done={r.queries_done} total={r.queries_total} label={`Ход прогона за ${ruDay(r.target_date)}`} />}
                  </div>
                  <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text">{r.findings}</div>
                  <div className={cn('min-w-0 px-2 text-right font-mono tabular-nums', r.errors > 0 ? 'text-kind-1' : 'text-text-secondary')}>{r.errors}</div>
                  <div className="min-w-0 truncate px-2" title={r.error ?? undefined}><RunStatusText status={r.status} /></div>
                  <div className="min-w-0 px-2"><RunButtons run={r} actions={actions} others={items} /></div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// --- Карточка -----------------------------------------------------------------

function RunCard({ id }: { id: number }) {
  const { navigate } = useRouter()
  const run = useRun(Number.isFinite(id) ? id : undefined)
  const all = useRuns()
  const cols = useColumnWidths('siem-th-run-queries-columns', QUERY_COLUMNS)
  const actions = useRunActions((out) => navigate(`/siem/hunting/runs/${out.run_id}`))

  if (run.isLoading) return <FullPageSpinner />
  const r = run.data
  if (!r) return <div className="p-6"><ErrorState message={apiMessage(run.error, 'Прогон не найден')} onRetry={run.isError ? () => run.refetch() : undefined} /></div>

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <header className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-grid bg-surface px-4 py-2.5">
        <Link to="/siem/hunting/runs" className={LINK}><ArrowLeft size={13} aria-hidden /> Прогоны</Link>
        <h1 className="text-sm font-semibold text-text">Ночь {ruDay(r.target_date)}</h1>
        <RunStatusText status={r.status} className="text-xs" />
        <div className="ml-auto"><RunButtons run={r} actions={actions} others={all.data ?? []} /></div>
        <div className="flex basis-full flex-col gap-1 empty:hidden"><Messages actions={actions} /></div>
      </header>

      <div className="flex flex-col gap-4 p-4">
        <section className="rounded border border-grid bg-surface p-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs md:grid-cols-[auto_1fr_auto_1fr]">
            <dt className="text-text-secondary">Период</dt>
            <dd className="tabular-nums text-text">{ruStamp(r.period_from)} — {ruStamp(r.period_to)}</dd>
            <dt className="text-text-secondary">Шёл</dt>
            <dd className="tabular-nums text-text">{r.started_at ? `${ruStamp(r.started_at)}, ${ruSpan(r.started_at, r.finished_at)}${r.finished_at ? '' : ' и продолжается'}` : '—'}</dd>
            <dt className="text-text-secondary">Запросов</dt>
            <dd className="font-mono tabular-nums text-text">{r.queries_done} из {r.queries_total}</dd>
            <dt className="text-text-secondary">Находок / ошибок</dt>
            <dd className="font-mono tabular-nums text-text">{r.findings} / <span className={r.errors > 0 ? 'text-kind-1' : undefined}>{r.errors}</span></dd>
          </dl>
          {r.status === 'running' && <div className="mt-3"><ProgressBar done={r.queries_done} total={r.queries_total} label="Ход прогона" /></div>}
          {r.error && <p className="mt-3 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2 text-xs text-text" role="alert">{r.error}</p>}
        </section>

        <section>
          <div className={SECTION_TITLE}>Запросы прогона ({r.queries.length})</div>
          {r.queries.length === 0 ? (
            <p className="rounded border border-dashed border-grid px-4 py-6 text-center text-xs text-text-secondary">Запросы ещё не запускались.</p>
          ) : (
            <div data-col-resize-root className="overflow-x-auto rounded border border-grid bg-surface">
              <table className="text-xs" style={cols.tableStyle}>
                <ColGroup cols={cols} />
                <thead>
                  <tr className="border-b border-grid"><ResizableHeader cols={cols} className={TH} /></tr>
                </thead>
                <tbody>
                  {r.queries.map((q) => (
                    <tr key={q.id} className="border-b border-grid">
                      <td className={`${TD} font-mono text-text`}>{q.hunt_code}</td>
                      <td className={`${TD} font-mono text-text-secondary`}>{q.query_id}</td>
                      <td className={TD}><QueryStatus status={q.status} /></td>
                      <td className={`${TD} tabular-nums text-text-secondary`}>{ruStamp(q.started_at)}</td>
                      <td className={`${TD} text-right font-mono tabular-nums text-text-secondary`}>{seconds(q.duration_ms)}</td>
                      <td className={`${TD} text-right font-mono tabular-nums text-text`}>{q.events}</td>
                      <td className={`${TD} text-text-secondary`} title={q.error ?? undefined}>
                        {q.finding_id !== null ? <Link to={`/siem/hunting/findings/${q.finding_id}`} className={LINK}>находка #{q.finding_id}</Link> : q.error ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
