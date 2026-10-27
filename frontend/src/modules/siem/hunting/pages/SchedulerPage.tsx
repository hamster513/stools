import { useState } from 'react'
import { CheckCircle2, ChevronDown, ChevronRight, ChevronUp, GripVertical, Library, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { useSaveQueueOrder, useSaveScheduler, useScheduler, useToggleHunt } from '../api/queries'
import type { QueueRow, SchedulerIn, SchedulerOut } from '../api/types'
import { QueryStatus } from '../components/QueryStatus'
import { apiMessage, ruStamp } from '../format'
import { RunsHistory } from './RunsPage'

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/
const ROW_HEIGHT = 36
const LINK = 'rounded text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const ICON_BUTTON =
  'rounded p-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring aria-disabled:cursor-not-allowed aria-disabled:opacity-30 aria-disabled:hover:bg-transparent'

const COLUMNS: ColumnDef[] = [
  { key: 'enabled', label: 'В очереди', width: 88, resizable: false },
  { key: 'order', label: 'Порядок', width: 96, resizable: false },
  { key: 'code', label: 'Код', width: 120 },
  { key: 'name', label: 'Название', width: 320, flex: true },
  { key: 'technique', label: 'Техника', width: 104 },
  { key: 'queries', label: 'Запросов', width: 88, align: 'right' },
  { key: 'last', label: 'Прошлая ночь', width: 232 },
]

/**
 * Планировщик Threat Hunting: когда идёт ночной прогон за прошедшие сутки, какие ханты и в каком порядке,
 * и история ночей. Расписание и очередь приходят одним ответом (`GET /scheduler`).
 */
export function SchedulerPage() {
  const scheduler = useScheduler()
  const data = scheduler.data

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="shrink-0 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Планировщик</h1>
        <p className="text-xs text-text-secondary">ночной прогон за прошедшие сутки: какие ханты, в каком порядке, когда и с каким интервалом</p>
      </header>

      <div className="min-h-0 flex-1 overflow-auto bg-app-bg p-4">
        {scheduler.isLoading && <FullPageSpinner />}
        {scheduler.isError && <ErrorState message={apiMessage(scheduler.error, 'Не удалось загрузить планировщик')} onRetry={() => scheduler.refetch()} />}
        {data && (
          <div className="flex flex-col gap-4">
            <ScheduleForm data={data} />
            <Queue data={data} />
            <History />
          </div>
        )}
      </div>
    </div>
  )
}

// --- Расписание -----------------------------------------------------------------

/** Поля строками: пока человек печатает, число может быть неполным. */
interface Draft {
  nightly_enabled: boolean
  window_from: string
  hunt_pause_s: string
}

function errorsOf(d: Draft): Partial<Record<keyof Draft, string>> {
  const out: Partial<Record<keyof Draft, string>> = {}
  if (!HHMM.test(d.window_from)) out.window_from = 'время в формате ЧЧ:ММ'
  // Граница та же, что у сервера (`hunt_pause_s` ≥ 1).
  if (!/^\d+$/.test(d.hunt_pause_s.trim()) || Number(d.hunt_pause_s) < 1) out.hunt_pause_s = 'целое число, не меньше 1'
  return out
}

const toBody = (d: Draft): SchedulerIn => ({ nightly_enabled: d.nightly_enabled, window_from: d.window_from, hunt_pause_s: Number(d.hunt_pause_s.trim()) })

function NextRun({ data }: { data: SchedulerOut }) {
  // Срок показывается по часам сервера: в них же введено «Начинать в», и числа совпадают.
  const when = !data.nightly_enabled ? 'выключен' : data.next_run_at ? `${ruStamp(data.next_run_at, data.tz)} (${data.tz})` : 'не назначен'
  return <p className="text-xs text-text-secondary">Следующий запуск: <span className="tabular-nums text-text">{when}</span></p>
}

function ScheduleForm({ data }: { data: SchedulerOut }) {
  const { admin } = useCan()
  const save = useSaveScheduler()
  const [draft, setDraft] = useState<Draft>({ nightly_enabled: data.nightly_enabled, window_from: data.window_from, hunt_pause_s: String(data.hunt_pause_s) })
  const [saved, setSaved] = useState(false)

  const errors = errorsOf(draft)
  const valid = Object.keys(errors).length === 0
  const body = toBody(draft)
  const dirty = !valid || body.nightly_enabled !== data.nightly_enabled || body.window_from !== data.window_from || body.hunt_pause_s !== data.hunt_pause_s

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setSaved(false)
    setDraft((d) => ({ ...d, [key]: value }))
  }

  const about = 'Прогон ищет события за сутки, закончившиеся в час старта, по часам сервера. Ханты идут по очереди ниже; запросы одного ханта — подряд, между хантами — пауза, чтобы не нагружать MaxPatrol.'

  // Расписание — настройка модуля: не администратор видит его текстом, поля, которые нельзя
  // менять, выглядели бы как сломанные.
  if (!admin) {
    return (
      <Section title="Расписание" about={about}>
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs">
          <dt className="text-text-secondary">Ночной прогон</dt>
          <dd className="text-text">{data.nightly_enabled ? 'включён' : 'выключен'}</dd>
          <dt className="text-text-secondary">Начинать в</dt>
          <dd className="font-mono tabular-nums text-text">{data.window_from}</dd>
          <dt className="text-text-secondary">Интервал между хантами</dt>
          <dd className="font-mono tabular-nums text-text">{data.hunt_pause_s} с</dd>
        </dl>
        <div className="mt-3"><NextRun data={data} /></div>
      </Section>
    )
  }

  return (
    <Section title="Расписание" about={about}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (valid && dirty) save.mutate(body, { onSuccess: () => setSaved(true) })
        }}
        className="grid gap-3"
      >
        <label className="flex items-center gap-2 text-xs text-text">
          <input type="checkbox" checked={draft.nightly_enabled} onChange={(e) => set('nightly_enabled', e.target.checked)} className="accent-primary" />
          Ночной прогон включён
        </label>
        <div className="grid max-w-md gap-3 sm:grid-cols-2">
          <Field label="Начинать в" hint={errors.window_from ? undefined : `по часам сервера (${data.tz})`}>
            <input type="time" value={draft.window_from} onChange={(e) => set('window_from', e.target.value)} aria-invalid={errors.window_from ? true : undefined} className={cn(FIELD, 'font-mono')} />
            {errors.window_from && <span className="mt-1 block text-xs text-kind-1">{errors.window_from}</span>}
          </Field>
          <Field label="Интервал между хантами, с" hint={errors.hunt_pause_s ? undefined : 'по умолчанию 30'}>
            <input value={draft.hunt_pause_s} onChange={(e) => set('hunt_pause_s', e.target.value)} inputMode="numeric" aria-invalid={errors.hunt_pause_s ? true : undefined} className={cn(FIELD, 'font-mono')} />
            {errors.hunt_pause_s && <span className="mt-1 block text-xs text-kind-1">{errors.hunt_pause_s}</span>}
          </Field>
        </div>
        <NextRun data={data} />
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!valid || !dirty}>
            <Save size={14} aria-hidden /> Сохранить
          </Button>
          {saved && !dirty && <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted"><CheckCircle2 size={14} aria-hidden /> сохранено</span>}
          {save.isError && <span className="text-xs text-kind-1" role="alert">{apiMessage(save.error, 'Не удалось сохранить расписание')}</span>}
        </div>
      </form>
    </Section>
  )
}

// --- Очередь ----------------------------------------------------------------------

/** `ids` с `moved`, поставленным на место `target`: перенос вниз и вверх занимает место той строки, на которую бросили. */
function moveTo(ids: number[], moved: number, target: number): number[] {
  const to = ids.indexOf(target)
  const rest = ids.filter((id) => id !== moved)
  return [...rest.slice(0, to), moved, ...rest.slice(to)]
}

function Queue({ data }: { data: SchedulerOut }) {
  // Включить хант в очередь — работа аналитика; порядок очереди — настройка расписания, администратору модуля.
  const { write, admin } = useCan()
  const toggle = useToggleHunt()
  const saveOrder = useSaveQueueOrder()
  const cols = useColumnWidths('siem-th-scheduler-columns', COLUMNS)
  // Порядок на экране до ответа сервера; null — показывается серверный. При ошибке сбрасывается, и строки встают как были.
  const [pending, setPending] = useState<number[] | null>(null)
  const [dragId, setDragId] = useState<number | null>(null)
  const [overId, setOverId] = useState<number | null>(null)

  const byId = new Map(data.hunts.map((h) => [h.id, h]))
  const rows: QueueRow[] = pending ? pending.map((id) => byId.get(id)).filter((h): h is QueueRow => h !== undefined) : data.hunts
  const ids = rows.map((h) => h.id)
  // Пока сервер не ответил на прошлую перестановку, новая не начинается: иначе ответы пришли бы вразнобой.
  // Стрелки при этом остаются в фокусе (`aria-disabled`, не `disabled`): отключённая кнопка роняет фокус с клавиатуры.
  const canMove = admin && !saveOrder.isPending

  function commit(next: number[]) {
    if (next.every((id, i) => id === ids[i])) return
    setPending(next)
    saveOrder.mutate({ ids: next }, { onSettled: () => setPending(null) })
  }

  function endDrag() {
    setDragId(null)
    setOverId(null)
  }

  const error = saveOrder.isError
    ? apiMessage(saveOrder.error, 'Не удалось сохранить порядок')
    : toggle.isError ? apiMessage(toggle.error, 'Не удалось переключить хант') : null

  return (
    <Section
      title="Очередь хантов"
      about={`Ночью ханты идут сверху вниз. Хант не в очереди пропускается, но его место в порядке сохраняется.${admin ? ' Порядок меняется перетаскиванием строки или стрелками.' : ''}`}
    >
      {error && <p className="mb-2 text-xs text-kind-1" role="alert">{error}</p>}
      {data.hunts.length === 0 ? (
        <EmptyState
          icon={Library}
          title="Хантов нет — добавьте в библиотеке"
          description="Очередь собирается из библиотеки хантов: новый хант встаёт в её конец."
          action={<Link to="/siem/hunting/library" className={cn(LINK, 'text-sm')}>Открыть библиотеку хантов</Link>}
        />
      ) : (
        <div data-col-resize-root className="overflow-x-auto rounded border border-grid">
          <div className="grid border-b border-grid text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
            <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
          </div>
          {rows.map((h, index) => (
            <div
              key={h.id}
              draggable={canMove}
              onDragStart={canMove ? (e) => {
                setDragId(h.id)
                e.dataTransfer.effectAllowed = 'move'
                // Без данных Firefox не начинает перетаскивание.
                e.dataTransfer.setData('text/plain', h.code)
              } : undefined}
              onDragOver={canMove ? (e) => {
                if (dragId === null) return
                e.preventDefault()
                e.dataTransfer.dropEffect = 'move'
                if (overId !== h.id) setOverId(h.id)
              } : undefined}
              onDrop={canMove ? (e) => {
                e.preventDefault()
                if (dragId !== null && dragId !== h.id) commit(moveTo(ids, dragId, h.id))
                endDrag()
              } : undefined}
              onDragEnd={canMove ? endDrag : undefined}
              className={cn(
                'grid items-center border-b border-grid text-xs last:border-b-0',
                !h.enabled && 'text-text-secondary',
                dragId === h.id && 'opacity-40',
                overId === h.id && dragId !== h.id ? 'bg-row-selected' : 'hover:bg-row-hover',
              )}
              style={{ ...cols.gridStyle, height: ROW_HEIGHT }}
            >
              <div className="min-w-0 px-2">
                {write ? (
                  <input
                    type="checkbox"
                    checked={h.enabled}
                    disabled={toggle.isPending && toggle.variables?.id === h.id}
                    onChange={(e) => toggle.mutate({ id: h.id, enabled: e.target.checked })}
                    aria-label={`${h.enabled ? 'Убрать из очереди' : 'Вернуть в очередь'} хант ${h.code}`}
                    className="accent-primary"
                  />
                ) : (
                  <span>{h.enabled ? 'да' : 'нет'}</span>
                )}
              </div>
              <div className="flex min-w-0 items-center gap-1 px-2">
                {admin && <GripVertical size={14} className={cn('shrink-0 text-text-secondary', canMove && 'cursor-grab')} aria-hidden />}
                <span className="w-5 text-right font-mono tabular-nums text-text-secondary">{index + 1}</span>
                {admin && (
                  <>
                    <button type="button" className={ICON_BUTTON} aria-disabled={!canMove || index === 0} onClick={() => { if (canMove && index > 0) commit(moveTo(ids, h.id, ids[index - 1])) }} aria-label={`Выше: ${h.code}`} title="Выше">
                      <ChevronUp size={14} aria-hidden />
                    </button>
                    <button type="button" className={ICON_BUTTON} aria-disabled={!canMove || index === rows.length - 1} onClick={() => { if (canMove && index < rows.length - 1) commit(moveTo(ids, h.id, ids[index + 1])) }} aria-label={`Ниже: ${h.code}`} title="Ниже">
                      <ChevronDown size={14} aria-hidden />
                    </button>
                  </>
                )}
              </div>
              <div className="min-w-0 truncate px-2 font-mono"><Link to={`/siem/hunting/library/${h.id}`} className={LINK}>{h.code}</Link></div>
              <div className="min-w-0 truncate px-2 text-text" title={h.name}>{h.name}</div>
              <div className="min-w-0 truncate px-2 font-mono text-text-secondary">{h.technique_id ?? '—'}</div>
              <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text">{h.queries}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary">
                {h.last_run ? (
                  <>
                    <QueryStatus status={h.last_run.status} /> <span className="tabular-nums">{ruStamp(h.last_run.at)}</span>
                  </>
                ) : '—'}
              </div>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

// --- История ----------------------------------------------------------------------

/** История ночей свёрнута: страница про будущий прогон, прошлые нужны реже. */
function History() {
  const [open, setOpen] = useState(false)
  return (
    <section className="rounded border border-grid bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls="th-scheduler-history"
        className="flex w-full items-center gap-2 rounded px-4 py-3 text-left text-sm font-semibold text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
      >
        {open ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
        История ночей
      </button>
      {open && <div id="th-scheduler-history" className="border-t border-grid p-4"><RunsHistory /></div>}
    </section>
  )
}
