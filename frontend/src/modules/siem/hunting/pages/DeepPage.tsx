import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Telescope } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner, Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { TH_DEEP_KEY, useCancelDeep, useCreateDeep, useDeepHunts, useHunt, useHunts, useHuntOfQuery, useThSettings } from '../api/queries'
import { DEEP_ACTIVE, type DeepCreate, type DeepView, type HuntView } from '../api/types'
import { DeepStatus, ProgressBar } from '../components/JobStatus'
import { apiMessage, ruPeriod } from '../format'

const ROW_HEIGHT = 40
const LABEL = 'mb-1 block text-xs font-medium text-text'
const HINT = 'mt-1 block text-xs text-text-secondary'
const SECTION_TITLE = 'mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'
const LIMIT_MAX = 100_000

const COLUMNS: ColumnDef[] = [
  { key: 'title', label: 'Название', width: 220, flex: true },
  { key: 'source', label: 'Источник', width: 150 },
  { key: 'period', label: 'Период', width: 232 },
  { key: 'status', label: 'Состояние', width: 192 },
  { key: 'events', label: 'Событий', width: 80, align: 'right' },
  { key: 'finding', label: 'Находка', width: 120 },
  { key: 'actions', label: '', width: 100, resizable: false },
]

/**
 * Большой хант: форма запуска сверху, ниже очередь и история. `?from=<номер запроса>` (ссылка «в большой хант»
 * из карточки ханта) открывает форму с запросом библиотеки; пока он ищется, форма не показывается —
 * иначе подстановка затёрла бы то, что человек уже начал вводить.
 */
export function DeepPage() {
  const params = useSearchParams()
  const { write } = useCan()
  const fromParam = Number(params.get('from'))
  const from = Number.isInteger(fromParam) && fromParam > 0 ? fromParam : undefined
  const huntParam = Number(params.get('hunt'))
  const huntId = Number.isInteger(huntParam) && huntParam > 0 ? huntParam : undefined
  // Аудитору форма не показывается — и запросов ради подстановки не делаем.
  const origin = useHuntOfQuery(from, huntId, write)
  const deeps = useDeepHunts()

  const errorMessage = deeps.isError ? apiMessage(deeps.error, 'Не удалось загрузить большие ханты') : null
  const items = deeps.data ?? []

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Большой хант</h1>
        <span className="text-xs text-text-secondary">запрос за длинный период кусками; запуск только руками, идёт один, остальные ждут</span>
        {deeps.data && <div className="ml-auto font-mono text-xs tabular-nums text-text-secondary">всего: {items.length}</div>}
      </header>

      <div className="flex flex-col gap-4 p-4">
        {write && (
          origin.loading
            ? <div className="flex justify-center rounded border border-grid bg-surface py-8"><Spinner /></div>
            : <DeepForm key={from ?? 'blank'} originHunt={origin.hunt} originQuery={from} originFailed={origin.failed} />
        )}

        <section>
          <div className={SECTION_TITLE}>Очередь и история</div>
          <DeepList items={items} loading={deeps.isLoading} errorMessage={errorMessage} onRetry={() => deeps.refetch()} />
        </section>
      </div>
    </div>
  )
}

// --- Форма ----------------------------------------------------------------------

interface Form {
  source: 'library' | 'own'
  huntId: number | null
  queryPk: number | null
  query: string
  fields: string
  labels: string
  limit: string
  period: 'months' | 'dates'
  /** Пусто — глубина по умолчанию из настроек, её выберет сервер. */
  months: string
  dateFrom: string
  dateTo: string
  title: string
}

function initialForm(hunt: HuntView | null, queryPk: number | undefined): Form {
  const q = hunt?.queries.find((x) => x.id === queryPk)
  return {
    source: q ? 'library' : 'own',
    huntId: q && hunt ? hunt.id : null,
    queryPk: q ? q.id : null,
    query: q?.query ?? '',
    fields: q?.fields ?? '',
    labels: q?.fields_label ?? '',
    limit: q?.limit != null ? String(q.limit) : '',
    period: 'months',
    months: '',
    dateFrom: '',
    dateTo: '',
    title: '',
  }
}

/** Сколько значений в списке через запятую: пустые не считаются. */
const countItems = (s: string) => s.split(',').filter((x) => x.trim()).length

const isInt = (s: string, min: number, max: number) => /^\d+$/.test(s.trim()) && Number(s) >= min && Number(s) <= max

/** Что мешает запуску; null — можно. Те же границы, что у сервера (`DeepIn`). */
function problemOf(f: Form): string | null {
  if (f.source === 'library' && f.queryPk === null) return 'выберите хант и его запрос'
  if (!f.query.trim()) return 'нужен текст запроса'
  if (!f.fields.trim()) return 'нужны поля'
  if (f.limit.trim() && !isInt(f.limit, 1, LIMIT_MAX)) return `предел событий: целое от 1 до ${LIMIT_MAX}`
  if (f.period === 'months') {
    if (f.months.trim() && !isInt(f.months, 1, 36)) return 'глубина: целое число месяцев от 1 до 36'
  } else {
    if (!f.dateFrom || !f.dateTo) return 'период: укажите начало и конец'
    if (new Date(f.dateFrom).getTime() >= new Date(f.dateTo).getTime()) return 'период: начало должно быть раньше конца'
  }
  return null
}

function bodyOf(f: Form): DeepCreate {
  const body: DeepCreate = { query: f.query.trim(), fields: f.fields.trim(), fields_label: f.labels.trim() }
  if (f.source === 'library' && f.queryPk !== null) body.hunt_query_id = f.queryPk
  if (f.title.trim()) body.title = f.title.trim()
  if (f.limit.trim()) body.limit = Number(f.limit)
  if (f.period === 'months') {
    if (f.months.trim()) body.months = Number(f.months)
  } else {
    body.period_from = new Date(f.dateFrom).toISOString()
    body.period_to = new Date(f.dateTo).toISOString()
  }
  return body
}

function DeepForm({ originHunt, originQuery, originFailed }: { originHunt: HuntView | null; originQuery: number | undefined; originFailed: boolean }) {
  const [form, setForm] = useState<Form>(() => initialForm(originHunt, originQuery))
  const [created, setCreated] = useState<DeepView | null>(null)
  const hunts = useHunts()
  const hunt = useHunt(form.huntId ?? undefined)
  const settings = useThSettings()
  const create = useCreateDeep()

  const problem = problemOf(form)
  const defaultMonths = settings.data?.default_depth_months
  const fieldCount = countItems(form.fields)
  const labelCount = countItems(form.labels)
  const labelsMismatch = labelCount > 0 && labelCount !== fieldCount
  const missingOrigin = originQuery !== undefined && !originHunt

  function patch(next: Partial<Form>) {
    setCreated(null)
    setForm((f) => ({ ...f, ...next }))
  }
  function pickHunt(value: string) {
    patch({ huntId: value ? Number(value) : null, queryPk: null })
  }
  /** Выбранный запрос подставляется копией: дальше его можно править, библиотека от этого не меняется. */
  function pickQuery(value: string) {
    const q = hunt.data?.queries.find((x) => x.id === Number(value))
    if (!q) return patch({ queryPk: null })
    patch({ queryPk: q.id, query: q.query, fields: q.fields, labels: q.fields_label, limit: q.limit === null ? '' : String(q.limit) })
  }

  function submit() {
    if (problem) return
    create.mutate(bodyOf(form), { onSuccess: (view) => { setCreated(view); setForm((f) => ({ ...f, title: '' })) } })
  }

  return (
    <section className="rounded border border-grid bg-surface p-4" aria-label="Запуск большого ханта">
      <div className={SECTION_TITLE}>Новый большой хант</div>
      {missingOrigin && (
        <p className="mb-3 text-xs text-kind-1" role="alert">
          {originFailed ? 'Не удалось загрузить хант — запрос не подставлен. Обновите страницу или заполните форму вручную.' : `Запрос №${originQuery} не найден в библиотеке — возможно, хант удалён. Заполните форму вручную.`}
        </p>
      )}

      <fieldset className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1">
        <legend className="sr-only">Источник запроса</legend>
        {([['library', 'Из библиотеки'], ['own', 'Свой запрос']] as const).map(([value, label]) => (
          <label key={value} className="flex items-center gap-1.5 text-xs text-text">
            <input type="radio" name="deep-source" checked={form.source === value} onChange={() => patch({ source: value })} className="accent-primary" />
            {label}
          </label>
        ))}
      </fieldset>

      {form.source === 'library' && (
        <div className="mb-3 grid gap-3 md:grid-cols-2">
          <label className="block">
            <span className={LABEL}>Хант</span>
            <select value={form.huntId ?? ''} onChange={(e) => pickHunt(e.target.value)} className={FIELD}>
              <option value="">— выберите хант —</option>
              {(hunts.data ?? []).map((h) => <option key={h.id} value={h.id}>{h.code} · {h.name}</option>)}
            </select>
          </label>
          <label className="block">
            <span className={LABEL}>Запрос</span>
            <select value={form.queryPk ?? ''} onChange={(e) => pickQuery(e.target.value)} disabled={form.huntId === null || !hunt.data} className={FIELD}>
              <option value="">{form.huntId !== null && hunt.isLoading ? 'загрузка…' : '— выберите запрос —'}</option>
              {(hunt.data?.queries ?? []).map((q) => <option key={q.id} value={q.id}>{q.query_id}{q.enabled ? '' : ' (выключен)'}</option>)}
            </select>
            {hunt.isError && <span className="mt-1 block text-xs text-kind-1">{apiMessage(hunt.error, 'Не удалось загрузить запросы ханта')}</span>}
          </label>
          <p className="text-xs text-text-secondary md:col-span-2">Запрос подставляется копией: его можно править ниже, библиотека от этого не меняется.</p>
        </div>
      )}

      <label className="mb-3 block">
        <span className={LABEL}>Запрос (PDQL)</span>
        <textarea value={form.query} onChange={(e) => patch({ query: e.target.value })} rows={4} spellCheck={false} className={`${FIELD} font-mono`} />
      </label>
      <div className="mb-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_9rem]">
        <label className="block">
          <span className={LABEL}>Поля</span>
          <input value={form.fields} onChange={(e) => patch({ fields: e.target.value })} className={`${FIELD} font-mono`} placeholder="time, src.ip, dst.hostname" />
          <span className={HINT}>Через запятую, как в запросе библиотеки.</span>
        </label>
        <label className="block">
          <span className={LABEL}>Подписи колонок</span>
          <input value={form.labels} onChange={(e) => patch({ labels: e.target.value })} className={FIELD} placeholder="Время, Источник, Домен" />
          <span className={HINT}>
            {labelsMismatch
              ? `подписей ${labelCount}, полей ${fieldCount} — лишние подписи отбрасываются, недостающие берутся из имён полей`
              : 'По одной на поле; пусто — подписи по умолчанию.'}
          </span>
        </label>
        <label className="block">
          <span className={LABEL}>Предел событий</span>
          <input value={form.limit} onChange={(e) => patch({ limit: e.target.value })} inputMode="numeric" className={`${FIELD} font-mono`} placeholder={String(settings.data?.default_limit ?? 5000)} />
          <span className={HINT}>На один кусок.</span>
        </label>
      </div>

      <div className="mb-3 flex flex-wrap items-start gap-x-8 gap-y-3">
        <div>
          <span className={LABEL}>Период</span>
          <div className="mb-2 flex items-center gap-4">
            {([['months', 'Месяцев назад'], ['dates', 'Даты']] as const).map(([value, label]) => (
              <label key={value} className="flex items-center gap-1.5 text-xs text-text">
                <input type="radio" name="deep-period" checked={form.period === value} onChange={() => patch({ period: value })} className="accent-primary" />
                {label}
              </label>
            ))}
          </div>
          {form.period === 'months' ? (
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <div className="w-20"><input value={form.months} onChange={(e) => patch({ months: e.target.value })} inputMode="numeric" aria-label="Глубина, месяцев" className={`${FIELD} font-mono`} placeholder={defaultMonths !== undefined ? String(defaultMonths) : '3'} /></div>
              назад от сейчас{defaultMonths !== undefined && `; пусто — ${defaultMonths} из настроек`}
            </label>
          ) : (
            <div className="flex flex-wrap items-center gap-2 text-xs text-text-secondary">
              <div className="w-52"><input type="datetime-local" value={form.dateFrom} onChange={(e) => patch({ dateFrom: e.target.value })} aria-label="Начало периода" className={FIELD} /></div>
              —
              <div className="w-52"><input type="datetime-local" value={form.dateTo} onChange={(e) => patch({ dateTo: e.target.value })} aria-label="Конец периода" className={FIELD} /></div>
            </div>
          )}
        </div>
        <label className="block min-w-64 flex-1">
          <span className={LABEL}>Название</span>
          <input value={form.title} onChange={(e) => patch({ title: e.target.value })} maxLength={255} className={FIELD} placeholder="по умолчанию — код и номер запроса или начало запроса" />
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={submit} loading={create.isPending} disabled={problem !== null}>
          <Telescope size={14} aria-hidden /> Запустить
        </Button>
        {problem && <span className="text-xs text-text-secondary">{problem}</span>}
        {create.isError && <span className="text-xs text-kind-1" role="alert">{apiMessage(create.error, 'Не удалось запустить большой хант')}</span>}
        {created && (
          <span className="text-xs text-text" role="status">
            Поставлен в очередь: <Link to={`/siem/hunting/deep/${created.id}`} className="text-primary hover:underline">{created.title}</Link>
          </span>
        )}
      </div>
    </section>
  )
}

// --- Список ---------------------------------------------------------------------

function DeepList({ items, loading, errorMessage, onRetry }: { items: DeepView[]; loading: boolean; errorMessage: string | null; onRetry: () => void }) {
  const { navigate } = useRouter()
  const { write } = useCan()
  const qc = useQueryClient()
  const cols = useColumnWidths('siem-th-deep-columns', COLUMNS)
  const cancel = useCancelDeep()

  if (loading) return <FullPageSpinner />
  if (errorMessage) return <ErrorState message={errorMessage} onRetry={onRetry} />
  if (items.length === 0) {
    return <EmptyState icon={Telescope} title="Больших хантов ещё не было" description="Заполните форму выше или откройте запрос в библиотеке и нажмите «в большой хант»." />
  }

  function onCancel(d: DeepView) {
    // 409 — хант успел завершиться: список обновляется, чтобы строка показала итог.
    cancel.mutate(d.id, { onError: () => qc.invalidateQueries({ queryKey: TH_DEEP_KEY }) })
  }

  return (
    <>
      {cancel.isError && <p className="mb-2 text-xs text-kind-1" role="alert">{apiMessage(cancel.error, 'Не удалось отменить большой хант')}</p>}
      <div data-col-resize-root className="overflow-x-auto rounded border border-grid bg-surface">
        <div className="grid border-b border-grid text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
          <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
        </div>
        {items.map((d) => {
          const active = DEEP_ACTIVE.includes(d.status)
          return (
            <div
              key={d.id}
              {...clickableRow(() => navigate(`/siem/hunting/deep/${d.id}`))}
              className={cn(ROW_FOCUS, 'grid cursor-pointer items-center border-b border-grid text-xs hover:bg-row-hover')}
              style={{ ...cols.gridStyle, height: ROW_HEIGHT }}
            >
              <div className="min-w-0 truncate px-2 text-text" title={d.title}>{d.title}</div>
              <div className="min-w-0 truncate px-2 text-text-secondary" title={d.source ? `${d.source.hunt_code} ${d.source.query_id ?? ''}` : 'свой запрос'}>
                {d.source ? <span className="font-mono">{d.source.hunt_code}{d.source.query_id ? ` · ${d.source.query_id}` : ''}</span> : 'свой запрос'}
              </div>
              <div className="min-w-0 truncate px-2 tabular-nums text-text-secondary" title={ruPeriod(d.period_from, d.period_to)}>{ruPeriod(d.period_from, d.period_to)}</div>
              <div className="flex min-w-0 flex-col gap-1 px-2">
                <DeepStatus deep={d} className="truncate" />
                {d.status === 'running' && <ProgressBar done={d.slices_done} total={d.slices_total} label={`Ход ханта «${d.title}»`} />}
              </div>
              <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text">{d.events}</div>
              <div className="min-w-0 px-2">{d.status_state ? <StatusBadge status={d.status_state} /> : <span className="text-text-secondary">—</span>}</div>
              <div className="min-w-0 px-2">
                {write && active && (
                  <Button
                    onClick={(e) => { e.stopPropagation(); onCancel(d) }}
                    loading={cancel.isPending && cancel.variables === d.id}
                    className="px-2 py-0.5 text-xs"
                    aria-label={`Отменить «${d.title}»`}
                  >
                    Отменить
                  </Button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </>
  )
}
