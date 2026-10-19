import { useEffect, useRef, useState } from 'react'
import { ArrowLeft } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, useRouter } from '@/lib/router'
import { FindingWorkBlock } from '@/platform/findings/FindingWorkBlock'
import { TH_DEEP_KEY, TH_FINDINGS_KEY, useCancelDeep, useDeepHunt, useRerunDeep, useSaveDeepToLibrary } from '../api/queries'
import { DEEP_ACTIVE, TH_MODULE, TH_SCOPE, type DeepDetail } from '../api/types'
import { EventsTable } from '../components/EventsTable'
import { DeepStatus, ProgressBar } from '../components/JobStatus'
import { apiMessage, ruPeriod, ruStamp } from '../format'

const LINK = 'inline-flex items-center gap-1 rounded text-xs text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const LABEL = 'mb-1 block text-xs font-medium text-text'
const SECTION_TITLE = 'mb-3 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

/** Карточка большого ханта: параметры, ход по кускам, события находки и работа со статусом. */
export function DeepHuntPage({ id }: { id: number }) {
  const deep = useDeepHunt(Number.isFinite(id) ? id : undefined)

  if (deep.isLoading) return <FullPageSpinner />
  if (!deep.data) {
    return <div className="p-6"><ErrorState message={apiMessage(deep.error, 'Большой хант не найден')} onRetry={deep.isError ? () => deep.refetch() : undefined} /></div>
  }
  return <DeepCard d={deep.data} />
}

function DeepCard({ d }: { d: DeepDetail }) {
  const { navigate } = useRouter()
  const { write } = useCan()
  const qc = useQueryClient()
  const cancel = useCancelDeep()
  const rerun = useRerunDeep()
  const [saving, setSaving] = useState(false)

  const active = DEEP_ACTIVE.includes(d.status)
  const finding = d.finding
  const findingId = finding?.id

  // Пока хант идёт, находка растёт с каждым куском: таблица событий не опрашивается сама, поэтому сбрасываем её кэш при росте счётчика.
  const seenEvents = useRef(d.events)
  useEffect(() => {
    if (seenEvents.current === d.events) return
    seenEvents.current = d.events
    if (findingId !== undefined) qc.invalidateQueries({ queryKey: [...TH_FINDINGS_KEY, 'events', findingId] })
  }, [qc, findingId, d.events])

  function onCancel() {
    // 409 — хант успел завершиться: карточка обновляется и показывает итог.
    cancel.mutate(d.id, { onError: () => qc.invalidateQueries({ queryKey: TH_DEEP_KEY }) })
  }

  const errors = ([cancel.error, rerun.error] as unknown[]).filter((e) => e instanceof Error).map((e) => apiMessage(e, 'Не удалось выполнить'))
  const labelOf = (i: number) => d.labels[i] ?? ''

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <header className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-grid bg-surface px-4 py-2.5">
        <Link to="/siem/hunting/deep" className={LINK}><ArrowLeft size={13} aria-hidden /> Большие ханты</Link>
        <h1 className="text-sm font-semibold text-text">{d.title}</h1>
        <DeepStatus deep={d} className="text-xs" />
        {write && (
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {active && <Button onClick={onCancel} loading={cancel.isPending} className="px-2.5 py-1 text-xs">Отменить</Button>}
            {d.source === null && <Button onClick={() => setSaving(true)} className="px-2.5 py-1 text-xs">Сохранить в библиотеку</Button>}
            <Button
              variant="primary"
              onClick={() => rerun.mutate(d.id, { onSuccess: (created) => navigate(`/siem/hunting/deep/${created.id}`) })}
              loading={rerun.isPending}
              className="px-2.5 py-1 text-xs"
              title="Новый хант с теми же запросом и периодом; этот остаётся как есть"
            >
              Запустить ещё раз
            </Button>
          </div>
        )}
        {errors.length > 0 && <p className="basis-full text-xs text-kind-1" role="alert">{errors.join('; ')}</p>}
      </header>

      <div className="flex flex-col gap-4 p-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <section className="rounded border border-grid bg-surface p-4">
            <div className={SECTION_TITLE}>Параметры</div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs">
              <dt className="text-text-secondary">Источник</dt>
              <dd className="text-text">{d.source ? <span className="font-mono">{d.source.hunt_code}{d.source.query_id ? ` · ${d.source.query_id}` : ''}</span> : 'свой запрос'}</dd>
              <dt className="text-text-secondary">Период</dt>
              <dd className="tabular-nums text-text">{ruPeriod(d.period_from, d.period_to)}</dd>
              <dt className="text-text-secondary">Предел на кусок</dt>
              <dd className="font-mono tabular-nums text-text">{d.limit}</dd>
              <dt className="text-text-secondary">Запущен</dt>
              <dd className="text-text">{ruStamp(d.created_at)}, {d.created_by}</dd>
              <dt className="text-text-secondary">Завершён</dt>
              <dd className="text-text">{ruStamp(d.finished_at)}</dd>
            </dl>
            <div className="mt-3 text-xs text-text-secondary">Запрос</div>
            <pre className="mt-1 max-h-40 overflow-auto rounded border border-grid bg-app-bg p-2 font-mono text-xs whitespace-pre-wrap text-text">{d.query}</pre>
            <div className="mt-3 text-xs text-text-secondary">Поля и подписи колонок</div>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {d.fields.map((f, i) => (
                <li key={f} className="rounded border border-grid px-1.5 py-0.5 text-xs text-text">
                  <span className="font-mono">{f}</span>{labelOf(i) && <span className="text-text-secondary"> → {labelOf(i)}</span>}
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded border border-grid bg-surface p-4">
            <div className={SECTION_TITLE}>Ход по кускам</div>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
              <span className="text-text"><DeepStatus deep={d} /></span>
              <span className="font-mono tabular-nums text-text-secondary">{d.slices_done} / {d.slices_total}</span>
            </div>
            <ProgressBar done={d.slices_done} total={d.slices_total} label="Пройдено кусков" />
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs">
              <dt className="text-text-secondary">Событий собрано</dt>
              <dd className="font-mono tabular-nums text-text">{d.events}</dd>
              <dt className="text-text-secondary">Окон с пределом</dt>
              <dd className={d.limit_hit_slices > 0 ? 'text-kind-1' : 'text-text'}>
                {d.limit_hit_slices > 0 ? `${d.limit_hit_slices} — в них событий могло быть больше предела` : 'нет'}
              </dd>
              <dt className="text-text-secondary">Неполная выборка</dt>
              <dd className={d.partial ? 'text-kind-1' : 'text-text'}>
                {d.partial ? (active ? 'идёт — события собраны не за весь период' : 'да — хант остановлен, события собраны не за весь период') : 'нет'}
              </dd>
            </dl>
            {d.error && <p className="mt-3 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2 text-xs text-text" role="alert">{d.error}</p>}
          </section>
        </div>

        {finding ? (
          <>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
              <section className="rounded border border-grid bg-surface p-4">
                <FindingWorkBlock
                  module={TH_MODULE}
                  scopeId={TH_SCOPE}
                  findingKey={finding.key}
                  title={`Большой хант #${d.id}`}
                  severity="medium"
                  onChanged={() => { qc.invalidateQueries({ queryKey: TH_FINDINGS_KEY }); qc.invalidateQueries({ queryKey: TH_DEEP_KEY }) }}
                />
              </section>
              <section className="rounded border border-grid bg-surface p-4">
                <div className={SECTION_TITLE}>Находка</div>
                <p className="text-xs text-text-secondary">
                  События всех кусков собраны в одну находку. <Link to={`/siem/hunting/findings/${finding.id}`} className={LINK}>Открыть карточку находки</Link>
                </p>
              </section>
            </div>
            {finding.events_purged || finding.columns.length === 0 ? (
              <p className="rounded border border-dashed border-grid px-4 py-8 text-center text-xs text-text-secondary">
                {finding.events_purged ? 'События этой находки удалены по сроку хранения. Саму находку и решения по ней это не затрагивает.' : 'У находки нет колонок событий.'}
              </p>
            ) : (
              <EventsTable key={finding.id} findingId={finding.id} columns={finding.columns} storageKey="siem-th-events-columns:deep" />
            )}
          </>
        ) : (
          <p className="rounded border border-dashed border-grid px-4 py-8 text-center text-xs text-text-secondary">
            {active ? 'Находка появится после первого куска, в котором найдутся события.' : d.status === 'done' ? 'За весь период событий не нашлось — находки нет.' : 'Событий собрать не успели — находки нет.'}
          </p>
        )}
      </div>

      {saving && <SaveDialog d={d} onClose={() => setSaving(false)} />}
    </div>
  )
}

/** Свой запрос — в библиотеку выключенным хантом с одним запросом: в ночь он пойдёт, когда его включат. */
function SaveDialog({ d, onClose }: { d: DeepDetail; onClose: () => void }) {
  const { navigate } = useRouter()
  const save = useSaveDeepToLibrary()
  const [code, setCode] = useState('')
  const [name, setName] = useState(d.title)
  const ready = code.trim() !== '' && name.trim() !== ''

  function submit() {
    if (!ready) return
    save.mutate({ id: d.id, code: code.trim(), name: name.trim() }, { onSuccess: (hunt) => navigate(`/siem/hunting/library/${hunt.id}`) })
  }

  return (
    <div role="dialog" aria-modal="true" aria-label="Сохранить запрос в библиотеку" className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
      <form onSubmit={(e) => { e.preventDefault(); submit() }} className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">Сохранить запрос в библиотеку</div>
        <p className="mb-3 text-xs text-text-secondary">Появится хант с одним запросом, выключенный: в ночные прогоны он попадёт, когда его включат.</p>
        <label className="mb-3 block">
          <span className={LABEL}>Код</span>
          <input value={code} onChange={(e) => setCode(e.target.value)} maxLength={64} autoFocus className={`${FIELD} font-mono`} placeholder="TH-XXX-001" />
        </label>
        <label className="mb-3 block">
          <span className={LABEL}>Название</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={255} className={FIELD} />
        </label>
        {save.isError && <p className="mb-3 text-xs text-kind-1" role="alert">{apiMessage(save.error, 'Не удалось сохранить в библиотеку')}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отмена</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!ready}>Сохранить</Button>
        </div>
      </form>
    </div>
  )
}
