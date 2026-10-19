import { useState, type ReactNode } from 'react'
import { ArrowLeft, Plus } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, useRouter } from '@/lib/router'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { useDeleteHunt, useHunt, useSaveHunt, useToggleHunt, useToggleQuery } from '../api/queries'
import type { HuntView } from '../api/types'
import { QueryEditor } from '../components/QueryEditor'
import { QueryStatus } from '../components/QueryStatus'
import { draftSignature, emptyHunt, emptyQuery, fromHunt, toHuntIn, type HuntDraft, type QueryDraft } from '../draft'
import { ruStamp } from '../format'

const LINK = 'inline-flex items-center gap-1 rounded text-xs text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const LABEL = 'mb-1 block text-xs font-medium text-text'
const SECTION_TITLE = 'mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'
const TH = 'px-2 py-2 text-left text-[11px] tracking-wide text-text-secondary uppercase'
const TD = 'truncate px-2 py-1.5'

const RUN_COLUMNS: ColumnDef[] = [
  { key: 'at', label: 'Начало', width: 144 },
  { key: 'query', label: 'Запрос', width: 80 },
  { key: 'status', label: 'Исход', width: 104 },
  { key: 'duration', label: 'Длительность', width: 128, align: 'right' },
  { key: 'events', label: 'Событий', width: 96, align: 'right' },
  { key: 'note', label: 'Находка или ошибка', width: 320, flex: true },
]

const FINDING_COLUMNS: ColumnDef[] = [
  { key: 'status', label: 'Статус', width: 144 },
  { key: 'kind', label: 'Вид', width: 112 },
  { key: 'query', label: 'Запрос', width: 80 },
  { key: 'period', label: 'Период', width: 320, flex: true },
  { key: 'events', label: 'Событий', width: 96, align: 'right' },
  { key: 'created', label: 'Найдена', width: 144 },
]

const seconds = (ms: number | null) => (ms === null ? '—' : `${(ms / 1000).toFixed(1)} с`)

/** Карточка ханта: `new` — создание, число — правка сохранённого. */
export function HuntPage({ id }: { id: number | 'new' }) {
  const hunt = useHunt(typeof id === 'number' && Number.isFinite(id) ? id : undefined)

  if (id === 'new') return <HuntForm key="new" hunt={undefined} />
  if (hunt.isLoading) return <FullPageSpinner />
  if (!hunt.data) {
    const message = hunt.error instanceof ApiRequestError ? hunt.error.message : 'Хант не найден'
    return <div className="p-6"><ErrorState message={message} onRetry={hunt.isError ? () => hunt.refetch() : undefined} /></div>
  }
  return <HuntForm key={hunt.data.id} hunt={hunt.data} />
}

/**
 * Форма ханта. Черновик живёт здесь, а выключатели сохранённого ханта и его запросов идут отдельными ручками
 * и не сбрасывают несохранённые правки; при сохранении на сервер уходят текущие значения всех выключателей.
 * Новый хант по умолчанию включён (попадёт в ближайшую ночь); выключатель на форме создания правит черновик.
 */
function HuntForm({ hunt }: { hunt: HuntView | undefined }) {
  const { navigate } = useRouter()
  const { write } = useCan()
  const [draft, setDraft] = useState<HuntDraft>(() => (hunt ? fromHunt(hunt) : emptyHunt()))
  const [confirmDelete, setConfirmDelete] = useState(false)
  const save = useSaveHunt()
  const remove = useDeleteHunt()
  const toggleHunt = useToggleHunt()
  const toggleQuery = useToggleQuery()
  const runCols = useColumnWidths('siem-th-hunt-runs-columns', RUN_COLUMNS)
  const findingCols = useColumnWidths('siem-th-hunt-findings-columns', FINDING_COLUMNS)

  const readOnly = !write
  const dirty = !hunt || draftSignature(draft, true) !== draftSignature(fromHunt(hunt), true)
  const enabled = hunt ? hunt.enabled : draft.enabled

  function patch(next: Partial<HuntDraft>) {
    setDraft((d) => ({ ...d, ...next }))
  }
  function patchQuery(key: string, next: Partial<QueryDraft>) {
    setDraft((d) => ({ ...d, queries: d.queries.map((q) => (q.key === key ? { ...q, ...next } : q)) }))
  }

  function onSave() {
    save.mutate({ id: hunt?.id, body: toHuntIn(draft, hunt) }, {
      onSuccess: (saved) => {
        if (hunt) setDraft(fromHunt(saved))
        else navigate(`/siem/hunting/library/${saved.id}`, { replace: true })
      },
    })
  }

  function onToggleHunt(next: boolean) {
    if (hunt) toggleHunt.mutate({ id: hunt.id, enabled: next })
    else patch({ enabled: next })
  }

  function onToggleQuery(q: QueryDraft, next: boolean) {
    if (q.pk === null) patchQuery(q.key, { enabled: next })
    else toggleQuery.mutate({ queryPk: q.pk, enabled: next })
  }

  const errors = ([save.error, toggleHunt.error, toggleQuery.error, remove.error] as unknown[])
    .filter((e) => e instanceof Error)
    .map((e) => (e instanceof ApiRequestError ? e.message : 'Не удалось выполнить'))

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <header className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-grid bg-surface px-4 py-2.5">
        <Link to="/siem/hunting/library" className={LINK}><ArrowLeft size={13} aria-hidden /> Библиотека</Link>
        <h1 className="text-sm font-semibold text-text">
          {hunt ? <><span className="font-mono">{hunt.code}</span> <span className="font-normal text-text-secondary">{hunt.name}</span></> : 'Новый хант'}
        </h1>
        <label className="flex items-center gap-1.5 text-xs text-text">
          <input
            type="checkbox"
            checked={enabled}
            disabled={readOnly || toggleHunt.isPending}
            onChange={(e) => onToggleHunt(e.target.checked)}
            className="accent-primary"
          />
          хант включён
        </label>
        {hunt && <span className="text-xs text-text-secondary">изменён {ruStamp(hunt.updated_at)}, {hunt.updated_by}</span>}
        {write && (
          <div className="ml-auto flex items-center gap-2">
            {hunt && <Button variant="danger" onClick={() => setConfirmDelete(true)} className="px-2.5 py-1 text-xs">Удалить хант</Button>}
            <Button variant="primary" onClick={onSave} loading={save.isPending} disabled={!dirty} className="px-2.5 py-1 text-xs">
              {hunt ? 'Сохранить' : 'Создать хант'}
            </Button>
          </div>
        )}
        {errors.length > 0 && <p className="basis-full text-xs text-kind-1" role="alert">{errors.join('; ')}</p>}
      </header>

      <div className="flex flex-col gap-4 p-4">
        <section className="rounded border border-grid bg-surface p-4">
          <div className="grid gap-3 md:grid-cols-[10rem_minmax(0,1fr)_10rem]">
            <label className="block">
              <span className={LABEL}>Код</span>
              <input
                value={draft.code}
                onChange={(e) => patch({ code: e.target.value })}
                disabled={readOnly || !!hunt}
                title={hunt ? 'Код после создания не меняется: на него ссылаются находки и история прогонов' : undefined}
                maxLength={64}
                className={`${FIELD} font-mono`}
              />
            </label>
            <label className="block">
              <span className={LABEL}>Название</span>
              <input value={draft.name} onChange={(e) => patch({ name: e.target.value })} disabled={readOnly} className={FIELD} />
            </label>
            <label className="block">
              <span className={LABEL}>Техника ATT&amp;CK</span>
              <input value={draft.technique_id} onChange={(e) => patch({ technique_id: e.target.value })} disabled={readOnly} placeholder="T1234.001" className={`${FIELD} font-mono`} />
            </label>
          </div>
          <label className="mt-3 block">
            <span className={LABEL}>Описание</span>
            <textarea value={draft.description} onChange={(e) => patch({ description: e.target.value })} disabled={readOnly} rows={3} className={FIELD} />
          </label>
        </section>

        <section>
          <div className="mb-2 flex items-center gap-3">
            <div className={`${SECTION_TITLE} mb-0`}>Запросы ({draft.queries.length})</div>
            {write && (
              <Button onClick={() => patch({ queries: [...draft.queries, emptyQuery(draft.queries)] })} className="px-2 py-0.5 text-xs">
                <Plus size={12} aria-hidden /> запрос
              </Button>
            )}
          </div>
          <div className="flex flex-col gap-3">
            {draft.queries.length === 0 && <p className="rounded border border-dashed border-grid px-4 py-6 text-center text-xs text-text-secondary">У ханта нет запросов: сервер не сохранит хант без запроса.</p>}
            {draft.queries.map((q) => {
              const view = q.pk === null ? undefined : hunt?.queries.find((s) => s.id === q.pk)
              return (
                <QueryEditor
                  key={q.key}
                  draft={q}
                  view={view}
                  enabled={view ? view.enabled : q.enabled}
                  readOnly={readOnly}
                  toggling={toggleQuery.isPending && toggleQuery.variables?.queryPk === q.pk}
                  onChange={(next) => patchQuery(q.key, next)}
                  onToggle={(next) => onToggleQuery(q, next)}
                  onRemove={() => setDraft((d) => ({ ...d, queries: d.queries.filter((x) => x.key !== q.key) }))}
                />
              )
            })}
          </div>
        </section>

        {hunt && (
          <>
            <Block title={`История прогонов (${hunt.runs.length})`} empty={hunt.runs.length === 0 ? 'Этот хант ещё не запускался.' : null}>
              <table className="text-xs" style={runCols.tableStyle}>
                <ColGroup cols={runCols} />
                <thead>
                  <tr className="border-b border-grid"><ResizableHeader cols={runCols} className={TH} /></tr>
                </thead>
                <tbody>
                  {hunt.runs.map((r) => (
                    <tr key={r.id} className="border-b border-grid">
                      <td className={`${TD} tabular-nums text-text-secondary`}>{ruStamp(r.started_at)}</td>
                      <td className={`${TD} font-mono text-text-secondary`}>{r.query_id}</td>
                      <td className={TD}><QueryStatus status={r.status} /></td>
                      <td className={`${TD} text-right font-mono tabular-nums text-text-secondary`}>{seconds(r.duration_ms)}</td>
                      <td className={`${TD} text-right font-mono tabular-nums text-text`}>{r.events}</td>
                      <td className={`${TD} text-text-secondary`} title={r.error ?? undefined}>
                        {r.finding_id !== null ? <Link to={`/siem/hunting/findings/${r.finding_id}`} className={LINK}>находка #{r.finding_id}</Link> : r.error ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Block>

            <Block title={`Находки ханта (${hunt.findings.length})`} empty={hunt.findings.length === 0 ? 'Находок пока нет.' : null}>
              <table className="text-xs" style={findingCols.tableStyle}>
                <ColGroup cols={findingCols} />
                <thead>
                  <tr className="border-b border-grid"><ResizableHeader cols={findingCols} className={TH} /></tr>
                </thead>
                <tbody>
                  {hunt.findings.map((f) => (
                    <tr key={f.id} className="border-b border-grid">
                      <td className={TD}>
                        <Link to={`/siem/hunting/findings/${f.id}`} className="rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title={`Открыть находку #${f.id}`}>
                          <StatusBadge status={f.status} />
                        </Link>
                      </td>
                      <td className={`${TD} text-text-secondary`}>{f.kind === 'deep' ? 'большой хант' : 'ночная'}</td>
                      <td className={`${TD} font-mono text-text-secondary`}>{f.query_id}</td>
                      <td className={`${TD} tabular-nums text-text-secondary`}>{ruStamp(f.period_from)} — {ruStamp(f.period_to)}</td>
                      <td className={`${TD} text-right font-mono tabular-nums text-text`}>{f.event_count}</td>
                      <td className={`${TD} tabular-nums text-text-secondary`}>{ruStamp(f.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Block>
          </>
        )}
      </div>

      {confirmDelete && hunt && (
        <div role="dialog" aria-modal="true" aria-label="Удалить хант" className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
            <div className="mb-2 text-sm font-semibold text-text">Удалить хант {hunt.code}?</div>
            <p className="mb-4 text-xs text-text-secondary">Хант пропадёт из библиотеки и ночных прогонов. Находки и история прогонов остаются.</p>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setConfirmDelete(false)}>Отмена</Button>
              <Button
                variant="danger"
                loading={remove.isPending}
                onClick={() => remove.mutate(hunt.id, { onSuccess: () => navigate('/siem/hunting/library', { replace: true }), onSettled: () => setConfirmDelete(false) })}
              >
                Удалить
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/** Раздел с таблицей внутри карточки: пустой — одной строкой вместо шапки без строк. */
function Block({ title, empty, children }: { title: string; empty: string | null; children: ReactNode }) {
  return (
    <section>
      <div className={SECTION_TITLE}>{title}</div>
      {empty ? (
        <p className="rounded border border-dashed border-grid px-4 py-6 text-center text-xs text-text-secondary">{empty}</p>
      ) : (
        <div data-col-resize-root className="overflow-x-auto rounded border border-grid bg-surface">{children}</div>
      )}
    </section>
  )
}
