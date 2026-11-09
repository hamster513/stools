import { useImperativeHandle, useState, type Ref } from 'react'
import { Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Link } from '@/lib/router'
import { useCheckQuery, useReadFilter } from '../api/queries'
import type { CheckWindow, QueryView } from '../api/types'
import type { QueryDraft } from '../draft'
import { ruStamp } from '../format'
import { CheckResult, WindowSelect } from './CheckResult'
import { SavedFilterControl } from './SavedFilterControl'
import { QueryStatus } from './QueryStatus'

const LABEL = 'mb-1 block text-xs font-medium text-text'
// Тот же текст, что `LOGIN_REJECTED` в api/hosts.py: им сервер называет отказ авторизации в MaxPatrol.
const LOGIN_REJECTED = 'вход отклонён'

/** Исход проверки для карточки ханта: `auth` — дальше проверять бессмысленно, следующие запросы упрутся в то же. */
export type CheckStatus = 'ok' | 'error' | 'auth'

/** Запуск проверки снаружи — кнопкой «Проверить все запросы» карточки ханта. */
export interface QueryCheckHandle {
  check: (window: CheckWindow) => Promise<CheckStatus>
}

const LINK = 'rounded text-xs text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Один запрос ханта: многострочный PDQL, поля, подписи колонок, предел, выключатель и «проверить запрос».
 * Правка идёт в черновик карточки (`onChange`); выключатель сохранённого запроса — отдельная ручка (`onToggle`),
 * у ещё не сохранённого он правит черновик. `view` — сохранённая версия: последний запуск, ссылка «в большой хант».
 * Только чтение: поля заблокированы, кнопок нет.
 */
export function QueryEditor({ ref, huntId, draft, view, enabled, readOnly, toggling, columnsKey, onChange, onToggle, onRemove }: {
  ref?: Ref<QueryCheckHandle>
  /** Номер ханта в базе — ссылка «в большой хант» несёт его, чтобы страница читала одну карточку; у несохранённого ханта пуст. */
  huntId: number | undefined
  draft: QueryDraft
  view: QueryView | undefined
  /** Текущий выключатель: у сохранённого запроса — серверный. */
  enabled: boolean
  readOnly: boolean
  toggling: boolean
  /** Ключ ширин колонок результата проверки — тот же, что у событий находки этого запроса. */
  columnsKey: string
  onChange: (patch: Partial<QueryDraft>) => void
  onToggle: (enabled: boolean) => void
  onRemove: () => void
}) {
  const check = useCheckQuery()
  const readFilter = useReadFilter()
  const [confirmed, setConfirmed] = useState(false)
  const [span, setSpan] = useState<CheckWindow>('24h')
  const [hidden, setHidden] = useState(false)

  async function run(win: CheckWindow): Promise<CheckStatus> {
    setHidden(false)
    try {
      const out = await check.mutateAsync({ query: draft.query, fields: draft.fields, fields_label: draft.fields_label, is_full_pdql: draft.is_full_pdql, window: win })
      if (out.ok) return 'ok'
      return out.message === LOGIN_REJECTED ? 'auth' : 'error'
    } catch (exc) {
      // Отказ нашего API, который повторится у всех запросов (подключение не настроено, сессия истекла,
      // нет прав), останавливает обход; разовый сбой или занятость сервера — нет.
      return exc instanceof ApiRequestError && [400, 401, 403].includes(exc.status) ? 'auth' : 'error'
    }
  }

  // Проверка из шапки ханта ставит выбранное там окно и в этот запрос: видно, за какой срок результат.
  useImperativeHandle(ref, () => ({
    check: (win) => {
      setSpan(win)
      return run(win)
    },
  }))

  // Результат проверки относится к тексту, который проверяли: после правки запроса или полей он устарел.
  function edit(patch: Partial<QueryDraft>) {
    // Подписи тоже входят в результат (это его колонки), поэтому их правка его устаревает.
    if ('query' in patch || 'fields' in patch || 'fields_label' in patch || 'is_full_pdql' in patch) check.reset()
    onChange(patch)
  }

  const checkError = check.error instanceof ApiRequestError ? check.error.message : check.isError ? 'Не удалось проверить запрос' : null
  const last = view?.last

  return (
    <section className="rounded border border-grid bg-surface p-3" aria-label={`Запрос ${draft.query_id}`}>
      {!view && <p className={`mb-2 text-xs ${draft.siem_filter_id ? 'text-text-secondary' : 'text-kind-1'}`}>
        {draft.siem_filter_id ? 'Выбран фильтр SIEM; связь сохранится вместе с хантом' : 'Локальный запрос: фильтра в SIEM нет. После сохранения его можно создать по кнопке.'}
      </p>}
      {view && <div className="mb-2"><SavedFilterControl value={view.saved_filter} kind="query" id={view.id} readOnly={readOnly}
        dirty={draft.query !== view.query || draft.fields !== view.fields || draft.name !== (view.name ?? view.query_id) || draft.is_full_pdql !== (view.is_full_pdql ?? false)} /></div>}
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        {draft.pk === null && !readOnly ? (
          <div className="w-24"><input value={draft.query_id} onChange={(e) => edit({ query_id: e.target.value })} aria-label="Номер запроса" className={`${FIELD} font-mono`} maxLength={32} /></div>
        ) : (
          <span className="font-mono text-sm font-semibold text-text">{draft.query_id}</span>
        )}
        <label className="flex items-center gap-1.5 text-xs text-text">
          <input
            type="checkbox"
            checked={enabled}
            disabled={readOnly || toggling}
            onChange={(e) => onToggle(e.target.checked)}
            className="accent-primary"
          />
          включён
        </label>
        {last && (
          <span className="text-xs text-text-secondary">
            последний запуск {ruStamp(last.at)}: <QueryStatus status={last.status} />, событий {last.events}
          </span>
        )}
        {view && view.new_findings > 0 && <span className="text-xs text-text">новых находок: {view.new_findings}</span>}
        <div className="ml-auto flex items-center gap-3">
          {view && <Link to={`/siem/hunting/deep?from=${view.id}${huntId !== undefined ? `&hunt=${huntId}` : ''}`} className={LINK} title="Запустить этот запрос за длинный период">в большой хант</Link>}
          {!readOnly && (
            confirmed ? (
              <span className="flex items-center gap-1.5 text-xs text-text-secondary">
                Убрать при сохранении?
                <Button variant="danger" onClick={onRemove} className="px-2 py-0.5 text-xs">Убрать</Button>
                <Button onClick={() => setConfirmed(false)} className="px-2 py-0.5 text-xs">Нет</Button>
              </span>
            ) : (
              <Button variant="ghost" onClick={() => setConfirmed(true)} aria-label={`Убрать запрос ${draft.query_id}`} className="px-1.5 py-1"><Trash2 size={14} aria-hidden /></Button>
            )
          )}
        </div>
      </div>

      {!readOnly && (draft.siem_filter_id || view?.saved_filter?.id) && <div className="mb-2">
        <Button type="button" loading={readFilter.isPending} onClick={() => readFilter.mutate(
          draft.siem_filter_id ?? view!.saved_filter!.id!,
          {onSuccess: q => edit({name: q.name, query: q.query, fields: q.fields, fields_label: q.fields_label,
            is_full_pdql: q.is_full_pdql, siem_filter_id: q.siem_filter_id})},
        )}>Обновить запрос из SIEM</Button>
        <span className="ml-2 text-xs text-text-secondary">заменит Name и PDQL в черновике; Description сохраняется</span>
        {readFilter.isError && <p role="alert" className="text-xs text-kind-1">{readFilter.error.message}</p>}
      </div>}
      <div className="mb-3 grid gap-2">
        <label><span className={LABEL}>Name — название фильтра SIEM</span>
          <input aria-label={`Name ${draft.query_id}`} value={draft.name} onChange={e => edit({name: e.target.value})} disabled={readOnly} maxLength={255} className={FIELD} />
        </label>
        <label><span className={LABEL}>Description — описание запроса</span>
          <textarea aria-label={`Description ${draft.query_id}`} value={draft.description} onChange={e => edit({description: e.target.value})} disabled={readOnly} rows={2} className={FIELD} />
        </label>
        <label className="flex items-center gap-2 text-xs text-text-secondary">
          <input type="checkbox" checked={draft.is_full_pdql} onChange={e => edit({is_full_pdql: e.target.checked})} disabled={readOnly} />
          Полный PDQL (включая select, sort и другие операции)
        </label>
      </div>
      <label className="block">
        <span className={LABEL}>{draft.is_full_pdql ? 'Полный запрос PDQL' : 'Условие фильтра (PDQL)'}</span>
        <textarea
          value={draft.query}
          onChange={(e) => edit({ query: e.target.value })}
          disabled={readOnly}
          rows={5}
          spellCheck={false}
          className={`${FIELD} font-mono text-xs leading-relaxed`}
        />
      </label>

      <div className="mt-2 grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_9rem]">
        <label className="block">
          <span className={LABEL}>{draft.is_full_pdql ? "Колонки результата (пусто — из ответа SIEM)" : "Поля через запятую"}</span>
          <input value={draft.fields} onChange={(e) => edit({ fields: e.target.value })} disabled={readOnly} spellCheck={false} className={`${FIELD} font-mono text-xs`} />
        </label>
        <label className="block">
          <span className={LABEL}>Подписи колонок</span>
          <input value={draft.fields_label} onChange={(e) => edit({ fields_label: e.target.value })} disabled={readOnly} placeholder="по одной на поле" className={FIELD} />
        </label>
        <label className="block">
          <span className={LABEL}>Предел событий</span>
          <input
            type="number"
            min={1}
            value={draft.limit}
            onChange={(e) => edit({ limit: e.target.value })}
            disabled={readOnly}
            placeholder="из настроек"
            className={`${FIELD} font-mono text-xs`}
          />
        </label>
      </div>

      {!readOnly && (
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <Button onClick={() => void run(span)} loading={check.isPending} disabled={!draft.query.trim() || (!draft.is_full_pdql && !draft.fields.trim())}>
            проверить запрос
          </Button>
          <WindowSelect value={span} onChange={setSpan} disabled={check.isPending} />
          {check.data && !check.data.ok && <span className="text-xs text-kind-1" role="alert">{check.data.message}</span>}
          {checkError && <span className="text-xs text-kind-1" role="alert">{checkError}</span>}
        </div>
      )}
      {!readOnly && check.data?.ok && !hidden && <CheckResult result={check.data} storageKey={columnsKey} onHide={() => setHidden(true)} />}
    </section>
  )
}
