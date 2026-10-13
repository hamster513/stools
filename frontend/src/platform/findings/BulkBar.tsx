import { useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useBulkChange, useUsersDirectory } from './queries'
import { MANUAL_STATUSES, NEEDS_REASON, STATUS_TITLES, type FindingChange, type FindingStatus } from './types'

/** Значение «очистить исполнителя» в списке: пустая строка уже значит «не менять». */
const NOBODY = '\u0000'
const SMALL = cn(FIELD, 'w-auto py-1 text-xs')

/**
 * Полоса массовых действий над выбранными находками (спека §6). Пустое поле —
 * «не менять»; исполнителя и срок можно и очистить. «Выбрать всё по фильтру»
 * показывается, только если модуль передал `onSelectAll`. Если модуль передал
 * `filter` (выбрано всё по фильтру), уходит фильтр, а не ключи: модуль с
 * фоновой задачей отвечает `{job_id}` — его получает `onJob`. Многозначные
 * фасеты в `filter` — списками (VM: `level: ['high', 'critical']`), как их
 * держит страница. Без права записи полосы нет.
 */
export function BulkBar({ module, scopeId, keys, total, onSelectAll, filter, onJob, onDone, onClear }: {
  module: string
  scopeId: number
  keys: string[]
  total: number
  onSelectAll?: () => void
  filter?: Record<string, unknown>
  onJob?: (jobId: number) => void
  onDone: (changed: number) => void
  onClear: () => void
}) {
  const { write } = useCan()
  const directory = useUsersDirectory()
  const bulk = useBulkChange()
  const [status, setStatus] = useState<FindingStatus | ''>('')
  const [assignee, setAssignee] = useState('')
  const [due, setDue] = useState('')
  const [clearDue, setClearDue] = useState(false)
  const [riskUntil, setRiskUntil] = useState('')
  const [comment, setComment] = useState('')

  if (!write || keys.length === 0) return null

  const change: FindingChange = {}
  if (status) change.status = status
  if (assignee) change.assignee = assignee === NOBODY ? null : assignee
  if (clearDue) change.due_date = null
  else if (due) change.due_date = due
  if (status === 'risk_accepted' && riskUntil) change.risk_until = riskUntil
  if (comment.trim()) change.comment = comment.trim()
  const needsReason = status !== '' && NEEDS_REASON.includes(status)
  const blocked = Object.keys(change).length === 0 || (needsReason && !change.comment)

  function apply() {
    bulk.mutate({ module, scope_id: scopeId, ...(filter ? { filter } : { keys }), change }, {
      onSuccess: (result) => {
        setStatus(''); setAssignee(''); setDue(''); setClearDue(false); setRiskUntil(''); setComment('')
        if ('job_id' in result) onJob?.(result.job_id)
        else onDone(result.changed)
      },
    })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-grid bg-row-selected px-4 py-2 text-xs">
      {filter
        ? <span className="text-text">Выбрано всё по фильтру: <span className="font-mono tabular-nums">{total}</span></span>
        : <span className="text-text">Выбрано <span className="font-mono tabular-nums">{keys.length}</span> из <span className="font-mono tabular-nums">{total}</span></span>}
      {onSelectAll && !filter && keys.length < total && <Button variant="ghost" className="px-2 py-1 text-xs" onClick={onSelectAll}>выбрать всё по фильтру</Button>}
      <select aria-label="Статус" className={SMALL} value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | '')}>
        <option value="">статус: не менять</option>
        {MANUAL_STATUSES.map((s) => <option key={s} value={s}>{STATUS_TITLES[s]}</option>)}
      </select>
      <select aria-label="Исполнитель" className={SMALL} value={assignee} onChange={(e) => setAssignee(e.target.value)}>
        <option value="">исполнитель: не менять</option>
        <option value={NOBODY}>исполнитель: очистить</option>
        {(directory.data ?? []).map((u) => <option key={u.login} value={u.login}>{u.display_name || u.login}</option>)}
      </select>
      <input aria-label="Срок" title="Срок" type="date" className={SMALL} value={due} disabled={clearDue} onChange={(e) => setDue(e.target.value)} />
      <label className="flex items-center gap-1 text-text-secondary">
        <input type="checkbox" checked={clearDue} onChange={(e) => setClearDue(e.target.checked)} />
        срок: очистить
      </label>
      {status === 'risk_accepted' && <input aria-label="Риск принят до" title="Риск принят до" type="date" className={SMALL} value={riskUntil} onChange={(e) => setRiskUntil(e.target.value)} />}
      <input aria-label="Комментарий" className={cn(SMALL, 'min-w-48 flex-1')} value={comment} onChange={(e) => setComment(e.target.value)}
        placeholder={needsReason ? 'Обоснование (обязательно)' : 'Комментарий'} />
      <Button variant="primary" className="px-2.5 py-1 text-xs" onClick={apply} disabled={blocked} loading={bulk.isPending}>Применить</Button>
      <Button variant="ghost" className="px-2 py-1 text-xs" onClick={onClear}>Снять выделение</Button>
      {bulk.error && <span className="basis-full text-kind-1">{bulk.error instanceof ApiRequestError ? bulk.error.message : 'Не удалось применить'}</span>}
    </div>
  )
}
