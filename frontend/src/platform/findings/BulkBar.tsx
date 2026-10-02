import { useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { useBulkChange, useUsersDirectory } from './queries'
import { MANUAL_STATUSES, NEEDS_REASON, STATUS_TITLES, type FindingChange, type FindingStatus } from './types'

/** Значение «снять исполнителя» в списке: пустая строка уже значит «не менять». */
const NOBODY = '\u0000'
const SMALL = cn(FIELD, 'w-auto py-1 text-xs')

/**
 * Полоса массовых действий над выбранными находками (спека §6). Пустое поле —
 * «не менять». «Выбрать всё по фильтру» показывается, только если модуль
 * передал `onSelectAll`.
 */
export function BulkBar({ module, scopeId, keys, total, onSelectAll, onDone, onClear }: {
  module: string
  scopeId: number
  keys: string[]
  total: number
  onSelectAll?: () => void
  onDone: (changed: number) => void
  onClear: () => void
}) {
  const directory = useUsersDirectory()
  const bulk = useBulkChange()
  const [status, setStatus] = useState<FindingStatus | ''>('')
  const [assignee, setAssignee] = useState('')
  const [due, setDue] = useState('')
  const [riskUntil, setRiskUntil] = useState('')
  const [comment, setComment] = useState('')

  if (keys.length === 0) return null

  const change: FindingChange = {}
  if (status) change.status = status
  if (assignee) change.assignee = assignee === NOBODY ? null : assignee
  if (due) change.due_date = due
  if (status === 'risk_accepted' && riskUntil) change.risk_until = riskUntil
  if (comment.trim()) change.comment = comment.trim()
  const needsReason = status !== '' && NEEDS_REASON.includes(status)
  const blocked = Object.keys(change).length === 0 || (needsReason && !change.comment)

  function apply() {
    bulk.mutate({ module, scope_id: scopeId, keys, change }, {
      onSuccess: ({ changed }) => {
        setStatus(''); setAssignee(''); setDue(''); setRiskUntil(''); setComment('')
        onDone(changed)
      },
    })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-grid bg-row-selected px-4 py-2 text-xs">
      <span className="text-text">Выбрано <span className="font-mono tabular-nums">{keys.length}</span> из <span className="font-mono tabular-nums">{total}</span></span>
      {onSelectAll && keys.length < total && <Button variant="ghost" className="px-2 py-1 text-xs" onClick={onSelectAll}>выбрать всё по фильтру</Button>}
      <select aria-label="Статус" className={SMALL} value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | '')}>
        <option value="">статус: не менять</option>
        {MANUAL_STATUSES.map((s) => <option key={s} value={s}>{STATUS_TITLES[s]}</option>)}
      </select>
      <select aria-label="Исполнитель" className={SMALL} value={assignee} onChange={(e) => setAssignee(e.target.value)}>
        <option value="">исполнитель: не менять</option>
        <option value={NOBODY}>снять исполнителя</option>
        {(directory.data ?? []).map((u) => <option key={u.login} value={u.login}>{u.display_name || u.login}</option>)}
      </select>
      <input aria-label="Срок" title="Срок" type="date" className={SMALL} value={due} onChange={(e) => setDue(e.target.value)} />
      {status === 'risk_accepted' && <input aria-label="Риск принят до" title="Риск принят до" type="date" className={SMALL} value={riskUntil} onChange={(e) => setRiskUntil(e.target.value)} />}
      <input aria-label="Комментарий" className={cn(SMALL, 'min-w-48 flex-1')} value={comment} onChange={(e) => setComment(e.target.value)}
        placeholder={needsReason ? 'Обоснование (обязательно)' : 'Комментарий'} />
      <Button variant="primary" className="px-2.5 py-1 text-xs" onClick={apply} disabled={blocked} loading={bulk.isPending}>Применить</Button>
      <Button variant="ghost" className="px-2 py-1 text-xs" onClick={onClear}>Снять выделение</Button>
      {bulk.error && <span className="basis-full text-kind-1">{bulk.error instanceof ApiRequestError ? bulk.error.message : 'Не удалось применить'}</span>}
    </div>
  )
}
