import { useEffect, useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useChangeFinding, useFindingState, useUsersDirectory } from './queries'
import { StatusBadge } from './StatusBadge'
import { MANUAL_STATUSES, NEEDS_REASON, STATUS_TITLES, type FindingChange, type FindingEvent, type FindingState, type FindingStatus } from './types'

const SYSTEM = 'system'
const LABEL = 'mb-1 block text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

/** Дата YYYY-MM-DD из API — в вид, привычный людям, без сдвига поясом. */
function day(value: unknown): string {
  return typeof value === 'string' && value ? value.split('-').reverse().join('.') : '—'
}

function describe(e: FindingEvent): string {
  const d = e.details
  const status = (s: FindingStatus | null) => (s ? STATUS_TITLES[s] : '—')
  switch (e.kind) {
    case 'status':
      return `${status(e.from_status)} → ${status(e.to_status)}${d.risk_until ? `, риск принят до ${day(d.risk_until)}` : ''}`
    case 'assign':
      return `исполнитель: ${d.old ?? '—'} → ${d.new ?? '—'}`
    case 'due':
      return `срок: ${day(d.old)} → ${day(d.new)}`
    case 'comment':
      return 'комментарий'
    case 'auto_resolved':
    case 'auto_reopened':
      return `${status(e.from_status)} → ${status(e.to_status)} по данным: ${String(d.ref ?? '')}`
    case 'risk_expired':
      return `срок принятия риска истёк (${day(d.risk_until)})`
    case 'migrated':
      return `перенесено из прежнего вердикта: ${status(e.to_status)}`
  }
}

interface Form {
  status: FindingStatus
  assignee: string
  due: string
  riskUntil: string
  comment: string
}

function formOf(s: FindingState): Form {
  return { status: s.status, assignee: s.assignee ?? '', due: s.due_date ?? '', riskUntil: s.risk_until ?? '', comment: '' }
}

/** Только то, что изменилось: сервер не трогает поля, которых нет в теле. */
function diff(s: FindingState, f: Form): FindingChange {
  const change: FindingChange = {}
  if (f.status !== s.status) change.status = f.status
  if (f.assignee !== (s.assignee ?? '')) change.assignee = f.assignee || null
  if (f.due !== (s.due_date ?? '')) change.due_date = f.due || null
  if (f.status === 'risk_accepted' && f.riskUntil !== (s.risk_until ?? '')) change.risk_until = f.riskUntil || null
  if (f.comment.trim()) change.comment = f.comment.trim()
  return change
}

/**
 * Блок «Работа с находкой» для карточки (спека §6): статус, исполнитель,
 * срок, «риск принят до», комментарий и история. Аудитор видит то же без
 * элементов управления.
 */
export function FindingWorkBlock({ module, scopeId, findingKey, title, severity, onChanged }: {
  module: string
  scopeId: number
  findingKey: string
  title: string
  severity: string
  onChanged?: (state: FindingState) => void
}) {
  const { write } = useCan()
  const state = useFindingState({ module, scope_id: scopeId, key: findingKey })
  const directory = useUsersDirectory()
  const save = useChangeFinding()
  const s = state.data
  const [form, setForm] = useState<Form | null>(null)
  // Новая находка или сохранённое состояние — форма заново от сервера.
  useEffect(() => { if (s) setForm(formOf(s)) }, [s])

  if (state.isLoading || !s || !form) return <div className="flex justify-center py-4"><Spinner /></div>

  const change = diff(s, form)
  const needsReason = change.status !== undefined && NEEDS_REASON.includes(change.status)
  const blocked = Object.keys(change).length === 0 || (needsReason && !change.comment)
  const set = (patch: Partial<Form>) => setForm({ ...form, ...patch })
  const names = new Map((directory.data ?? []).map((u) => [u.login, u.display_name || u.login]))
  // Исполнитель, которого уже нет в справочнике, остаётся видимым в списке.
  const logins = [...names.keys(), ...(s.assignee && !names.has(s.assignee) ? [s.assignee] : [])]

  function submit() {
    save.mutate({ module, scope_id: scopeId, key: findingKey, title, severity, ...change }, { onSuccess: (next) => onChanged?.(next) })
  }

  return (
    <section className="flex flex-col gap-3 text-xs">
      <div className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Работа с находкой</div>
      <div className="grid grid-cols-2 gap-3">
        <label>
          <span className={LABEL}>Статус</span>
          {write ? (
            <select className={FIELD} value={form.status} onChange={(e) => set({ status: e.target.value as FindingStatus })}>
              {!MANUAL_STATUSES.includes(s.status) && <option value={s.status} disabled>{STATUS_TITLES[s.status]}</option>}
              {MANUAL_STATUSES.map((st) => <option key={st} value={st}>{STATUS_TITLES[st]}</option>)}
            </select>
          ) : <StatusBadge status={s.status} />}
        </label>
        <label>
          <span className={LABEL}>Исполнитель</span>
          {write ? (
            <select className={FIELD} value={form.assignee} onChange={(e) => set({ assignee: e.target.value })}>
              <option value="">— не назначен —</option>
              {logins.map((login) => <option key={login} value={login}>{names.get(login) ?? login}</option>)}
            </select>
          ) : <span className="text-text">{s.assignee_name ?? '—'}</span>}
        </label>
        <label>
          <span className={LABEL}>Срок</span>
          {write
            ? <input type="date" className={FIELD} value={form.due} onChange={(e) => set({ due: e.target.value })} />
            : <span className="text-text">{day(s.due_date)}</span>}
          {s.overdue && <span className="mt-1 block text-kind-1">просрочено</span>}
        </label>
        {form.status === 'risk_accepted' && (
          <label>
            <span className={LABEL}>Риск принят до</span>
            {write
              ? <input type="date" className={FIELD} value={form.riskUntil} onChange={(e) => set({ riskUntil: e.target.value })} />
              : <span className="text-text">{day(s.risk_until)}</span>}
          </label>
        )}
      </div>
      {s.reason && NEEDS_REASON.includes(s.status) && <p className="text-text-secondary">Обоснование: <span className="text-text">{s.reason}</span></p>}
      {write && (
        <>
          <label>
            <span className={LABEL}>{needsReason ? 'Обоснование (обязательно)' : 'Комментарий'}</span>
            <textarea rows={2} className={cn(FIELD, 'text-xs')} value={form.comment} onChange={(e) => set({ comment: e.target.value })}
              placeholder={needsReason ? 'Почему находка не требует исправления' : 'Необязательно'} />
          </label>
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={submit} disabled={blocked} loading={save.isPending}>Сохранить</Button>
            {save.error && <span className="text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
          </div>
        </>
      )}
      <div>
        <div className={LABEL}>История</div>
        {s.events.length === 0 ? <p className="text-text-secondary">решений по находке ещё не было</p> : (
          <ul className="flex flex-col gap-1.5">
            {s.events.map((e, i) => (
              <li key={`${e.at}-${i}`}>
                <div className={e.actor === SYSTEM ? 'text-kind-4' : 'text-text'}>{describe(e)}</div>
                {e.comment && <div className="whitespace-pre-line text-text">{e.comment}</div>}
                <div className="text-[11px] text-text-secondary">{e.actor === SYSTEM ? 'система' : e.actor}, {new Date(e.at).toLocaleString('ru-RU')}</div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
