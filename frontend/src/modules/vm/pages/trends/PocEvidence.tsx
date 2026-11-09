import { useState } from 'react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/platform/collector/ui'
import { useCan } from '@/lib/can'
import { TREND_BASE, useTrendMutation, when } from '../../api/trends'
import { safeUrl } from './publicationUrl'

export interface PocItem {
  id: string; repository_name: string; url: string; commit_sha: string; family_id: string
  state: string; effective_state: string; decision_version: number; needs_recheck: boolean
  reason: string; signals: string[]; checked_at?: string; incomplete: boolean; error: string
  evidence: { path: string; url: string; sha256: string; quote: string }[]
  history: { actor: string; at: string; state: string; commit_sha: string; reason: string; evidence: string[] }[]
}
const labels: Record<string, string> = { candidate: 'Кандидат', likely: 'Вероятный PoC', confirmed: 'Подтверждён аналитиком', rejected: 'Отклонён аналитиком' }
export function PocEvidence({ item }: { item: PocItem }) {
  const { write } = useCan()
  const [reason, setReason] = useState('')
  const [evidence, setEvidence] = useState('')
  const decision = useTrendMutation((state: string) => api.post(TREND_BASE + '/poc/' + encodeURIComponent(item.id) + '/review', {
    state, commit_sha: item.commit_sha, version: item.decision_version, reason, evidence: evidence.split('\n').map(s => s.trim()).filter(Boolean),
  }))
  return <article className="space-y-2 rounded border border-grid p-3 text-sm">
    <a className="underline" href={safeUrl(item.url)} target="_blank" rel="noopener noreferrer">{item.repository_name || item.url}</a>
    <p>{labels[item.effective_state] ?? item.effective_state} · Проверка {when(item.checked_at)}</p>
    <p className="break-all text-xs text-text-secondary">SHA {item.commit_sha || 'ещё не прочитана'} · Семейство {item.family_id || 'не определено'}</p>
    {item.needs_recheck && <p role="status">Репозиторий изменился после подтверждения. Нужна повторная проверка.</p>}
    <p>{item.reason}</p><p className="text-xs">{item.signals?.join(' · ')}</p>
    {(item.incomplete || item.error) && <p role="status">Проверка неполная{item.error ? ': ' + item.error : ''}. Показан последний доступный результат.</p>}
    {item.evidence?.map(entry => <details key={entry.path}><summary>{entry.path}</summary><a href={safeUrl(entry.url)} target="_blank" rel="noopener noreferrer" className="underline">Файл проверенной версии</a><pre className="whitespace-pre-wrap break-words text-xs">{entry.quote}</pre><p className="break-all text-xs">SHA256 {entry.sha256}</p></details>)}
    {write && item.commit_sha && <div className="space-y-2 border-t border-grid pt-2">
      <input className={FIELD} aria-label="Причина решения PoC" placeholder="Причина решения" value={reason} onChange={e => setReason(e.target.value)} />
      <textarea className={FIELD} aria-label="Доказательства PoC" placeholder="Ссылки на доказательства, по одной в строке" value={evidence} onChange={e => setEvidence(e.target.value)} />
      <div className="flex flex-wrap gap-2">{(['confirmed', 'rejected', 'candidate'] as const).map(state => <Button key={state} disabled={decision.isPending || reason.trim().length < 5 || (state === 'confirmed' && !evidence.trim())} onClick={() => decision.mutate(state)}>{state === 'confirmed' ? 'Подтвердить' : state === 'rejected' ? 'Отклонить' : 'Вернуть в кандидаты'}</Button>)}</div>
      {decision.error && <p role="alert">{decision.error.message}</p>}
    </div>}
    {!!item.history?.length && <details><summary>История решений</summary>{item.history.map((h, i) => <p key={i}>{when(h.at)} · {h.actor} · {labels[h.state]} · {h.commit_sha.slice(0, 12)} · {h.reason}</p>)}</details>}
  </article>
}
