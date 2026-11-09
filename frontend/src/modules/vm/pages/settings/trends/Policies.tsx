import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useCan } from '@/lib/can'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/platform/collector/ui'
import { TREND_BASE, useTrendMutation, when } from '../../../api/trends'
interface Policy { id: number; scope: string; target_key: string; reason: string; expires_at: string | null; enabled: boolean; active: boolean; version: number; actor: string; history: { actor: string; at: string; reason: string; enabled: boolean }[] }
export function Policies() {
  const { write, admin } = useCan(); const [scope, setScope] = useState('publication'); const [target, setTarget] = useState(''); const [reason, setReason] = useState(''); const [expiry, setExpiry] = useState('')
  const rows = useQuery({ queryKey: ['vm-trends', 'policies'], queryFn: () => api.get<Policy[]>(TREND_BASE + '/policies') })
  const save = useTrendMutation(async () => { await api.post(TREND_BASE + '/policies', { scope, target_key: target, reason, expires_at: expiry ? new Date(expiry).toISOString() : null }); setTarget(''); setReason('') })
  const toggle = useTrendMutation((row: Policy) => api.patch(TREND_BASE + '/policies/' + row.id, { ...row, enabled: !row.enabled, reason: reason.trim() || row.reason }))
  return <section className="space-y-3"><p className="text-sm">Исключения действуют только в этом STools. Публикации и находки сохраняются. Истёкшее исключение перестаёт скрывать данные.</p>
    {write && <div className="grid gap-3 md:grid-cols-2"><Field label="Область"><select className={FIELD} value={scope} onChange={e => setScope(e.target.value)}><option value="publication">Одна публикация</option><option value="cve_product">CVE и продукт</option><option value="match">Одно локальное совпадение</option>{admin && <option value="cve_global">Вся CVE — глобальное исключение</option>}</select></Field><Field label="Стабильный ключ" hint={scope === 'publication' ? 'publication_key из карточки' : scope === 'match' ? 'CVE-2026-12345|host:42 или |image:42' : scope === 'cve_product' ? 'CVE-2026-12345|точное имя пакета' : 'CVE-2026-12345'}><input className={FIELD} value={target} onChange={e => setTarget(e.target.value)} /></Field><Field label="Причина"><input className={FIELD} value={reason} onChange={e => setReason(e.target.value)} /></Field><Field label="Действует до (пусто — бессрочно)"><input className={FIELD} type="datetime-local" value={expiry} onChange={e => setExpiry(e.target.value)} /></Field><Button disabled={!target || reason.trim().length < 5 || save.isPending} onClick={() => save.mutate()}>Добавить исключение</Button></div>}
    {[rows.error, save.error, toggle.error].filter(Boolean).map((error, i) => <p role="alert" key={i}>{error?.message}</p>)}
    {rows.data?.map(row => <article key={row.id} className="space-y-1 rounded border border-grid p-3 text-sm"><p>{row.scope} · {row.target_key} · {row.active ? 'Действует' : 'Не действует'}</p><p>{row.reason} · {row.actor} · До {when(row.expires_at)}</p>{write && (row.scope !== 'cve_global' || admin) && <Button disabled={toggle.isPending} onClick={() => toggle.mutate(row)}>{row.enabled ? 'Отменить исключение' : 'Включить'}</Button>}<details><summary>История</summary>{row.history.map((h, i) => <p key={i}>{when(h.at)} · {h.actor} · {h.enabled ? 'Включено' : 'Выключено'} · {h.reason}</p>)}</details></article>)}
  </section>
}
