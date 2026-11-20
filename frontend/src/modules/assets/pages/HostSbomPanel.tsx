import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'

const groups = { all: 'Все находки', both: 'Оба источника', trivy_only: 'Только Trivy', vm_only: 'Только MaxPatrol' }
type Group = keyof typeof groups
const statuses: Record<string, string> = {
  pending: 'В очереди на проверку', running: 'Trivy проверяет SBOM', ready: 'Проверка завершена',
  partial: 'Проверена часть инвентаризации', no_inventory: 'Состав ПО ещё не получен',
  empty: 'Инвентаризация получена, список ПО пуст', error: 'Проверка завершилась ошибкой',
  blocked: 'Trivy недоступен', stale: 'Инвентаризация или база Trivy обновилась. Ожидается новая проверка.',
}
const sourceStates: Record<string, string> = {
  available: 'получено', missing: 'нет данных', partial: 'частичные данные', stale: 'предыдущий снимок', error: 'ошибка сбора',
}
interface Result {
  status: string; inventory: { maxpatrol: string; ksc: string }; components: number; checked: number | null
  scanned_components: number | null; scan_at: string | null; db_version: string | null; scanner_version: string | null
  error: string | null; vm_available: boolean; vm_at: string | null
  counts: Record<Exclude<Group, 'all'>, number> | null; total: number
  items: { id: string; group: Exclude<Group, 'all'> | 'trivy_uncompared' | 'vm_uncompared'
    packages: { package: string; installed_version: string; fixed_version: string; severity: string }[] }[]
}
const fmt = (stamp: string) => new Date(stamp).toLocaleString('ru-RU')
const sourceName = { ...groups, trivy_uncompared: 'Trivy', vm_uncompared: 'MaxPatrol' }
const pageSize = 40

export function HostSbomPanel({ assetId }: { assetId: number }) {
  const { write } = useCan('assets')
  const [group, setGroup] = useState<Group>('all')
  const [offset, setOffset] = useState(0)
  const client = useQueryClient()
  const key = ['host-sbom', assetId]
  const path = `/api/assets/assets/${assetId}/sbom`
  const report = useQuery<Result>({
    queryKey: [...key, group, offset],
    queryFn: ({ signal }) => api.get(`${path}/comparison${buildQuery({ group, limit: pageSize, offset })}`, { signal }),
    refetchInterval: (q) => ['pending', 'running', 'stale'].includes(q.state.data?.status ?? '') ? 5000 : 60000,
  })
  const scan = useMutation({
    mutationFn: () => api.post(`${path}/scan`),
    onSuccess: () => client.invalidateQueries({ queryKey: key }),
  })
  if (report.isError) return <ErrorState message={errorText(report.error, 'Не удалось получить результаты Trivy') ?? ''} onRetry={() => report.refetch()} />
  const r = report.data
  if (!r) return <div className="flex justify-center py-6"><Spinner /></div>
  const waiting = ['pending','running'].includes(r.status)
  return <section className="space-y-3" aria-label="Сравнение Trivy и MaxPatrol VM">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="font-medium text-text" role="status">{statuses[r.status] ?? r.status}</h3>
      {write && <Button disabled={waiting || !r.components || r.status === 'blocked'} loading={scan.isPending} onClick={() => scan.mutate()}>Проверить в Trivy</Button>}
    </div>
    <p className="text-text-secondary">Компонентов в SBOM: {r.components.toLocaleString('ru-RU')}. MaxPatrol: {sourceStates[r.inventory.maxpatrol]}. KSC: {sourceStates[r.inventory.ksc]}.</p>
    {r.scan_at && <p className="text-text-secondary">Последняя успешная проверка: {fmt(r.scan_at)}. Проверено компонентов: {r.checked} из {r.scanned_components}.
      {r.scanner_version && ` Trivy ${r.scanner_version}.`} {r.db_version && `База: ${r.db_version}.`}</p>}
    {r.vm_at && <p className="text-text-secondary">Снимок находок MaxPatrol: {fmt(r.vm_at)}.</p>}
    {(r.error || scan.error) && <p role="alert" className="text-kind-1">{r.error || errorText(scan.error, 'Не удалось поставить проверку в очередь')}</p>}
    {!r.vm_available && <p className="text-risk-medium">Для этого хоста нет подтверждённого снимка находок MaxPatrol.</p>}
    {!!r.scan_at && r.checked === 0 && <p className="text-risk-medium">Trivy не распознал ни одного пакета для проверки. Оценить уязвимости по этому SBOM пока невозможно.</p>}
    {r.counts && <label className="block max-w-xs text-text-secondary">Сравнение находок
      <select className={`${FIELD} mt-1 w-full`} value={group} onChange={e => { setGroup(e.target.value as Group); setOffset(0) }}>
        {Object.entries(groups).map(([value, label]) => <option value={value} key={value}>{label}{value !== 'all' && ` (${r.counts![value as Exclude<Group,'all'>]})`}</option>)}
      </select></label>}
    {!r.counts && group !== 'all' && <Button onClick={() => { setGroup('all'); setOffset(0) }}>Показать доступные находки</Button>}
    {r.items.length > 0 && <div className="overflow-x-auto"><table className="w-full text-left text-xs">
      <thead className="border-b border-grid text-text-secondary"><tr>{['Уязвимость','Источник','Пакет и версия','Исправлено в'].map(t => <th className="px-2 py-1.5 font-medium" key={t}>{t}</th>)}</tr></thead>
      <tbody>{r.items.map(item => <tr key={`${item.group}-${item.id}`} className="border-b border-grid align-top">
        <td className="whitespace-nowrap px-2 py-2 font-mono">{item.id}</td><td className="px-2 py-2">{sourceName[item.group]}</td>
        <td className="px-2 py-2">{item.packages.length ? item.packages.map((pkg, i) => <div key={i}>{pkg.package} {pkg.installed_version}</div>) : '—'}</td>
        <td className="px-2 py-2">{item.packages.length ? item.packages.map((pkg, i) => <div key={i}>{pkg.fixed_version || '—'}</div>) : '—'}</td>
      </tr>)}</tbody></table></div>}
    {r.counts && r.total === 0 && <p className="text-text-secondary">В этой группе находок нет.</p>}
    {(r.total > pageSize || offset > 0) && <div className="flex items-center gap-2"><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset-pageSize))}>Назад</Button>
      <span>{offset+1}–{Math.min(offset+pageSize, r.total)} из {r.total}</span>
      <Button disabled={offset+pageSize >= r.total} onClick={() => setOffset(offset+pageSize)}>Далее</Button></div>}
  </section>
}
