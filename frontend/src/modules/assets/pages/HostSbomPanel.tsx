import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { SoftwarePager } from './software/SoftwarePager'
import { SbomSoftware } from './SbomSoftware'
import { UnlinkedVmFindings } from './UnlinkedVmFindings'

const groups = {
  packages: 'Все с привязкой к ПО', both: 'Оба источника', trivy_only: 'Только Trivy',
  candidates: 'Кандидаты по базовому дистрибутиву', vendor_confirmed: 'Подтверждены производителем ОС',
}
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
  inventory_warnings?: string[]
  scanned_components: number | null; scan_at: string | null; db_version: string | null; scanner_version: string | null
  error: string | null; vm_available: boolean; vm_at: string | null
  vendor_summary?: { profile: string; feed: string; available: boolean; has_bulletins?: boolean; confirmed: number; candidates: number } | null
  counts: { both: number; trivy_only: number; vm_only: number } | null; total: number
  unlinked_total: number; inventory_revision: string | null; nvd_updated_at: string | null
  items: { id: string; group: 'both' | 'trivy_only' | 'trivy_uncompared' | 'candidate' | 'vendor_confirmed'
    packages: { package: string; installed_version: string; fixed_version: string; severity: string;
      profile?: string; assessment?: string; bulletin?: string; bulletin_url?: string }[] }[]
}
const fmt = (stamp: string) => new Date(stamp).toLocaleString('ru-RU')
const sourceName = { both: 'Trivy и MaxPatrol', trivy_only: 'Trivy', trivy_uncompared: 'Trivy',
  candidate: 'Кандидат', vendor_confirmed: 'Бюллетень производителя ОС' }
const pageSize = 40

export function HostSbomPanel({ assetId }: { assetId: number }) {
  const { write } = useCan('assets')
  const [group, setGroup] = useState<Group>('packages')
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
  const statusText = r.status === 'partial' && r.checked === 0
    ? 'Trivy не проверил ни одного компонента'
    : statuses[r.status] ?? r.status
  return <section className="space-y-3" aria-label="Сравнение Trivy и MaxPatrol VM">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="font-medium text-text" role="status">{statusText}</h3>
      {write && <Button disabled={waiting || !r.components || r.status === 'blocked'} loading={scan.isPending} onClick={() => scan.mutate()}>Проверить в Trivy</Button>}
    </div>
    <p className="text-text-secondary">Инвентаризация ПО · MaxPatrol: {sourceStates[r.inventory.maxpatrol]}. KSC: {sourceStates[r.inventory.ksc]}.</p>
    {r.inventory_warnings?.map(warning => <p key={warning} className="text-risk-medium">{warning}</p>)}
    {r.scan_at && <p className="text-text-secondary">Последнее сканирование {fmt(r.scan_at)}. Проверено компонентов: {r.checked} из {r.scanned_components}.
      {r.scanner_version && ` Trivy ${r.scanner_version}.`} {r.db_version && <span title={r.db_version}>База: {r.db_version.replace(/(OVAL [a-f0-9]{12})[a-f0-9]{52}\b/, '$1')}.</span>}</p>}
    {r.vm_at && <p className="text-text-secondary">Снимок находок MaxPatrol: {fmt(r.vm_at)}.</p>}
    {(r.error || scan.error) && <p role="alert" className="text-kind-1">{r.error || errorText(scan.error, 'Не удалось поставить проверку в очередь')}</p>}
    {!r.vm_available && <p className="text-risk-medium">Для этого хоста нет подтверждённого снимка находок MaxPatrol.</p>}
    {r.components > 0 && <SbomSoftware path={path} revision={[r.inventory_revision, r.nvd_updated_at].join('|')} />}
    {(r.counts || r.vendor_summary || r.items.length > 0) && <h3 className="border-t border-grid pt-3 font-medium text-text">Уязвимости с привязкой к ПО</h3>}
    {r.vendor_summary && <p className="text-text-secondary">Профиль {r.vendor_summary.profile}. Кандидатов {r.vendor_summary.candidates.toLocaleString('ru-RU')}.
      {' '}Подтверждено производителем для риска хоста {r.vendor_summary.confirmed.toLocaleString('ru-RU')} CVE.
      {!r.vendor_summary.available && ' Для этой версии ОС справочник бюллетеней недоступен.'}
      {r.vendor_summary.available && r.vendor_summary.has_bulletins === false && ' В загруженном справочнике этой версии ОС отсутствуют номера бюллетеней производителя.'}</p>}
    {(r.counts || r.vendor_summary) && <label className="block max-w-sm text-text-secondary">Показать находки
      <select className={FIELD + ' mt-1 w-full'} value={group} onChange={e => { setGroup(e.target.value as Group); setOffset(0) }}>
        <option value="packages">{r.vendor_summary ? 'Прямые и подтверждённые находки' : groups.packages}{r.counts && ` (${r.counts.both + r.counts.trivy_only})`}</option>
        {r.counts && <option value="both">{groups.both} ({r.counts.both})</option>}
        {r.counts && <option value="trivy_only">{groups.trivy_only} ({r.counts.trivy_only})</option>}
        {r.vendor_summary && <option value="vendor_confirmed">{groups.vendor_confirmed} ({r.vendor_summary.confirmed})</option>}
        {r.vendor_summary && <option value="candidates">{groups.candidates} ({r.vendor_summary.candidates})</option>}
      </select></label>}
    {!r.counts && !r.vendor_summary && group !== 'packages' && <Button onClick={() => { setGroup('packages'); setOffset(0) }}>Показать доступные находки</Button>}
    {r.items.length > 0 && <div className="overflow-x-auto"><table aria-label="Уязвимости с привязкой к ПО" className="w-full text-left text-xs">
      <thead className="border-b border-grid text-text-secondary"><tr>{['Уязвимость', 'Источник', 'Название ПО', 'Установленная версия', 'Исправлено в'].map(t => <th className="py-2 pr-3" key={t}>{t}</th>)}</tr></thead>
      <tbody>{r.items.flatMap(item => item.packages.map((pkg, index) => <tr key={item.id + '-' + index} className="border-b border-grid align-top">
        <td className="whitespace-nowrap py-1.5 pr-3"><Link className="font-mono text-primary hover:underline" to={'/vm/cve?id=' + encodeURIComponent(item.id)}>{item.id}</Link></td>
        <td className="pr-3">{sourceName[item.group]}{pkg.assessment === 'candidate' && ` · ${pkg.profile}`}
          {pkg.bulletin && <div>{pkg.bulletin_url
            ? <a className="text-primary hover:underline" href={pkg.bulletin_url} target="_blank" rel="noreferrer">{pkg.bulletin}</a>
            : pkg.bulletin}</div>}</td><td className="pr-3">{pkg.package}</td>
        <td className="pr-3">{pkg.installed_version}</td><td>{pkg.fixed_version || (pkg.assessment === 'candidate' ? 'Нет подтверждения' : 'Не указана')}</td>
      </tr>))}</tbody></table></div>}
    {(r.counts || r.vendor_summary) && r.total === 0 && <p className="text-text-secondary">В этой группе находок нет.</p>}
    {(r.total > pageSize || offset > 0) && <SoftwarePager label="Страницы уязвимостей с привязкой к ПО" total={r.total} offset={offset} pageSize={pageSize}
      busy={report.isFetching} onChange={setOffset} />}
    {r.unlinked_total > 0 && <UnlinkedVmFindings path={path} total={r.unlinked_total}
      version={[r.vm_at, r.scan_at, r.status, r.unlinked_total].join('|')} />}
  </section>
}
