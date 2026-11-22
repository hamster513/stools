import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { useRouter, useSearchParams } from '@/lib/router'
import { dateText } from './api'
import { NETTRACE, active, display, object, objects, statuses, verdicts, nettraceSync, type Device, type Evaluation, type Inventory, type PathRequest } from './nettraceApi'

const LIMITATIONS: Record<string, string> = {
  single_source_address: 'Один IPv4-адрес источника', source_port_not_evaluated: 'Исходный порт не проверяется',
  return_path_not_evaluated: 'Обратный путь не проверяется', connection_state_not_modelled: 'Состояние соединения не моделируется', translated_port_not_computed: 'Порт после NAT не вычисляется',
}
const publicationStatuses: Record<string, string> = { ok: 'Получены', no_snapshot: 'Нет снимка политик', no_topology: 'Нет топологии', unsupported_platform: 'Платформа не поддерживается' }
function Values({ value }: { value: unknown }) {
  return <dl className="space-y-1 text-xs">{Object.entries(object(value)).map(([key, val]) => <div key={key} className="grid grid-cols-[minmax(7rem,1fr)_3fr] gap-2"><dt className="break-all text-text-secondary">{key}</dt><dd className="whitespace-pre-wrap break-all">{display(val)}</dd></div>)}</dl>
}
function Entries({ title, value }: { title: string; value: unknown }) {
  const [page, setPage] = useState(0)
  const rows = objects(value)
  return <details className="rounded border border-border p-3"><summary className="cursor-pointer">{title}: {rows.length}</summary><div className="mt-3 space-y-3">{rows.slice(page * 20, (page + 1) * 20).map((row, i) => <div key={page * 20 + i} className="border-b border-border pb-2"><Values value={row} /></div>)}{rows.length > 20 && <div className="flex gap-2"><Button disabled={!page} onClick={() => setPage(page - 1)}>Назад</Button><span>{page + 1} / {Math.ceil(rows.length / 20)}</span><Button disabled={(page + 1) * 20 >= rows.length} onClick={() => setPage(page + 1)}>Далее</Button></div>}</div></details>
}
function DeviceDetail({ device }: { device: Device }) {
  const query = useQuery({ queryKey: ['radar', 'nettrace', 'device', device.id], queryFn: () => api.get<Record<string, unknown>>(`${NETTRACE}/devices/${device.id}`) })
  return <section className="space-y-3 rounded border border-border p-4"><h3 className="break-all font-semibold">{device.name}</h3>{query.isPending && <p role="status">Загрузка устройства…</p>}{query.error && <p role="alert">{query.error.message}</p>}{query.data && <><Entries title="Интерфейсы" value={query.data.interfaces} /><Entries title="Правила NAT" value={query.data.rules} /><Entries title="Публикации NAT" value={query.data.publications} /><details><summary className="cursor-pointer text-sm">Снимки и статус источника</summary><Values value={{ interfaces: query.data.interfaces_meta, rules: query.data.rules_meta, publications: query.data.publications_meta }} /></details></>}</section>
}
function PathForm({ entry, configured, onCreated }: { entry: Device | null; configured: boolean; onCreated: (id: number) => void }) {
  const qc = useQueryClient()
  const params = useSearchParams()
  const [source, setSource] = useState('')
  const [destination, setDestination] = useState(params.get('destination') ?? '')
  const [port, setPort] = useState(params.get('port') ?? '443')
  const [protocol, setProtocol] = useState<'tcp' | 'udp'>(params.get('protocol') === 'udp' ? 'udp' : 'tcp')
  const [deviceId, setDeviceId] = useState(entry?.device_id ?? '')
  const [iface, setIface] = useState('')
  const query = useQuery({ queryKey: ['radar', 'nettrace', 'device', entry?.id], queryFn: () => api.get<Record<string, unknown>>(`${NETTRACE}/devices/${entry!.id}`), enabled: !!entry })
  const interfaces = objects(query.data?.interfaces)
  const submit = useMutation({ mutationFn: (request: PathRequest) => api.post<{ id: number; run_id: number }>(`${NETTRACE}/evaluations`, request), onSuccess: data => { qc.invalidateQueries({ queryKey: ['radar', 'nettrace', 'evaluations'] }); onCreated(data.id) } })
  return <form className="space-y-3 rounded border border-border p-4" onSubmit={e => { e.preventDefault(); submit.mutate({ source: { address: source, ...(deviceId && iface ? { entry_device_id: deviceId, entry_interface: iface } : {}) }, destination: { address: destination, port: Number(port) }, protocol }) }}>
    <h2 className="font-semibold">Рассчитать сетевой участок</h2>
    <p className="text-sm text-text-secondary">Укажите фактический исходящий IP: для nginx → backend это адрес исходящего соединения nginx. Результат описывает прямой путь по модели firewall; он не подтверждает доступность приложения или эксплуатацию уязвимости.</p>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label className="space-y-1 text-sm"><span>IPv4 источника</span><input className={`${FIELD} w-full`} required placeholder="198.51.100.25" value={source} onChange={e => setSource(e.target.value)} /></label>
      <label className="space-y-1 text-sm"><span>IPv4 назначения</span><input className={`${FIELD} w-full`} required placeholder="203.0.113.15" value={destination} onChange={e => setDestination(e.target.value)} /></label>
      <label className="space-y-1 text-sm"><span>Порт назначения</span><input className={`${FIELD} w-full`} type="number" min={1} max={65535} required value={port} onChange={e => setPort(e.target.value)} /></label>
      <label className="space-y-1 text-sm"><span>Протокол</span><select className={`${FIELD} w-full`} value={protocol} onChange={e => setProtocol(e.target.value as 'tcp' | 'udp')}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    </div>
    <div className="grid gap-3 sm:grid-cols-2"><label className="space-y-1 text-sm"><span>Входное устройство (UUID)</span><input className={`${FIELD} w-full`} value={deviceId} onChange={e => setDeviceId(e.target.value)} required={!!iface} placeholder="Автоматическое определение" /></label><label className="space-y-1 text-sm"><span>Входной интерфейс (имя)</span><input className={`${FIELD} w-full`} list="nettrace-interfaces" value={iface} onChange={e => setIface(e.target.value)} required={!!deviceId} placeholder="Например, ethernet1/1" /><datalist id="nettrace-interfaces">{interfaces.slice(0, 200).map((item, i) => <option key={i} value={display(item.name)} />)}</datalist></label></div>
    <p className="text-xs text-text-secondary">Лучше явно выбрать устройство в списке выше и ввести интерфейс. Без них NetTrace определяет вход автоматически. CIDR, IPv6 и доменные имена не поддерживаются.{interfaces.length > 200 && ' В подсказке первые 200 интерфейсов; любое имя можно ввести вручную.'}</p>
    {entry && <p className="text-xs text-text-secondary">Выбрано устройство: {entry.name}. {query.error?.message}</p>}
    {submit.error && <p role="alert" className="text-sm text-kind-1">{submit.error.message}</p>}
    <Button type="submit" variant="primary" loading={submit.isPending} disabled={!configured || submit.isPending}>Поставить расчёт в очередь</Button>
  </form>
}
function Packet({ value }: { value: unknown }) {
  const packet = object(value)
  return <span className="break-all">{display(packet.source)} → {display(packet.destination)} · {display(packet.protocol)}:{packet.destination_port == null ? 'порт неизвестен' : display(packet.destination_port)}</span>
}
function EvaluationDetail({ id }: { id: number }) {
  const { write } = useCan('radar')
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['radar', 'nettrace', 'evaluation', id], queryFn: () => api.get<Evaluation>(`${NETTRACE}/evaluations/${id}`), refetchInterval: q => q.state.data && active(q.state.data.status) ? 2500 : false })
  const cancel = useMutation({ mutationFn: (runId: number) => api.post(`/api/settings/sync-runs/${runId}/cancel`), onSuccess: () => qc.invalidateQueries({ queryKey: ['radar', 'nettrace'] }) })
  if (query.isPending) return <p role="status">Загрузка расчёта…</p>
  if (query.error) return <p role="alert">{query.error.message}</p>
  const data = query.data
  const response = data.response
  const paths = objects(response?.paths)
  return <section className="space-y-3 rounded border border-border bg-panel p-4">
    <div className="flex flex-wrap items-center gap-3"><h2 className="font-semibold">Расчёт №{id}</h2><span role="status">{statuses[data.status] ?? data.status}</span>{write && active(data.status) && data.run_id && <Button loading={cancel.isPending} onClick={() => cancel.mutate(data.run_id!)}>Отменить</Button>}</div>
    <p className="break-all text-sm">{data.request.source.address} → {data.request.destination.address}:{data.request.destination.port} · {data.request.protocol.toUpperCase()}</p>
    {!!data.request.source.entry_device_id && <p className="break-all text-xs text-text-secondary">Вход: {data.request.source.entry_device_id} / {data.request.source.entry_interface}</p>}
    {data.message && <p className="text-sm">{data.message}</p>}
    {cancel.error && <p role="alert">{cancel.error.message}</p>}
    {data.connection_changed && <p className="text-sm text-kind-2">Настройки подключения изменились. Это исторический расчёт предыдущего подключения.</p>}
    {data.status === 'done' && response && <>
      <p className="font-semibold">{verdicts[data.verdict] ?? data.verdict}</p>
      <p className="text-sm text-text-secondary">Это оценка прямого пути до сети назначения. Работа сервиса, обратный трафик и применимость CVE не подтверждены.</p>
      {data.warnings.map(w => <p key={w} className="text-sm text-kind-2">{w}</p>)}
      <p className="break-all text-xs text-text-secondary">Оригинальный вердикт NetTrace: {display(response.verdict)} · рассчитан: {display(response.evaluated_at)} · полный: {response.complete === true ? 'да' : 'нет'} · усечён: {response.truncated === true ? 'да' : 'нет'}{data.cached_from != null && ` · повторно использован расчёт №${data.cached_from} (кэш до 15 минут)`}</p>
      <details><summary className="cursor-pointer text-sm">Ограничения и причины</summary><ul className="my-2 list-disc pl-5 text-sm">{(Array.isArray(response.limitations) ? response.limitations : []).map((l, i) => <li key={i}>{LIMITATIONS[display(l)] ?? display(l)}</li>)}</ul><Values value={{ reasons: response.reasons, missing_data: response.missing_data, entry_points: response.entry_points }} /></details>
      {paths.map((path, i) => <details key={i} open={paths.length === 1} className="rounded border border-border p-3"><summary className="cursor-pointer text-sm">Путь {display(path.path_id) === '—' ? i + 1 : display(path.path_id)} · {verdicts[display(path.verdict)] ?? display(path.verdict)} · шагов: {objects(path.hops).length}</summary><div className="mt-3 overflow-x-auto"><div className="flex min-w-max items-start gap-3">{objects(path.hops).map((hop, n) => <div className="flex items-start gap-3" key={n}>{n > 0 && <span className="mt-4 text-primary" aria-hidden>→</span>}<article className="w-80 space-y-2 rounded border border-border p-3 text-xs"><h3 className="break-all font-semibold">{n + 1}. {display(object(hop.device).name)}</h3><p>Решение: {display(hop.decision)}</p><p className="break-all">{display(hop.message)}</p><p className="break-all">Вход: {display(object(hop.ingress).interface)} → выход: {display(object(hop.egress).interface)}</p><p>До: <Packet value={hop.packet_before} /></p><p>После: <Packet value={hop.packet_after} /></p><details><summary className="cursor-pointer">Правила, NAT, маршрут и снимки</summary><Values value={{ rules: hop.matched_rules, NAT: hop.transformations, route: hop.route, snapshots: hop.snapshots, reason_code: hop.reason_code }} /></details></article></div>)}</div></div><div className="mt-3"><Values value={{ reasons: path.reasons, missing_data: path.missing_data }} /></div></details>)}
      {!paths.length && <p className="text-sm">NetTrace не вернул шагов пути. Смотрите причины и недостающие данные.</p>}
      <details><summary className="cursor-pointer text-sm">Сохранённые снимки и идентификаторы</summary><Values value={{ snapshot_set_id: data.snapshot_set_id, evaluation_id: response.evaluation_id, snapshots: response.snapshots, requested_set: data.snapshot_set }} /></details>
    </>}
  </section>
}

export function NettracePage() {
  const { write } = useCan('radar')
  const { path, search: prefill, navigate } = useRouter()
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [historyOffset, setHistoryOffset] = useState(0)
  const [selected, setSelected] = useState<Device | null>(null)
  const [entry, setEntry] = useState<Device | null>(null)
  const match = /^\/radar\/nettrace\/(\d+)$/.exec(path)
  const inventory = useQuery({ queryKey: ['radar', 'nettrace', 'inventory', search, offset], queryFn: () => api.get<Inventory>(`${NETTRACE}/inventory?q=${encodeURIComponent(search)}&offset=${offset}&limit=50`), refetchInterval: 10000 })
  const history = useQuery({ queryKey: ['radar', 'nettrace', 'evaluations', historyOffset], queryFn: () => api.get<{ items: Evaluation[]; total: number }>(`${NETTRACE}/evaluations?offset=${historyOffset}`), refetchInterval: q => q.state.data?.items.some(item => active(item.status)) ? 2500 : 10000 })
  const sync = useMutation({ mutationFn: nettraceSync })
  return <div className="space-y-4">
    <p className="text-sm text-text-secondary">NetTrace рассчитывает путь через свои firewall с учётом правил, маршрутов и NAT. Связи NAT с nginx и backend-сервисами доступны на вкладке «Пути к приложениям».</p>
    <div className="flex flex-wrap items-center gap-3">{write && <Button disabled={!inventory.data?.configured || sync.isPending} loading={sync.isPending} onClick={() => sync.mutate()}>Синхронизировать NetTrace</Button>}<Button onClick={() => navigate('/settings/schedules')}>Расписание и очередь</Button>{sync.data && <span role="status" className="text-sm">В очереди: №{sync.data.run_id}</span>}</div>
    {sync.error && <p role="alert">{sync.error.message}</p>}
    {inventory.error && <p role="alert">{inventory.error.message}</p>}
    {inventory.isPending && <p role="status">Загрузка устройств…</p>}
    {inventory.data && <section className="space-y-3">
      {!inventory.data.configured && <p className="rounded border border-border p-4 text-sm">Подключение не настроено. Укажите адрес и ключ в «Настройки → Радар → NetTrace».</p>}
      {inventory.data.snapshot ? <><p className="text-xs text-text-secondary">Проверено: {dateText(inventory.data.snapshot.checked_at)} · импортировано: {dateText(inventory.data.snapshot.collected_at)} · набор: {inventory.data.snapshot.snapshot_set_id}</p><p className="text-xs text-text-secondary">Снимки источника: {inventory.data.snapshot.source.oldest_collected_at ? dateText(inventory.data.snapshot.source.oldest_collected_at) : 'нет даты'} — {inventory.data.snapshot.source.newest_collected_at ? dateText(inventory.data.snapshot.source.newest_collected_at) : 'нет даты'}. Данные устройств могут быть собраны в разное время.</p>{inventory.data.snapshot.warnings.map(w => <p className="text-xs text-kind-2" key={w}>{w}</p>)}</> : inventory.data.configured && <p className="text-sm">Выгрузки ещё нет. Запустите синхронизацию. Ручной расчёт доступен и без локальной выгрузки.</p>}
      <input className={`${FIELD} w-full`} aria-label="Поиск устройств NetTrace" placeholder="Название устройства NetTrace" value={search} onChange={e => { setSearch(e.target.value); setOffset(0) }} />
      <p className="text-sm">Устройств: {inventory.data.total}</p>
      {!!inventory.data.items.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{['Устройство', 'Интерфейсы', 'Правила NAT', 'Публикации', ''].map((label, i) => <th className="p-2" key={i}>{label}</th>)}</tr></thead><tbody>{inventory.data.items.map(d => <tr className="border-t border-border" key={d.id}><td className="break-all p-2"><button className="text-primary underline" onClick={() => setSelected(d)}>{d.name}</button></td><td className="p-2">{d.interfaces_count}</td><td className="p-2">{d.rules_count}</td><td className="p-2">{d.publications_status === 'ok' ? d.publications_count : publicationStatuses[d.publications_status] ?? d.publications_status}</td><td className="p-2">{write && <Button onClick={() => setEntry(d)}>Выбрать вход</Button>}</td></tr>)}</tbody></table></div>}
      {inventory.data.total > 50 && <div className="flex gap-3"><Button disabled={!offset} onClick={() => setOffset(offset - 50)}>Назад</Button><span>Страница {offset / 50 + 1}</span><Button disabled={offset + 50 >= inventory.data.total} onClick={() => setOffset(offset + 50)}>Далее</Button></div>}
    </section>}
    {selected && <div className="space-y-2"><Button onClick={() => setSelected(null)}>Закрыть устройство</Button><DeviceDetail key={selected.id} device={selected} /></div>}
    {write && <PathForm key={`entry-${entry?.id ?? 'auto'}-${prefill}`}  entry={entry} configured={!!inventory.data?.configured} onCreated={id => { setHistoryOffset(0); navigate(`/radar/nettrace/${id}`) }} />}
    {match && <EvaluationDetail key={`evaluation-${match[1]}`} id={Number(match[1])} />}
    <section className="space-y-3"><h2 className="font-semibold">История расчётов</h2>{history.error && <p role="alert">{history.error.message}</p>}{history.isPending && <p role="status">Загрузка истории…</p>}{history.data && <><p className="text-sm text-text-secondary">Всего: {history.data.total}. Результаты сохранены в STools вместе с запросом и снимками; повторить расчёт на историческом снимке NetTrace нельзя.</p><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{['Время', 'Участок', 'Статус / результат'].map(label => <th key={label} className="p-2">{label}</th>)}</tr></thead><tbody>{history.data.items.map(item => <tr key={item.id} className="border-t border-border"><td className="whitespace-nowrap p-2"><button className="text-primary underline" onClick={() => navigate(`/radar/nettrace/${item.id}`)}>{dateText(item.created_at)} · №{item.id}</button></td><td className="p-2">{item.request.source.address} → {item.request.destination.address}:{item.request.destination.port} {item.request.protocol}</td><td className="p-2">{item.status === 'done' ? verdicts[item.verdict] ?? item.verdict : statuses[item.status] ?? item.status}{item.connection_changed && <p className="text-xs text-text-secondary">Предыдущее подключение</p>}</td></tr>)}</tbody></table></div>{history.data.total > 20 && <div className="flex gap-3"><Button disabled={!historyOffset} onClick={() => setHistoryOffset(historyOffset - 20)}>Назад</Button><span>{historyOffset / 20 + 1}</span><Button disabled={historyOffset + 20 >= history.data.total} onClick={() => setHistoryOffset(historyOffset + 20)}>Далее</Button></div>}</>}</section>
  </div>
}
