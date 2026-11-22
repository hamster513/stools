import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Globe, Server, Shield, AppWindow } from 'lucide-react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { ACTION, dateText } from './api'
import { display } from './nettraceApi'
import { PATHS, evidence, candidateKey, type Candidate, type NginxPath, type PathTarget, type PublicationList, type PublicationPath } from './pathApi'

const BOX = 'w-80 shrink-0 space-y-2 rounded border border-border bg-panel p-3 text-sm'
const Arrow = () => <ArrowRight className="mt-7 shrink-0 text-primary" aria-hidden />
function WarningList({ items }: { items: string[] }) {
  return items.length ? <details className="text-xs text-kind-2"><summary className="cursor-pointer">Ограничения и происхождение данных: {items.length}</summary><ul className="mt-2 list-disc space-y-1 pl-4">{items.map((w, i) => <li key={i}>{w}</li>)}</ul></details> : null
}
function CandidatePath({ candidates, total, trail }: { candidates: Candidate[]; total: number; trail: string[] }) {
  const [selected, setSelected] = useState(candidates.length === 1 && total === 1 ? 0 : -1)
  const candidate = candidates[selected]
  return <div className="flex items-start gap-3">
    {(!candidate || candidates.length > 1 || total > candidates.length) && <div className={BOX}><h3 className="font-semibold">Выбор nginx</h3><p className="text-xs text-text-secondary">Кандидатов: {total}. Host/SNI и преобразование URI не вычисляются — выберите нужный вариант.</p>{total > candidates.length && <p className="text-xs text-kind-2">Показаны первые {candidates.length}; список неполный.</p>}<select aria-label={`Выбор nginx, уровень ${trail.length + 1}`} className={`${FIELD} w-full`} value={selected} onChange={e => setSelected(Number(e.target.value))}><option value={-1}>Выберите виртуальный сервер</option>{candidates.map((c, i) => <option value={i} key={`${c.snapshot_id}-${c.site}-${c.port}`}>{c.hostname}:{c.port} — {c.domains.join(', ') || 'без server_name'}</option>)}</select></div>}
    {candidate && <NginxHop key={`${candidate.snapshot_id}-${candidate.site}-${candidate.port}`} candidate={candidate} trail={trail} />}
  </div>
}
function Backend({ target, trail }: { target: PathTarget; trail: string[] }) {
  const { navigate } = useRouter()
  const { write } = useCan('radar')
  return <><Arrow /><div className={BOX}><Server size={17} className="text-primary" /><h3 className="font-semibold">{target.local ? 'Сервис на том же сервере' : 'Внутренний сервер / сервис'}</h3><p className="break-all">{target.dynamic ? 'Динамическое назначение' : `${target.host}${target.port != null ? ':' + target.port : ''}`}</p><p className="break-all font-mono text-xs">{target.address}</p>{target.parameters && <p className="break-all text-xs">{target.parameters}</p>}{target.disabled && <p className="text-kind-2">Продолжение не строится: узел down или динамический адрес.</p>}{target.asset && <Button onClick={() => navigate(`/assets/list?asset=${target.asset!.id}`)}>Актив: {target.asset.name}</Button>}{target.asset_ambiguous && <p className="text-xs text-kind-2">В Assets несколько совпадений; актив не выбран.</p>}<p className="text-xs text-text-secondary">Доступность соединения и программный продукт по адресу и порту не определяются.</p>{write && !target.disabled && target.port != null && /^\d+\.\d+\.\d+\.\d+$/.test(target.host) && <Button onClick={() => navigate(`/radar/nettrace?destination=${encodeURIComponent(target.host)}&port=${target.port}`)}>Проверить сетевой участок</Button>}</div>
    {!target.disabled && target.candidates.length > 0 && <><Arrow /><CandidatePath key={candidateKey(target.candidates, target.candidate_total)} candidates={target.candidates} total={target.candidate_total} trail={trail} /></>}
    {!target.disabled && !target.candidates.length && <><Arrow /><div className={BOX}><AppWindow size={17} className="text-primary" /><h3 className="font-semibold">Приложение / конечная точка</h3><p className="break-all">{target.address || 'Адрес не определён'}</p><p className="text-xs text-text-secondary">Достигнута граница известных конфигураций. Если здесь ещё один reverse proxy, импортируйте его конфигурацию. Название и версия приложения не подтверждены.</p></div></>}
  </>
}
function NginxHop({ candidate, trail }: { candidate: Candidate; trail: string[] }) {
  const { navigate } = useRouter()
  const [route, setRoute] = useState<number | null>(null)
  const [targetIndex, setTargetIndex] = useState(0)
  const key = `${candidate.snapshot_id}:${candidate.site}`
  const cycle = trail.includes(key), depthLimit = trail.length >= 8
  const query = useQuery({ queryKey: ['radar', 'path-nginx', candidate.snapshot_id, candidate.site, route], queryFn: () => api.get<NginxPath>(`${PATHS}/nginx/${candidate.snapshot_id}/${candidate.site}${route == null ? '' : '?route_index=' + route}`), enabled: !cycle && !depthLimit })
  if (cycle || depthLimit) return <div className={BOX}><p className="text-kind-2">{cycle ? 'Повторный переход к тому же nginx: возможен цикл.' : 'Достигнут предел 8 nginx-узлов.'}</p><p>Продолжение не раскрыто.</p></div>
  if (query.isPending) return <div className={BOX} role="status">Загрузка маршрута nginx…</div>
  if (query.error) return <div className={BOX} role="alert">{query.error.message}<Button onClick={() => query.refetch()}>Повторить</Button></div>
  const data = query.data, target = data.targets[targetIndex]
  return <div className="flex items-start gap-3"><div className={BOX}><Server size={17} className="text-primary" /><h3 className="break-all font-semibold">nginx · {data.hostname}</h3><p className="break-all">{data.site.names.join(', ') || 'Без server_name'}</p><p className="break-all font-mono text-xs">listen {candidate.listen}</p><p className="text-xs text-text-secondary">{evidence[candidate.evidence] ?? candidate.evidence} · импорт {dateText(data.imported_at)}</p><Button onClick={() => navigate(`/radar/nginx/${data.snapshot_id}`)}>Конфигурация и IP сервера</Button>
    <label className="block space-y-1"><span>Маршрут (выбранный вариант)</span><select aria-label={`Маршрут ${data.hostname}`} className={`${FIELD} w-full`} value={data.route_index} onChange={e => { setRoute(Number(e.target.value)); setTargetIndex(0) }}>{data.routes.map((r, i) => <option key={i} value={i}>{r.match} → {r.destination || ACTION[r.action]}</option>)}</select></label>
    <p className="break-all font-mono text-xs">{data.route.destination || ACTION[data.route.action]}</p>{(data.route.settings.some(s => s.name === 'internal') || data.route.match.startsWith('@')) && <p className="text-xs text-kind-2">Внутренний маршрут nginx: прямой внешний HTTP-запрос не допускается.</p>}<p className="break-all text-xs text-text-secondary">{data.route.file}:{data.route.line}</p><p className="text-xs text-text-secondary">Конфигурационный вариант; выбор location, Host/SNI, авторизация и rewrite для реального запроса не проверены.</p>
    <details><summary className="cursor-pointer text-xs">Настройки маршрута</summary><dl className="mt-2 space-y-1 text-xs">{data.route.settings.map((s, i) => <div key={i}><dt className="font-mono">{s.name}</dt><dd className="break-all">{s.value}</dd></div>)}</dl></details>
    {data.targets.length > 0 && <label className="block space-y-1"><span>Backend: {targetIndex + 1} из {data.target_total}</span><select aria-label={`Backend ${data.hostname}`} className={`${FIELD} w-full`} value={targetIndex} onChange={e => setTargetIndex(Number(e.target.value))}>{data.targets.map((t, i) => <option key={i} value={i}>{t.address}{t.disabled ? ' (down / динамический)' : ''}</option>)}</select></label>}<WarningList items={data.warnings} />
    </div>{target ? <Backend key={`${data.route_index}-${targetIndex}`} target={target} trail={[...trail, key]} /> : <><Arrow /><div className={BOX}><AppWindow size={17} className="text-primary" /><h3 className="font-semibold">{ACTION[data.route.action]}</h3><p className="break-all">{data.route.destination || 'Назначение не определено'}</p><p className="text-xs text-text-secondary">{data.route.action === 'return' ? 'Ответ или перенаправление клиента; серверное проксирование не выполняется.' : data.route.action === 'static' ? 'Локальная обработка nginx. Отдельное приложение этим конфигом не установлено.' : 'Для продолжения нужны дополнительные данные.'}</p></div></>}</div>
}
function PublicationDetail({ device, index }: { device: number; index: number }) {
  const { write } = useCan('radar')
  const { navigate } = useRouter()
  const query = useQuery({ queryKey: ['radar', 'path-publication', device, index], queryFn: () => api.get<PublicationPath>(`${PATHS}/publications/${device}/${index}`) })
  if (query.isPending) return <p role="status">Сопоставление публикации…</p>
  if (query.error) return <p role="alert">{query.error.message}</p>
  const data = query.data, pub = data.publication
  const singlePort = /^\d+$/.test(display(pub.ports)) ? display(pub.ports) : ''
  return <section className="space-y-3"><h2 className="font-semibold">Путь по конфигурациям</h2><p className="text-sm text-text-secondary">NAT-публикация не доказывает доступность из интернета. Каждый следующий сервер и маршрут — конфигурационный вариант. Снимки источников собраны в разное время.</p>{data.candidates.some(c => c.public_port == null) && <p className="text-sm text-kind-2">Порт после NAT не подтверждён. Ниже показаны кандидаты по адресу, а не подтверждённая связь портов.</p>}<WarningList items={data.warnings} />
    <div className="overflow-x-auto rounded border border-border p-3" aria-label="Полный конфигурационный путь слева направо"><div className="flex min-w-max items-start gap-3">
      <div className={BOX}><Globe size={17} className="text-primary" /><h3 className="font-semibold">Внешний адрес публикации</h3><p className="break-all">{display(pub.external)}</p><p>Протокол: {display(pub.protocol)} · порты: {display(pub.ports)}</p>{write && /^\d+\.\d+\.\d+\.\d+$/.test(display(pub.external)) && <Button onClick={() => navigate(`/radar/nettrace?destination=${encodeURIComponent(display(pub.external))}&port=${singlePort}&protocol=${pub.protocol === 'udp' ? 'udp' : 'tcp'}`)}>Проверить сетевой участок</Button>}<p className="text-xs text-text-secondary">Источник пакета задаётся отдельно в расчёте NetTrace.</p></div><Arrow />
      <div className={BOX}><Shield size={17} className="text-primary" /><h3 className="break-all font-semibold">{data.device.name}</h3><p className="break-all">NAT: {display(pub.external)} → {display(pub.internal)}</p><p>Тип: {display(pub.kind)}</p><p className="break-all text-xs">Правило: {display(pub.nat_rule_id)}</p><p className="text-xs text-text-secondary">Сбор: {dateText(data.snapshot.collected_at)} · {data.snapshot.snapshot_set_id}</p><details><summary className="cursor-pointer text-xs">Основание связи</summary><p className="mt-2 break-all font-mono text-xs">{display(data.rule)}</p><p className="break-all text-xs">Снимок политики: {display(data.snapshot.policy)}</p></details></div><Arrow />
      {data.candidates.length ? <CandidatePath key={candidateKey(data.candidates, data.candidate_total)} candidates={data.candidates} total={data.candidate_total} trail={[]} /> : <div className={BOX}><h3 className="font-semibold">Связь с nginx не найдена</h3><p>Нужны конфигурация и IP сервера после NAT. Откройте nginx и задайте IP в «IP сервера для связи с NetTrace».</p><Button onClick={() => navigate('/radar')}>Серверы nginx</Button></div>}
    </div></div>
  </section>
}
export function PathsPage() {
  const qc = useQueryClient()
  const { path, navigate } = useRouter()
  const [q, setQ] = useState(''), [offset, setOffset] = useState(0)
  const match = /^\/radar\/paths\/(\d+)\/(\d+)$/.exec(path)
  const query = useQuery({ queryKey: ['radar', 'publications', q, offset], queryFn: () => api.get<PublicationList>(`${PATHS}/publications?q=${encodeURIComponent(q)}&offset=${offset}&limit=50`) })
  return <div className="space-y-4"><p className="text-sm text-text-secondary">Выберите NAT-публикацию, затем проследите выбранную ветвь через nginx до сервиса. Альтернативные виртуальные серверы, маршруты и backend-узлы доступны в списках.</p><div className="flex gap-2"><input className={`${FIELD} min-w-0 flex-1`} aria-label="Поиск публикаций" placeholder="Внешний / внутренний IP или firewall" value={q} onChange={e => { setQ(e.target.value); setOffset(0) }} /><Button onClick={() => qc.invalidateQueries({ queryKey: ['radar'] })}>Обновить данные</Button>{match && <Button onClick={() => navigate('/radar/paths')}>Закрыть путь</Button>}</div>
    {query.isPending && <p role="status">Загрузка публикаций…</p>}{query.error && <p role="alert">{query.error.message}</p>}{query.data && <>
      {!query.data.snapshot ? <p>Нет текущей выгрузки NetTrace. Настройте подключение и запустите синхронизацию.</p> : <><p className="text-xs text-text-secondary">Набор {query.data.snapshot.snapshot_set_id} · {dateText(query.data.snapshot.collected_at)} · публикаций найдено: {query.data.total}</p><WarningList items={query.data.snapshot.warnings} /></>}
      {!!query.data.incomplete_devices && <p className="text-sm text-kind-2">Устройств без достаточных данных о публикациях: {query.data.incomplete_devices}. Пустая выдача не означает отсутствия внешнего доступа.</p>}
      <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{['Внешний адрес', 'После NAT', 'Протокол / порты', 'Firewall'].map(v => <th className="p-2" key={v}>{v}</th>)}</tr></thead><tbody>{query.data.items.map(item => <tr key={`${item.device_row_id}-${item.publication_index}`} className="border-t border-border"><td className="p-2"><button className="text-primary underline" onClick={() => navigate(`/radar/paths/${item.device_row_id}/${item.publication_index}`)}>{display(item.publication.external)}</button></td><td className="p-2">{display(item.publication.internal)}</td><td className="p-2">{display(item.publication.protocol)} / {display(item.publication.ports)}</td><td className="p-2">{item.device_name}</td></tr>)}</tbody></table></div>
      {query.data.total > 50 && <div className="flex gap-2"><Button disabled={!offset} onClick={() => setOffset(offset - 50)}>Назад</Button><span>{offset / 50 + 1}</span><Button disabled={offset + 50 >= query.data.total} onClick={() => setOffset(offset + 50)}>Далее</Button></div>}
    </>}{match && <PublicationDetail key={`${match[1]}-${match[2]}`} device={Number(match[1])} index={Number(match[2])} />}</div>
}
