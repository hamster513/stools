import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { NETTRACE, nettraceSync, type Connection } from './nettraceApi'

function ConnectionForm({ initial }: { initial: Connection }) {
  const qc = useQueryClient()
  const { navigate } = useRouter()
  const [url, setUrl] = useState(initial.url)
  const [token, setToken] = useState('')
  const [ca, setCa] = useState(initial.ca_pem)
  const [enabled, setEnabled] = useState(initial.enabled)
  const [clear, setClear] = useState(false)
  const save = useMutation({ mutationFn: () => api.put<Connection>(`${NETTRACE}/settings`, { url, ca_pem: ca, enabled, clear_token: clear, ...(token ? { api_token: token } : {}) }), onSuccess: data => { setToken(''); setClear(false); qc.setQueryData(['radar', 'nettrace', 'settings'], data); qc.invalidateQueries({ queryKey: ['radar', 'nettrace'] }) } })
  const check = useMutation({ mutationFn: () => api.post<{ message: string; devices: number }>(`${NETTRACE}/test`) })
  const sync = useMutation({ mutationFn: nettraceSync })
  const dirty = url !== initial.url || ca !== initial.ca_pem || enabled !== initial.enabled || !!token || clear
  const busy = save.isPending || check.isPending || sync.isPending
  const error = save.error || check.error || sync.error
  return <div className="space-y-3 text-sm">
    <p className="text-text-secondary">Данные firewall, NAT и расчёт сетевого участка. Ключ NetTrace должен иметь права nat:read и path:evaluate. Проверка подключения использует сохранённые настройки.</p>
    <label className="block space-y-1"><span>HTTPS-адрес NetTrace</span><input className={`${FIELD} w-full`} type="url" placeholder="https://nettrace.example.org" value={url} onChange={e => { setUrl(e.target.value); check.reset() }} /></label>
    <label className="block space-y-1"><span>API-ключ {initial.api_token_set ? '(сохранён; пустое поле сохраняет ключ)' : '(не задан)'}</span><input className={`${FIELD} w-full`} type="password" autoComplete="new-password" value={token} onChange={e => { setToken(e.target.value); check.reset() }} placeholder="ntk_…" /></label>
    {initial.api_token_set && <label className="flex items-center gap-2"><input type="checkbox" checked={clear} onChange={e => setClear(e.target.checked)} />Удалить сохранённый ключ при сохранении</label>}
    <details><summary className="cursor-pointer">Сертификат доверенного центра (CA)</summary><label className="mt-2 block space-y-1"><span>PEM, если используется внутренний центр сертификации</span><textarea className={`${FIELD} w-full font-mono`} rows={4} value={ca} onChange={e => setCa(e.target.value)} maxLength={65536} /></label><p className="text-text-secondary">Проверка TLS обязательна. Системные доверенные центры также используются.</p></details>
    <label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Подключение включено</label>
    {dirty && <p className="text-text-secondary">Сначала сохраните изменения. Смена подключения сбросит текущую выгрузку; история расчётов останется.</p>}
    <div className="flex flex-wrap gap-2"><Button loading={save.isPending} disabled={busy || !dirty} onClick={() => { check.reset(); sync.reset(); save.mutate() }}>Сохранить</Button><Button loading={check.isPending} disabled={busy || dirty || !initial.enabled} onClick={() => check.mutate()}>Проверить подключение</Button><Button loading={sync.isPending} disabled={busy || dirty || !initial.enabled} onClick={() => sync.mutate()}>Синхронизировать</Button><Button onClick={() => navigate('/settings/schedules')}>Расписание и очередь</Button><Button onClick={() => navigate('/radar/nettrace')}>Открыть NetTrace</Button></div>
    {error && <p role="alert" className="text-kind-1">{error.message}</p>}
    {check.data && <p role="status">{check.data.message} Устройств в области ключа: {check.data.devices}.</p>}
    {sync.data && <p role="status">Синхронизация в общей очереди: №{sync.data.run_id}. Выполнение можно отслеживать в панели очереди.</p>}
  </div>
}

export function NettraceSettings() {
  const { admin } = useCan('radar')
  const query = useQuery({ queryKey: ['radar', 'nettrace', 'settings'], queryFn: () => api.get<Connection>(`${NETTRACE}/settings`), enabled: admin })
  return <section className="space-y-3 rounded border border-border bg-panel p-4"><h2 className="font-semibold">NetTrace</h2>
    {!admin ? <p className="text-sm text-text-secondary">Настройка подключения доступна администратору «Радара». Синхронизация и расчёты — на вкладке NetTrace.</p> : query.isPending ? <p role="status">Загрузка настроек…</p> : query.error ? <p role="alert">{query.error.message}</p> : <ConnectionForm key={query.data.generation} initial={query.data} />}
  </section>
}
