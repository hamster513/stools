import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { TREND_BASE, useTrendMutation, when, type TrendConnection, type TrendSource } from '../../api/trends'

const message = (error: unknown) => error instanceof Error ? error.message : 'Ошибка запроса'

export function TrendsSection() {
  const connection = useQuery({ queryKey: ['vm-trends', 'settings'], queryFn: () => api.get<TrendConnection>(TREND_BASE + '/settings') })
  return <Section id="trends" title="Трендовые уязвимости" about="Получение внешних сигналов из отдельного сборщика. STools устанавливает соединение по HTTPS напрямую или через настроенный прокси.">
    {connection.isLoading && <Spinner />}
    {connection.error && <ErrorState message={message(connection.error)} onRetry={() => connection.refetch()} />}
    {connection.data && <ConnectionForm data={connection.data} />}
  </Section>
}

function ConnectionForm({ data }: { data: TrendConnection }) {
  const { admin, write } = useCan()
  const [form, setForm] = useState({ ...data, token: '', proxy_password: '' })
  const [testResult, setTestResult] = useState('')
  const patch = (value: Partial<TrendConnection>) => { setForm(previous => ({ ...previous, ...value })); setTestResult('') }
  const save = useTrendMutation(async () => {
    await api.put(TREND_BASE + '/settings', form)
    setForm(previous => ({ ...previous, token: '', proxy_password: '', clear_token: false, clear_proxy_password: false }))
  })
  const test = useTrendMutation(async () => {
    const result = await api.post<{ ok: boolean; message: string; route?: string }>(TREND_BASE + '/settings/test', form)
    setTestResult(result.message + (result.route ? ` · ${result.route === 'proxy' ? 'Через прокси' : 'Прямое соединение'}` : ''))
  })
  const sync = useTrendMutation(() => api.post(TREND_BASE + '/sync'))
  const full = useTrendMutation(() => api.post(TREND_BASE + '/sync/full'))
  const [confirmFull, setConfirmFull] = useState(false)
  const imported = useTrendMutation((file: File) => { const body = new FormData(); body.append('file', file); return api.postForm(TREND_BASE + (confirmFull && admin ? '/import/full' : '/import'), body) })
  const status = useQuery({ queryKey: ['vm-trends', 'status'], queryFn: () => api.get<{ received_at: string | null; cursor: number; processing: Record<string, number>; job_id: number | null; rebuilding: boolean }>(TREND_BASE + '/status'), refetchInterval: 5000 })
  return <div className="space-y-4">
    <fieldset disabled={!admin || save.isPending || test.isPending} className="grid max-w-4xl gap-3 md:grid-cols-2">
      <Field label="HTTPS-адрес сборщика"><input className={FIELD} value={form.url} placeholder="https://collector.example:8443" onChange={e => patch({ url: e.target.value })} /></Field>
      <Field label="Токен доступа" hint={data.token_set ? 'Токен задан. Пустое поле сохраняет его.' : 'Токен создаётся на сборщике.'}><input className={FIELD} type="password" autoComplete="new-password" value={form.token} onChange={e => patch({ token: e.target.value })} /></Field>
      <Field label="Дополнительный CA сборщика (PEM)"><textarea className={FIELD} rows={3} value={form.ca_pem} onChange={e => patch({ ca_pem: e.target.value })} /></Field>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.proxy_enabled} onChange={e => patch({ proxy_enabled: e.target.checked })} />Использовать прокси</label>
      {form.proxy_enabled && <>
        <Field label="Тип прокси"><select className={FIELD} value={form.proxy_scheme} onChange={e => patch({ proxy_scheme: e.target.value as 'http' | 'https' })}><option value="http">HTTP CONNECT</option><option value="https">HTTPS CONNECT</option></select></Field>
        <Field label="Адрес прокси"><input className={FIELD} value={form.proxy_host} onChange={e => patch({ proxy_host: e.target.value })} /></Field>
        <Field label="Порт прокси"><input className={FIELD} type="number" min={1} max={65535} value={form.proxy_port} onChange={e => patch({ proxy_port: Number(e.target.value) })} /></Field>
        <Field label="Пользователь прокси"><input className={FIELD} autoComplete="off" value={form.proxy_username} onChange={e => patch({ proxy_username: e.target.value })} /></Field>
        <Field label="Пароль прокси" hint={data.proxy_password_set ? 'Пароль задан. Пустое поле сохраняет его.' : 'Для прокси с Basic-авторизацией.'}><input className={FIELD} type="password" autoComplete="new-password" value={form.proxy_password} onChange={e => patch({ proxy_password: e.target.value })} /></Field>
        {form.proxy_scheme === 'https' && <Field label="Дополнительный CA HTTPS-прокси (PEM)"><textarea className={FIELD} rows={3} value={form.proxy_ca_pem} onChange={e => patch({ proxy_ca_pem: e.target.value })} /></Field>}
      </>}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={Boolean(form.clear_token)} onChange={e => patch({ clear_token: e.target.checked })} />Удалить сохранённый токен</label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={Boolean(form.clear_proxy_password)} onChange={e => patch({ clear_proxy_password: e.target.checked })} />Удалить сохранённый пароль прокси</label>
    </fieldset>
    <div className="flex flex-wrap items-center gap-3">
      {admin && <><Button disabled={save.isPending} onClick={() => save.mutate()}>Сохранить</Button><Button disabled={test.isPending} onClick={() => test.mutate()}>Проверить связь</Button></>}
      {write && <Button disabled={!data.configured || sync.isPending || Boolean(status.data?.job_id)} onClick={() => sync.mutate()}>Получить обновления</Button>}
      <Link to="/settings/schedules" className="text-sm underline">Расписание получения</Link>
      <Link to="/vm/trends" className="text-sm underline">Открыть тренды</Link>
    </div>
    {testResult && <p role="status" className="text-sm">{testResult}</p>}
    {save.isSuccess && <p role="status" className="text-sm">Настройки сохранены</p>}
    {[save.error, test.error, sync.error, full.error, imported.error].filter(Boolean).map((error, index) => <p key={index} role="alert" className="text-sm text-danger">{message(error)}</p>)}
    <p className="text-sm text-text-secondary">Последнее получение — {when(status.data?.received_at)}. Обработано — {status.data?.processing.done ?? 0}, ожидает — {status.data?.processing.pending ?? 0}, ошибки анализа — {status.data?.processing.error ?? 0}.</p>
    {status.data?.job_id && <Link className="text-sm underline" to="/vm/jobs">Выполняется задача #{status.data.job_id}</Link>}
    {write && <details className="text-sm"><summary className="cursor-pointer">Перенос пакета и восстановление</summary><div className="mt-3 space-y-3">
      <Field label="Пакет сборщика (ZIP, до 100 MiB)"><input type="file" accept=".zip" disabled={imported.isPending || Boolean(status.data?.job_id)} onChange={e => { const file = e.target.files?.[0]; if (file) imported.mutate(file) }} /></Field>
      {admin && <><p>Полная синхронизация перечитывает историю сборщика. Решения аналитиков сохраняются.</p><label className="flex items-center gap-2"><input type="checkbox" checked={confirmFull} onChange={e => setConfirmFull(e.target.checked)} />Перечитать историю полностью</label><Button disabled={!confirmFull || full.isPending || Boolean(status.data?.job_id)} onClick={() => full.mutate()}>Начать восстановление</Button></>}
    </div></details>}
    {data.configured && <Sources />}
  </div>
}

function Sources() {
  const { admin } = useCan()
  const sources = useQuery({ queryKey: ['vm-trends', 'sources'], queryFn: () => api.get<{ items: TrendSource[] }>(TREND_BASE + '/sources'), refetchInterval: 30_000 })
  const [editing, setEditing] = useState<TrendSource | null>(null)
  const collect = useTrendMutation((id: string) => api.post(TREND_BASE + '/sources/' + id + '/collect'))
  return <div className="space-y-3 border-t border-grid pt-4"><h3 className="font-medium">Источники сборщика</h3>
    <p className="text-sm text-text-secondary">Каталог и интервалы опроса общие для всех STools, подключённых к этому сборщику. Редактирование требует права sources:write у токена.</p>
    {sources.error && <ErrorState message={message(sources.error)} onRetry={() => sources.refetch()} />}
    {admin && <Button onClick={() => setEditing({ name: '', publisher_id: '', adapter: 'rss', url: '', language: 'ru', region: 'RU', enabled: false, interval_minutes: 60, version: 1, llm_allowed: false })}>Добавить источник</Button>}
    {editing && <SourceEditor key={editing.id ?? 'new'} source={editing} close={() => setEditing(null)} />}
    <div className="divide-y divide-grid">{sources.data?.items.map(source => <div key={source.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
      <div><p className="text-sm font-medium">{source.name} · {source.enabled ? 'Включён' : 'Выключен'}</p><p className="text-xs text-text-secondary">{source.region} · {source.language} · каждые {source.interval_minutes} мин · получено {when(source.status?.last_success)}</p>{source.status?.error && <p className="text-xs text-danger">{source.status.error}</p>}</div>
      {admin && <div className="flex gap-2"><Button onClick={() => setEditing(source)}>Настроить</Button><Button disabled={collect.isPending} onClick={() => collect.mutate(source.id!)}>Собрать</Button></div>}
    </div>)}</div>
    {collect.error && <p role="alert" className="text-danger">{message(collect.error)}</p>}
    {collect.isSuccess && <p role="status" className="text-sm">Сбор поставлен в очередь</p>}
  </div>
}

function SourceEditor({ source, close }: { source: TrendSource; close: () => void }) {
  const [form, setForm] = useState(source)
  const save = useTrendMutation(async () => {
    if (form.id) await api.patch(TREND_BASE + '/sources/' + form.id, form)
    else await api.post(TREND_BASE + '/sources', form)
    close()
  })
  return <div className="space-y-3 rounded border border-grid p-4"><div className="grid gap-3 md:grid-cols-2">
    {(['name', 'publisher_id', 'url', 'language', 'region'] as const).map((key, index) => <Field key={key} label={['Название', 'Издатель (общий для перепечаток)', 'URL ленты или канала', 'Язык', 'Регион'][index]}><input className={FIELD} value={form[key]} onChange={e => setForm({ ...form, [key]: e.target.value })} /></Field>)}
    <Field label="Адаптер"><select className={FIELD} value={form.adapter} onChange={e => setForm({ ...form, adapter: e.target.value, llm_allowed: false })}>{['rss', 'telegram', 'kev', 'msrc', 'github', 'cncert'].map(value => <option key={value}>{value}</option>)}</select></Field>
    <Field label="Интервал опроса, минуты"><input className={FIELD} type="number" min={15} max={10080} value={form.interval_minutes} onChange={e => setForm({ ...form, interval_minutes: Number(e.target.value) })} /></Field>
    <label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />Включить сбор</label>
    <label className="flex items-center gap-2"><input type="checkbox" disabled={form.adapter === 'telegram'} checked={form.llm_allowed} onChange={e => setForm({ ...form, llm_allowed: e.target.checked })} />Разрешить обработку моделью</label>
  </div><div className="flex gap-2"><Button disabled={save.isPending} onClick={() => save.mutate()}>Сохранить источник</Button><Button onClick={close}>Отмена</Button></div>{save.error && <p role="alert" className="text-danger">{message(save.error)}</p>}</div>
}
