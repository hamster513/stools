import { SourcesTable } from './trends/SourcesTable'
import { MonitoringSettings } from './trends/MonitoringSettings'
import { RunHistory } from './trends/RunHistory'
import { Policies } from './trends/Policies'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { TREND_BASE, useTrendMutation, when, type TrendConnection } from '../../api/trends'

const message = (error: unknown) => error instanceof Error ? error.message : 'Ошибка запроса'

export function TrendsSection() {
  const [tab, setTab] = useState('connection')
  const connection = useQuery({ queryKey: ['vm-trends', 'settings'], queryFn: () => api.get<TrendConnection>(TREND_BASE + '/settings') })
  const offline = connection.data?.mode === 'offline'
  return <Section id="trends" title="Трендовые уязвимости" about="Получение внешних сигналов из отдельного сборщика. STools устанавливает соединение по HTTPS напрямую или через настроенный прокси.">
    {connection.isLoading && <Spinner />}
    {connection.error && <ErrorState message={message(connection.error)} onRetry={() => connection.refetch()} />}
    <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Настройки мониторинга">{Object.entries({ connection: 'Подключение', sources: 'Источники', telegram: 'Telegram', enrichment: 'Обогащение и PoC', diagnostics: 'Диагностика', policies: 'Исключения' }).map(([key, label]) => <Button key={key} variant={tab === key ? 'primary' : 'secondary'} aria-pressed={tab === key} onClick={() => setTab(key)}>{label}</Button>)}</div>
    {tab === 'connection' && connection.data && <ConnectionForm data={connection.data} />}
    {!offline && connection.data && (tab === 'sources' || tab === 'telegram') && <SourcesTable key={tab} telegram={tab === 'telegram'} />}
    {!offline && connection.data && tab === 'enrichment' && <MonitoringSettings />}{!offline && connection.data && tab === 'diagnostics' && <RunHistory />}
    {offline && ['sources', 'telegram', 'enrichment', 'diagnostics'].includes(tab) && <p className="text-sm text-text-secondary">Offline: обращения к сборщику отключены. <Link className="underline" to="/settings/vm#news-archive">Загрузить архив новостей</Link></p>}{tab === 'policies' && <Policies />}
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
    <Field label="Режим получения данных" hint="Архивы доступны в обоих режимах. Настройки подключения сохраняются при переключении.">
      <select className={FIELD} aria-label="Режим получения данных" disabled={!admin || save.isPending} value={form.mode ?? 'online'} onChange={e => patch({ mode: e.target.value as 'online' | 'offline' })}>
        <option value="online">Online — сборщик и архивы</option><option value="offline">Offline — только архивы</option>
      </select>
    </Field>
    {form.mode === 'offline' && <p className="text-sm text-text-secondary">После сохранения обращения к сборщику будут отключены. Импорт архивов и просмотр загруженных публикаций остаются доступны.</p>}
    <fieldset disabled={!admin || form.mode === 'offline' || save.isPending || test.isPending} className="grid max-w-4xl gap-3 md:grid-cols-2">
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
      {admin && <><Button disabled={save.isPending} onClick={() => save.mutate()}>Сохранить</Button><Button disabled={test.isPending || form.mode === 'offline' || data.mode === 'offline'} onClick={() => test.mutate()}>Проверить связь</Button></>}
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
      {admin && <><p>Полная синхронизация перечитывает историю сборщика. Решения аналитиков сохраняются.</p><label className="flex items-center gap-2"><input type="checkbox" checked={confirmFull} onChange={e => setConfirmFull(e.target.checked)} />Перечитать историю полностью</label><Button disabled={data.mode === 'offline' || !confirmFull || full.isPending || Boolean(status.data?.job_id)} onClick={() => full.mutate()}>Начать восстановление</Button></>}
    </div></details>}

  </div>
}
