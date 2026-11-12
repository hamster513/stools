import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { SiemLogons } from '@/modules/assets/pages/SiemLogons'

type Mapping = Record<'user' | 'domain' | 'last_login' | 'src_host' | 'src_ip' | 'dst_host' | 'dst_ip', string>
type Config = { table_name: string; siem_id: string; mapping: Mapping; time_format: string; max_rows: number }
type Preview = { columns: string[]; items: Record<string, string>[]; errors: { row: number; error: string }[]; sample_size: number }
type Job = { id: number; status: string; message: string; error: string | null }
const ROOT = '/api/siem/logons'
const DEFAULT: Config = {
  table_name: '', siem_id: '', time_format: 'iso', max_rows: 100000,
  mapping: { user: 'user', domain: 'domain', last_login: '_last_changed', src_host: 'src_host', src_ip: 'src_ip', dst_host: 'dst_host', dst_ip: 'dst_ip' },
}
const FIELDS: [keyof Mapping, string][] = [
  ['user', 'Пользователь *'], ['domain', 'Домен'], ['last_login', 'Время последнего входа *'],
  ['src_host', 'Хост источника'], ['src_ip', 'IP источника'], ['dst_host', 'Хост назначения'], ['dst_ip', 'IP назначения'],
]
const STEPS = ['Источник', 'Поля', 'Предпросмотр', 'Запуск']
const STATUS: Record<string, string> = { running: 'Выполняется', done: 'Завершён', failed: 'Ошибка', cancelled: 'Отменён' }

function Wizard({ initial }: { initial: Config | null }) {
  const can = useCan('siem')
  const assets = useCan('assets')
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<Config>(initial ?? DEFAULT)
  const [saved, setSaved] = useState<Config | null>(initial)
  const [step, setStep] = useState(initial ? 3 : 0)
  const [columns, setColumns] = useState<string[]>([])
  const [preview, setPreview] = useState<Preview | null>(null)
  const [message, setMessage] = useState('')
  const [catalog, setCatalog] = useState<{ name: string; id: string }[]>([])
  const dirty = JSON.stringify(saved) !== JSON.stringify(config)
  const jobs = useQuery({ queryKey: ['siem-logon-jobs'], queryFn: () => api.get<Job[]>(`${ROOT}/jobs?limit=5`),
    refetchInterval: (q) => q.state.data?.some((j) => j.status === 'running') ? 2000 : 10000 })
  const completed = jobs.data?.filter((j) => j.status === 'done').map((j) => j.id).join(',') ?? ''
  useEffect(() => {
    if (completed) void queryClient.invalidateQueries({ queryKey: ['assets'] })
  }, [completed, queryClient])
  const busy = jobs.data?.some((j) => j.status === 'running') ?? false
  const action = useMutation({
    mutationFn: async (kind: 'catalog' | 'columns' | 'preview' | 'save' | 'run' | 'cancel') => {
      setMessage('')
      if (kind === 'catalog') {
        const data = await api.get<{ items: typeof catalog }>(`${ROOT}/catalog?siem_id=${encodeURIComponent(config.siem_id)}`)
        setCatalog(data.items)
        if (!data.items.length) setMessage('В SIEM нет доступных табличных списков.')
      } else if (kind === 'columns' || kind === 'preview') {
        const data = await api.post<Preview>(`${ROOT}/preview`, config)
        setColumns(data.columns); setPreview(data); setStep(kind === 'columns' ? 1 : 2)
      } else if (kind === 'save') {
        await api.put(`${ROOT}/settings`, config)
        setSaved(config); setStep(3); setMessage('Настройки импорта сохранены.')
        await queryClient.invalidateQueries({ queryKey: ['siem-logon-settings'] })
      } else if (kind === 'run') {
        await api.post(`${ROOT}/run`)
        setMessage('Импорт запущен. Результат появится ниже.')
        await queryClient.invalidateQueries({ queryKey: ['siem-logon-jobs'] })
      } else {
        const job = jobs.data?.find((j) => j.status === 'running')
        if (job) await api.post(`${ROOT}/jobs/${job.id}/cancel`)
        await queryClient.invalidateQueries({ queryKey: ['siem-logon-jobs'] })
      }
    },
    onError: (error) => setMessage(errorText(error, 'Не удалось выполнить действие') ?? ''),
  })
  const pending = action.isPending
  function update(next: Config) { setConfig(next); setPreview(null); setMessage('') }
  const formValid = !!config.table_name.trim() && !!config.mapping.user && !!config.mapping.last_login && !!(config.mapping.dst_host || config.mapping.dst_ip)
  return <div className="grid max-w-4xl gap-4">
    <p className="text-xs text-text-secondary">Источник — существующее подключение к MaxPatrol SIEM. <Link to="/settings/siem#kb" className="text-primary hover:underline">Настроить подключение</Link></p>
    {can.admin && <ol className="flex flex-wrap gap-3 text-sm" aria-label="Шаги импорта">{STEPS.map((name, i) => <li key={name} aria-current={step === i ? 'step' : undefined} className={step === i ? 'font-semibold text-primary' : 'text-text-secondary'}>{i + 1}. {name}</li>)}</ol>}
    <fieldset disabled={pending} className="grid min-w-0 gap-4 rounded border border-grid bg-surface p-4">
      {can.admin && step === 0 && <>
        <h2 className="font-semibold">Выберите табличный список</h2>
        <label className="grid gap-1 text-sm">ID конвейера SIEM (если их несколько)<input className={FIELD} value={config.siem_id} onChange={(e) => { update({ ...config, siem_id: e.target.value }); setCatalog([]) }} /></label>
        <Button disabled={pending} onClick={() => action.mutate('catalog')}>{pending ? 'Загрузка…' : 'Получить списки из SIEM'}</Button>
        <label className="grid gap-1 text-sm">Название табличного списка<input className={FIELD} list="siem-logon-tables" value={config.table_name} onChange={(e) => update({ ...config, table_name: e.target.value })} placeholder="Выберите из списка или введите название" /></label>
        <datalist id="siem-logon-tables">{catalog.map((t) => <option key={t.id} value={t.name} />)}</datalist>
        <Button disabled={pending || !config.table_name.trim()} onClick={() => action.mutate('columns')}>Далее: сопоставить поля</Button>
      </>}
      {can.admin && step === 1 && <>
        <h2 className="font-semibold">Сопоставьте поля STools с колонками списка</h2>
        <p className="text-xs text-text-secondary">Домен можно взять из отдельной колонки или имени вида DOMAIN\user / user@domain. Укажите хост или IP назначения. Неиспользуемые поля оставьте пустыми.</p>
        <div className="grid gap-3 sm:grid-cols-2">{FIELDS.map(([key, title]) => <label className="grid gap-1 text-sm" key={key}>{title}<input className={FIELD} list="siem-logon-columns" value={config.mapping[key]} onChange={(e) => update({ ...config, mapping: { ...config.mapping, [key]: e.target.value } })} /></label>)}</div>
        <datalist id="siem-logon-columns">{columns.map((c) => <option key={c} value={c} />)}</datalist>
        <label className="grid gap-1 text-sm">Формат времени<select className={FIELD} value={config.time_format} onChange={(e) => update({ ...config, time_format: e.target.value })}><option value="iso">ISO 8601 с часовым поясом</option><option value="seconds">Unix, секунды</option><option value="milliseconds">Unix, миллисекунды</option></select></label>
        <label className="grid gap-1 text-sm">Максимум строк за импорт<input className={FIELD} type="number" min={1} max={1000000} value={config.max_rows} onChange={(e) => update({ ...config, max_rows: Number(e.target.value) })} /></label>
        <p className="text-xs text-text-secondary">При превышении лимита или ошибке строки импорт остановится без изменения данных.</p>
        <div className="flex gap-2"><Button disabled={pending} onClick={() => setStep(0)}>Назад</Button><Button disabled={pending || !formValid} onClick={() => action.mutate('preview')}>Проверить сопоставление</Button></div>
      </>}
      {can.admin && step === 2 && preview && <>
        <h2 className="font-semibold">Предпросмотр · строк: {preview.sample_size}</h2>
        <p className="text-xs text-text-secondary">Показаны последние входы, а не активные сеансы. Повторный импорт обновляет время той же связки пользователь → источник → назначение. Полный список проверяется при запуске.</p>
        {!preview.sample_size && <p>Список пуст. Настройку можно сохранить, но проверить сопоставление на данных пока нельзя.</p>}
        {!!preview.errors.length && <div role="alert" className="text-sm text-risk-high">{preview.errors.map((e) => <p key={e.row}>Строка {e.row}: {e.error}</p>)}</div>}
        {!!preview.items.length && <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr>{['Пользователь', 'Откуда', 'Куда', 'Последний вход'].map((t) => <th className="p-2 text-left" key={t}>{t}</th>)}</tr></thead><tbody>{preview.items.map((r, i) => <tr className="border-t border-grid" key={i}><td className="p-2">{r.domain}\{r.user}</td><td className="p-2">{[r.src_host, r.src_ip].filter(Boolean).join(' · ') || '—'}</td><td className="p-2">{[r.dst_host, r.dst_ip].filter(Boolean).join(' · ')}</td><td className="p-2 whitespace-nowrap">{new Date(r.last_login).toLocaleString('ru-RU')}</td></tr>)}</tbody></table></div>}
        <div className="flex gap-2"><Button disabled={pending} onClick={() => setStep(1)}>Назад к полям</Button><Button disabled={pending || preview.errors.length > 0} onClick={() => action.mutate('save')}>Сохранить настройку</Button></div>
      </>}
      {(step === 3 || !can.admin) && <>
        <h2 className="font-semibold">{saved ? `Список: ${saved.table_name}` : 'Импорт ещё не настроен'}</h2>
        {saved && <p className="text-xs text-text-secondary">Время входа: {saved.mapping.last_login}. Максимум строк: {saved.max_rows.toLocaleString('ru-RU')}. Новые данные дополняют ранее импортированные входы.</p>}
        {dirty && <p>Есть несохранённые изменения. Завершите мастер перед запуском.</p>}
        <div className="flex flex-wrap gap-2">{can.admin && <Button disabled={pending} onClick={() => setStep(0)}>Изменить настройку</Button>}<Button disabled={!saved || dirty || busy || pending || !can.write} onClick={() => action.mutate('run')}>Импортировать сейчас</Button>{busy && can.write && <Button disabled={pending} onClick={() => action.mutate('cancel')}>Отменить импорт</Button>}</div>
        {can.admin && <Link to="/settings/schedules" className="text-sm text-primary hover:underline">Настроить время и дни импорта в общем расписании</Link>}
      </>}
      {message && <p role="status" className="text-sm">{message}</p>}
      {pending && <p role="status" className="text-xs text-text-secondary">Выполняется запрос к серверу…</p>}
    </fieldset>
    <section className="rounded border border-grid p-4"><h2 className="mb-2 text-sm font-semibold">Последние импорты</h2>
      {jobs.isError && <p role="alert">Не удалось загрузить историю импортов.</p>}
      {jobs.data?.length === 0 && <p className="text-xs text-text-secondary">Импорт ещё не запускался.</p>}
      {jobs.data?.map((job) => <div key={job.id} className="border-t border-grid py-2 text-xs"><strong>#{job.id} · {STATUS[job.status] ?? job.status}</strong><p>{job.message}</p>{job.error && <p className="text-risk-high">{job.error}</p>}</div>)}
    </section>
    {assets.read && <SiemLogons key={jobs.data?.[0]?.status} />}
  </div>
}

export function LogonImportPage() {
  const settings = useQuery({ queryKey: ['siem-logon-settings'], queryFn: () => api.get<{ config: Config | null }>(`${ROOT}/settings`) })
  return <div className="h-full overflow-y-auto p-6 text-text"><h1 className="mb-4 text-base font-semibold">Импорт авторизаций SIEM</h1>
    {settings.isPending ? <p>Загрузка настроек…</p> : settings.isError ? <p role="alert">{errorText(settings.error, 'Не удалось получить настройки')}</p> : <Wizard initial={settings.data.config} />}
  </div>
}
