import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, HardDrive, RefreshCw } from 'lucide-react'
import { api, type ApiRequestError } from '@/api/client'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { atLeast } from '@/platform/access/types'
import { Link } from '@/lib/router'
import { bytes, type StorageResponse, type StorageSample } from '../storage'
import { StorageHistory } from './StorageHistory'
import { StorageRetention } from './StorageRetention'

export function StoragePage() {
  const [days, setDays] = useState(30), [expanded, setExpanded] = useState<string[]>([])
  const { data: me } = useMe(), qc = useQueryClient()
  const admin = !!me && atLeast(me.access, 'platform', 'admin')
  const query = useQuery<StorageResponse, ApiRequestError>({ queryKey: ['storage', days], queryFn: () => api.get(`/api/settings/storage?days=${days}`), refetchInterval: 60_000 })
  const measure = useMutation<StorageSample, ApiRequestError>({ mutationFn: () => api.post('/api/settings/storage/measure', {}), onSuccess: async () => {
    await Promise.all([qc.invalidateQueries({ queryKey: ['storage'] }), qc.invalidateQueries({ queryKey: ['sync-schedules'] })])
  } })
  const data = query.data, latest = data?.latest
  const collectorNote = latest?.collector_status === 'not_configured' ? 'Не подключён' : latest?.collector_status === 'legacy' ? 'Без WAL/SHM' : latest?.collector_status === 'unavailable' ? 'Недоступен' : 'SQLite + WAL/SHM'
  return <div className="mx-auto w-full min-w-0 max-w-6xl space-y-5 p-6">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="flex items-center gap-2 text-xl font-semibold"><HardDrive size={22} aria-hidden />Хранилище</h1><div className="flex flex-wrap items-center gap-3"><Link className="text-sm text-primary hover:underline" to="/settings/schedules">Расписание замеров</Link>{admin && <Button loading={measure.isPending} onClick={() => measure.mutate()}><RefreshCw size={15} aria-hidden />Измерить сейчас</Button>}</div></div>
    <p className="text-sm text-text-secondary">PostgreSQL, файлы модулей и база коллектора. Каждый объект учитывается один раз. Автоматические замеры настраиваются в общем расписании.</p>
    {query.isLoading && <p role="status">Загрузка замеров…</p>}
    {query.isError && <p role="alert">{query.error.message} <Button onClick={() => query.refetch()}>Повторить</Button></p>}
    {measure.isPending && <p role="status" className="text-sm">Измеряем хранилище…</p>}
    {measure.isError && <p role="alert" className="text-sm text-kind-1">{measure.error.message}</p>}
    {data && !latest && <div className="rounded border border-grid p-5"><h2 className="font-medium">Пока нет замеров</h2><p className="mt-2 text-sm text-text-secondary">История начнётся с первого замера. По умолчанию задача запускается ежедневно в 03:00 ({data.tz}). {admin ? 'Можно выполнить первый замер сейчас.' : 'Администратор платформы может запустить замер вручную.'}</p></div>}
    {latest && data && <>
      <p className="text-xs text-text-secondary">Последний замер: {new Date(latest.measured_at).toLocaleString('ru-RU', { timeZone: data.tz })} ({data.tz}). Значения обновляются после замера, а не при открытии страницы.</p>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[
        ['Измеренный объём', `${latest.complete ? '' : '≥ '}${bytes(latest.total_bytes)}`, latest.complete ? 'Все настроенные источники измерены' : 'Неполный замер'],
        ['PostgreSQL', bytes(latest.database_bytes), 'Таблицы, индексы и системное пространство'],
        ['Файлы модулей', bytes(latest.file_bytes), 'Архивы, вложения и кэши в каталоге API'],
        ['База коллектора', bytes(latest.collector_bytes), collectorNote],
      ].map(([title, value, note]) => <div key={title} className="min-w-0 rounded border border-grid bg-surface p-4"><p className="text-xs text-text-secondary">{title}</p><p className="my-2 break-words text-2xl font-semibold tabular-nums">{value}</p><p className="text-xs text-text-secondary">{note}</p></div>)}</div>
      {latest.disk && <p className="text-sm text-text-secondary">Свободно на файловой системе каталога данных API: {bytes(latest.disk.free_bytes)} из {bytes(latest.disk.total_bytes)}. Это не свободное место на удалённом сервере БД или коллекторе.</p>}
      {!!latest.warnings.length && <ul aria-label="Ограничения замера" className="list-disc space-y-1 rounded border border-grid p-4 pl-8 text-sm">{latest.warnings.map(w => <li key={w}>{w}</li>)}</ul>}
      <section className="space-y-3"><h2 className="font-semibold">По модулям</h2><p className="text-xs text-text-secondary">Строки отсортированы по объёму. Раскройте модуль для детализации таблиц; общие данные не распределяются между модулями повторно.</p><div className="overflow-x-auto rounded border border-grid"><table className="w-full text-left text-sm"><thead className="bg-surface text-xs text-text-secondary"><tr>{['Модуль', 'Данные БД¹', 'Индексы', 'Файлы', 'Внешняя БД', 'Всего'].map(t => <th key={t} className="whitespace-nowrap p-3">{t}</th>)}</tr></thead><tbody>{latest.modules.map(m => {
        const open = expanded.includes(m.id)
        return <Fragment key={m.id}><tr className="border-t border-grid"><td className="p-3"><button className="flex min-h-11 items-center gap-2 text-left font-medium hover:text-primary" aria-expanded={open} aria-label={`Детализация: ${m.title}`} onClick={() => setExpanded(s => open ? s.filter(id => id !== m.id) : [...s, m.id])}>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}{m.title}</button></td>{[m.data_bytes, m.index_bytes, m.file_bytes].map((v,i) => <td key={i} className="whitespace-nowrap p-3 tabular-nums">{bytes(v)}</td>)}<td className="whitespace-nowrap p-3">{m.id === 'collector' ? latest.collector_status === 'not_configured' ? 'Не подключён' : bytes(latest.collector_bytes) : '—'}</td><td className="whitespace-nowrap p-3 font-medium tabular-nums">{!m.complete ? '≥ ' : ''}{m.id === 'collector' && latest.collector_bytes == null ? '—' : bytes(m.total_bytes)}</td></tr>
          {open && <tr><td colSpan={6} className="border-t border-grid bg-surface p-4">{m.tables.length ? <div className="max-h-80 overflow-auto"><table className="w-full text-left text-xs"><thead><tr>{['Таблица', 'Данные¹', 'Индексы', 'Всего', 'Строк, оценка'].map(t => <th key={t} className="p-2">{t}</th>)}</tr></thead><tbody>{m.tables.map(t => <tr key={t.name} className="border-t border-grid"><td className="p-2 font-mono">{t.name}</td><td className="p-2">{bytes(t.data_bytes)}</td><td className="p-2">{bytes(t.index_bytes)}</td><td className="p-2">{bytes(t.total_bytes)}</td><td className="p-2">{t.estimated_rows?.toLocaleString('ru-RU') ?? 'Нет статистики'}</td></tr>)}</tbody></table></div> : <p className="text-sm text-text-secondary">{m.id === 'collector' ? `Отдельная база коллектора: ${collectorNote}.` : m.id === 'database_system' ? 'Каталоги PostgreSQL, последовательности и пространство, не отнесённое к прикладным таблицам.' : 'Таблиц в этом модуле нет.'}</p>}<p className="mt-2 text-xs text-text-secondary">Файлы: {bytes(m.file_bytes)}. {m.complete ? '' : 'Есть неизмеренная часть; указанные размеры могут быть неполными.'}</p></td></tr>}
        </Fragment>
      })}</tbody></table></div><p className="text-xs text-text-secondary">¹ Данные БД включают TOAST и служебное пространство таблиц. Оценка числа строк берётся из статистики PostgreSQL. Удаление записей не всегда сразу уменьшает размер файлов базы.</p></section>
      <section className="space-y-3 border-t border-grid pt-4"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">История роста</h2><label className="flex items-center gap-2 text-sm">Период<select aria-label="Период" className={FIELD} value={days} onChange={e => setDays(Number(e.target.value))}>{[7,30,90,365].map(n => <option key={n} value={n}>{n} дней</option>)}</select></label></div><StorageHistory points={data.history} modules={latest.modules} tz={data.tz} /><p className="text-xs text-text-secondary">Храним до 1000 замеров за последние 365 дней. Исторические значения до включения замеров неизвестны.</p></section>
    </>}
    <StorageRetention admin={admin} />
    <p className="border-t border-grid pt-3 text-xs text-text-secondary">В объём входят текущая база PostgreSQL, обычные файлы каталога данных API и SQLite коллектора. Размеры файлов считаются по выделенным блокам; симлинки пропускаются, жёсткие ссылки учитываются один раз. Образы Docker, резервные копии, WAL PostgreSQL и данные внешних систем (включая отдельный IRP) сюда не входят.</p>
  </div>
}
