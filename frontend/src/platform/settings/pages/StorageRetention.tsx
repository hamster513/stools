import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Link } from '@/lib/router'
import { bytes } from '../storage'
import { canRunRetention, RETENTION_FIELDS, retentionConfirmation, validRetentionPolicy, type RetentionItem, type RetentionPolicy, type RetentionPreview, type RetentionResponse, type RetentionRun } from '../retention'

const endpoint = '/api/settings/storage/retention'
const queryKey = ['storage-retention']
const counts = (value: number | null | undefined) => value == null ? 'Нет данных' : value.toLocaleString('ru-RU')
const statusLabel: Record<string, string> = { running: 'Запущено, результат ещё не получен', ready: 'Доступно для очистки', protected: 'Защищено', skipped: 'Пропущено', unavailable: 'Недоступно', completed: 'Завершено', partial: 'Выполнено частично', failed: 'Ошибка' }

function RetentionItems({ items, result = false }: { items: RetentionItem[]; result?: boolean }) {
  return <div className="overflow-x-auto rounded border border-grid"><table className="w-full text-left text-sm"><thead className="bg-surface text-xs text-text-secondary"><tr>
    {['Данные', result ? 'Обработано записей' : 'К очистке, записей', 'Защищено, записей', 'Объём данных, оценка', 'Состояние и причина'].map(title => <th key={title} className="p-3">{title}</th>)}
  </tr></thead><tbody>{items.map(item => <tr key={item.id} className="border-t border-grid">
    <th scope="row" className="p-3 font-medium">{item.title}</th>
    <td className="p-3 tabular-nums">{counts(result ? item.removed_rows ?? (item.status === 'protected' ? 0 : null) : item.eligible_rows)}</td>
    <td className="p-3 tabular-nums">{counts(item.protected_rows)}</td>
    <td className="whitespace-nowrap p-3 tabular-nums">{item.estimated_bytes == null ? 'Нет данных' : `≈ ${bytes(item.estimated_bytes)}`}</td>
    <td className="min-w-48 p-3"><p>{result && item.status === 'ready' ? 'Завершено' : statusLabel[item.status] ?? item.status}</p>{item.reason && <p className="mt-1 text-xs text-text-secondary">{item.reason}</p>}</td>
  </tr>)}</tbody></table></div>
}

function Warnings({ items }: { items: string[] }) {
  return items.length ? <ul className="list-disc space-y-1 rounded border border-grid p-3 pl-7 text-sm" aria-label="Ограничения очистки">{items.map((warning, index) => <li key={index}>{warning}</li>)}</ul> : null
}

export function StorageRetention({ admin }: { admin: boolean }) {
  const qc = useQueryClient()
  const query = useQuery<RetentionResponse, ApiRequestError>({ queryKey, queryFn: () => api.get(endpoint) })
  const [draft, setDraft] = useState<RetentionPolicy | null>(null)
  const [preview, setPreview] = useState<RetentionPreview | null>(null)
  const [busy, setBusy] = useState<'save' | 'preview' | 'run' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now)
  const inFlight = useRef(false)
  const policy = draft ?? query.data?.policy
  const dirty = !!draft && JSON.stringify(draft) !== JSON.stringify(query.data?.policy)
  const valid = !!policy && validRetentionPolicy(policy)
  const lastRun = query.data?.last_run

  useEffect(() => {
    if (!preview) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [preview])

  async function refreshPreview() {
    try {
      const next = await api.post<RetentionPreview>(`${endpoint}/preview`, {})
      setPreview(next)
      setNow(Date.now())
    } catch (cause) {
      setError(`Не удалось обновить расчёт: ${cause instanceof Error ? cause.message : 'ошибка запроса'}`)
    }
  }

  async function act(action: 'save' | 'preview' | 'run') {
    if (!admin || inFlight.current || !policy) return
    if (action === 'save' && !valid) return
    if (action === 'preview' && dirty) return
    if (action === 'run') {
      if (!canRunRetention(preview, dirty, !!busy, Date.now())) return
      if (!window.confirm(retentionConfirmation(preview!))) return
      if (!canRunRetention(preview, dirty, !!busy, Date.now())) {
        setError('Срок расчёта истёк во время подтверждения. Рассчитайте очистку заново.')
        return
      }
    }
    inFlight.current = true
    setBusy(action)
    setError(null)
    setNotice(null)
    setPreview(null)
    try {
      if (action === 'save') {
        const saved = await api.put<RetentionResponse>(endpoint, policy)
        qc.setQueryData(queryKey, saved)
        setDraft(null)
        setNotice('Сроки сохранены.')
      } else if (action === 'run') {
        const run = await api.post<RetentionRun>(`${endpoint}/run`, { preview_id: preview!.preview_id })
        qc.setQueryData<RetentionResponse>(queryKey, current => current ? { ...current, last_run: run } : current)
        setNotice(`Очистка: ${statusLabel[run.status] ?? run.status}. Результат показан ниже.`)
        await qc.invalidateQueries({ queryKey: ['sync-schedules'] })
      }
      await refreshPreview()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось выполнить действие. Обновите расчёт перед повторным запуском.')
    } finally {
      inFlight.current = false
      setBusy(null)
    }
  }

  return <section className="space-y-4 border-t border-grid pt-5" aria-labelledby="storage-retention-title">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 id="storage-retention-title" className="font-semibold">Сроки хранения и очистка</h2><Link className="text-sm text-primary hover:underline" to="/settings/schedules">Расписание очистки</Link></div>
    <p className="text-sm text-text-secondary">Удаляются только устаревшие служебные данные. Публикации, справочники, текущие связи CVE, решения аналитика и сохранённые ответы ИИ защищены. Удаление публикаций станет доступно только после появления архива.</p>
    <p className="text-xs text-text-secondary">Задача «Очистка хранилища» в общем расписании изначально выключена. Сохранение сроков не запускает очистку; расписание включается отдельно.</p>
    {query.isLoading && <p role="status">Загрузка сроков хранения…</p>}
    {query.isError && <p role="alert">{query.error.message} <Button onClick={() => query.refetch()}>Повторить</Button></p>}
    {policy && <form className="space-y-3" onSubmit={event => { event.preventDefault(); void act('save') }}>
      <fieldset disabled={!admin || !!busy} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {RETENTION_FIELDS.map(({ key, label, hint }) => <label key={key} className="space-y-1 text-sm"><span className="block font-medium">{label}</span><span className="flex items-center gap-2"><input type="number" min={1} max={3650} step={1} required className={`${FIELD} w-24`} value={Number.isNaN(policy[key]) ? '' : policy[key]} onChange={event => { setDraft({ ...policy, [key]: event.target.valueAsNumber }); setPreview(null); setNotice(null) }} />дней</span><span className="block text-xs text-text-secondary">{hint}</span></label>)}
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={policy.clear_staging} onChange={event => { setDraft({ ...policy, clear_staging: event.target.checked }); setPreview(null); setNotice(null) }} /><span>Освобождать место временных таблиц импорта<span className="mt-1 block text-xs text-text-secondary">Только пустые таблицы, когда импорт не выполняется.</span></span></label>
      </fieldset>
      {admin ? <div className="flex flex-wrap items-center gap-3"><Button type="submit" disabled={!dirty || !valid || !!busy} loading={busy === 'save'}>Сохранить сроки</Button><span className="text-xs text-text-secondary">От 1 до 3650 дней.{dirty ? ' Сначала сохраните изменения, затем проверьте новый расчёт.' : ''}</span></div> : <p className="text-xs text-text-secondary">Менять сроки и запускать очистку может администратор платформы.</p>}
    </form>}
    {admin && policy && <div className="flex flex-wrap items-center gap-3"><Button disabled={dirty || !!busy} loading={busy === 'preview'} onClick={() => void act('preview')}>Рассчитать очистку</Button><Button variant="danger" disabled={!canRunRetention(preview, dirty, !!busy, now)} loading={busy === 'run'} onClick={() => void act('run')}>Очистить по расчёту</Button></div>}
    {busy && <p role="status" className="text-sm">{busy === 'run' ? 'Очистка выполняется…' : busy === 'save' ? 'Сохраняем сроки и обновляем расчёт…' : 'Рассчитываем доступные для очистки данные…'}</p>}
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {error && <p role="alert" className="text-sm text-kind-1">{error}</p>}
    {preview && <div className="space-y-3"><h3 className="text-sm font-medium">Предварительный расчёт</h3><p className="text-xs text-text-secondary">Создан: {new Date(preview.created_at).toLocaleString('ru-RU')}. Действует до {new Date(preview.expires_at).toLocaleString('ru-RU')}.</p>{Date.parse(preview.expires_at) <= now && <p role="status" className="text-sm text-kind-1">Расчёт устарел. Рассчитайте очистку заново.</p>}<RetentionItems items={preview.items} /><Warnings items={preview.warnings} /></div>}
    <p className="text-xs text-text-secondary">Объём в расчёте — приблизительный размер обрабатываемых данных, а не обещание освободить столько места на диске. PostgreSQL может оставить место для повторного использования. Недоступный коллектор показывается отдельно; его данные пропускаются, а не считаются нулём. Условия защиты повторно проверяются перед очисткой.</p>
    {lastRun && <details className="rounded border border-grid p-3"><summary className="cursor-pointer text-sm font-medium">Последняя очистка: {statusLabel[lastRun.status] ?? lastRun.status} · {new Date(lastRun.finished_at ?? lastRun.started_at).toLocaleString('ru-RU')}</summary><div className="mt-3 space-y-3"><RetentionItems items={lastRun.items} result /><Warnings items={lastRun.warnings} /></div></details>}
  </section>
}
