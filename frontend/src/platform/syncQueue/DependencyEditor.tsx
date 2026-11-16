import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { type Dependency, type QueueTask } from './types'

export function DependencyEditor({ task, tasks }: { task: QueueTask; tasks: QueueTask[] }) {
  const [needs, setNeeds] = useState<Dependency[]>(task.dependencies)
  const [search, setSearch] = useState('')
  const qc = useQueryClient()
  const save = useMutation<unknown, ApiRequestError>({ mutationFn: () => api.put(
    `/api/settings/schedules/${task.key}/dependencies`,
    { dependencies: needs.map(edge => {
      const [module, kind, id] = edge.key.split('/')
      return { module, kind, target_id: Number(id), max_age_minutes: edge.max_age_minutes }
    }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sync-tasks'] }),
  })
  const missing = needs.filter(edge => !tasks.some(t => t.key === edge.key))
  const available = tasks.filter(t => t.key !== task.key && t.dependency_allowed &&
    (t.title + ' ' + t.module).toLowerCase().includes(search.toLowerCase()))
  return <section className="space-y-3 border-t border-grid pt-4">
    <h3 className="font-semibold">Зависимости и свежесть</h3>
    <p className="text-sm text-text-secondary">Перед этой задачей проверяются выбранные источники. Если данные старше допустимого возраста, источник обновляется первым. Ошибка блокирует зависимые шаги.</p>
    {task.hidden_dependencies > 0 && <p role="alert">Часть зависимостей недоступна по вашим правам. Изменение списка недоступно.</p>}
    <input aria-label="Поиск зависимостей" placeholder="Найти источник" value={search} onChange={e => setSearch(e.target.value)}
      className="w-full rounded border border-border bg-surface px-3 py-2" />
    <div className="max-h-72 space-y-2 overflow-y-auto rounded border border-border p-3">
      {missing.map(edge => <div key={edge.key} className="flex items-center justify-between gap-3 text-sm">
        <span>Источник удалён: {edge.key}</span>
        <Button variant="ghost" disabled={task.hidden_dependencies > 0} onClick={() => setNeeds(needs.filter(n => n.key !== edge.key))}>Убрать</Button>
      </div>)}
      {available.map(other => {
        const edge = needs.find(e => e.key === other.key)
        return <div key={other.key} className="flex flex-wrap items-center gap-3 text-sm">
          <label className="flex min-w-0 flex-1 items-center gap-2">
            <input type="checkbox" checked={!!edge} disabled={!other.can_run || task.hidden_dependencies > 0}
              onChange={e => setNeeds(e.target.checked ? [...needs, { key: other.key, max_age_minutes: 1440 }] : needs.filter(n => n.key !== other.key))} />
            <span>{other.title} <span className="text-text-secondary">({other.module})</span></span>
          </label>
          {edge && <label className="flex items-center gap-2">Не старше
            <input aria-label={`Допустимый возраст: ${other.title}`} type="number" min={1} max={43200} value={edge.max_age_minutes}
              onChange={e => setNeeds(needs.map(n => n.key === other.key ? { ...n, max_age_minutes: Number(e.target.value) } : n))}
              className="w-24 rounded border border-border bg-surface px-2 py-1" /> мин.
          </label>}
        </div>
      })}
      {!available.length && <p className="text-sm text-text-secondary">Подходящих источников нет.</p>}
    </div>
    <Button onClick={() => save.mutate()} loading={save.isPending} disabled={task.hidden_dependencies > 0 || needs.some(e => e.max_age_minutes < 1 || e.max_age_minutes > 43200)}>
      Сохранить зависимости
    </Button>
    {save.isSuccess && !save.isPending && <span role="status" className="ml-3 text-sm">Зависимости сохранены</span>}
    {save.isError && <p role="alert" className="text-sm text-risk-critical">{save.error.message}</p>}
  </section>
}
