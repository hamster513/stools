import { ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import type { SavedFilter } from '../api/types'
import { usePublishFilter, useRefreshFilters } from '../api/queries'
import { apiMessage } from '../format'

const STATUS = {
  not_published: 'Нет фильтра в SIEM — прямой переход недоступен',
  missing: 'Фильтр не найден в выбранной папке SIEM — прямой переход недоступен',
  modified: 'Запрос или Name отличаются от фильтра SIEM',
  unknown: 'Доступность фильтра SIEM не подтверждена',
  available: 'Фильтр SIEM связан',
}

export function SavedFilterControl({ value, kind, id, readOnly, dirty = false }: {
  value?: SavedFilter | null; kind: 'query' | 'deep'; id: number; readOnly: boolean; dirty?: boolean
}) {
  const publish = usePublishFilter()
  const refresh = useRefreshFilters()
  const error = publish.isError ? apiMessage(publish.error, 'Не удалось синхронизировать фильтр SIEM') : value?.error
  const status = value?.status ?? (value?.url ? 'available' : 'not_published')
  return <div className="flex flex-wrap items-center gap-2 text-xs">
    <span className={status === 'available' ? 'text-text-secondary' : 'text-kind-1'}>{STATUS[status]}</span>
    {value?.url && <a href={value.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
      открыть в MaxPatrol <ExternalLink size={12} aria-hidden />
    </a>}
    {!readOnly && <Button type="button" loading={publish.isPending} disabled={dirty}
      title={dirty ? 'Сначала сохраните изменения запроса' : 'Сохранить фильтр в выбранную папку SIEM'}
      onClick={() => publish.mutate({kind, id})}>
      {value?.id && status !== 'missing' ? 'Обновить фильтр в SIEM' : 'Создать фильтр в SIEM'}
    </Button>}
    {value?.id && <Button type="button" loading={refresh.isPending} onClick={() => refresh.mutate()}>Проверить в SIEM</Button>}
    {dirty && !readOnly && <span className="text-text-secondary">сначала сохраните запрос</span>}
    {error && <span role="alert" className="text-kind-1">{error}</span>}
  </div>
}
