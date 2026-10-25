import { useQuery } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'

/** Одна база, справочник или выгрузка модуля в сводке «Данные». */
export interface DataItem {
  module: string
  key: string
  title: string
  kind: 'reference' | 'snapshot' | 'source'
  updated_at: string | null
  state: 'fresh' | 'stale' | 'missing' | 'running'
  source: string | null
  detail: string
  /** id секции на странице модуля: /settings/<module>#<anchor>. */
  anchor: string
}

/**
 * Свежесть данных всех модулей. Пока что-то обновляется, сводка
 * перечитывается сама: иначе «обновляется» висело бы до перезагрузки.
 */
export function useDataStatus() {
  return useQuery<{ items: DataItem[] }, ApiRequestError>({
    queryKey: ['data-status'],
    queryFn: () => api.get('/api/settings/data-status'),
    staleTime: 60_000,
    refetchInterval: (q) => (q.state.data?.items.some((i) => i.state === 'running') ? 30_000 : false),
  })
}
