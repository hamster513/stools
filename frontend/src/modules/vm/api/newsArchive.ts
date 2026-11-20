import { useQuery } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import type { IntelImport } from '@/modules/siem/hunting/api/intel'

export type NewsImport = IntelImport & { news_total?: number }
const URL = '/api/vm/trends/news-archive'
export function useNewsImports() {
  return useQuery<{ items: NewsImport[] }, ApiRequestError>({ queryKey: ['vm-news-imports'], queryFn: () => api.get(URL + '/imports') })
}
