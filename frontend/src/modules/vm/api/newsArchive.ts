import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import type { IntelImport } from '@/modules/siem/hunting/api/intel'

export type NewsImport = IntelImport & { news_total?: number }
const URL = '/api/vm/trends/news-archive'
export function useNewsImports() {
  return useQuery<{ items: NewsImport[] }, ApiRequestError>({ queryKey: ['vm-news-imports'], queryFn: () => api.get(URL + '/imports') })
}
export function useImportNews() {
  const qc = useQueryClient()
  return useMutation<NewsImport, ApiRequestError, File>({
    mutationFn: file => { const form = new FormData(); form.append('file', file); return api.postForm(URL, form) },
    onSuccess: async () => {
      await Promise.all([['vm-trends'], ['vm-news-imports'], ['th-intel']].map(queryKey => qc.invalidateQueries({ queryKey })))
    },
  })
}
