import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import { QUEUE_ACCEPTED } from '@/platform/syncQueue/client'

export interface ArchiveFile {
  name: string; size: number; status: string; kind?: 'references' | 'news' | 'trivy' | 'oval'; db_updated_at?: string
  error?: string; warning?: string; added?: number; updated?: number; duplicate?: boolean
}
export interface ArchiveBatch {
  run_id: number; status: string; cancel_requested: boolean; created_at: string; finished_at: string | null
  files: ArchiveFile[]; message?: string; rebuild?: string; news_projection?: string
}
const URL = '/api/vm/refs/batches'
export const activeBatch = (status: string) => status === 'queued' || status === 'running'

export function useArchiveBatches() {
  return useQuery<{ items: ArchiveBatch[] }, ApiRequestError>({
    queryKey: ['vm-archive-batches'], queryFn: () => api.get(URL),
    refetchInterval: query => query.state.data?.items.some(batch => activeBatch(batch.status)) ? 2000 : false,
  })
}
export function useUploadArchives() {
  const qc = useQueryClient()
  return useMutation<{ run_id: number }, ApiRequestError, File[]>({
    mutationFn: files => {
      const form = new FormData()
      for (const file of files) form.append('files', file)
      return api.postForm(URL, form)
    },
    onSuccess: result => {
      window.dispatchEvent(new CustomEvent(QUEUE_ACCEPTED, { detail: { id: result.run_id, status: 'queued' } }))
      qc.invalidateQueries({ queryKey: ['vm-archive-batches'] })
    },
  })
}
export function useCancelArchiveBatch() {
  const qc = useQueryClient()
  return useMutation<unknown, ApiRequestError, number>({
    mutationFn: id => api.post(`/api/settings/sync-runs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-archive-batches'] }),
  })
}
