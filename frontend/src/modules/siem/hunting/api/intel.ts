import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, type ApiRequestError } from '@/api/client'

export interface IntelSource {
  id: string; name: string; kind: 'news' | 'rule'; url: string
  status: 'ok' | 'partial' | 'error'; items: number; error?: string
  revision?: string; license_text?: string; license_url?: string | null
}
export interface IntelItem {
  id: string; source_id: string; external_id: string; kind: 'news' | 'rule'
  title: string; url: string; format: string; published_at: string | null
  collected_at: string; full_text: boolean; technique_ids: string[]
}
export interface IntelDetail extends IntelItem { text: string; source: IntelSource }
export interface IntelImport {
  id: string; added: number; updated: number; unchanged: number; stale: number
  duplicate: boolean; generated_at: string; sources: IntelSource[]; created_at?: string
}
const URL = '/api/siem/hunting/intel'
export function useIntel(q: string, kind: '' | 'news' | 'rule', offset: number) {
  return useQuery<{ items: IntelItem[]; total: number }, ApiRequestError>({
    queryKey: ['th-intel', 'items', q, kind, offset],
    queryFn: () => api.get(URL + buildQuery({ q, kind: kind || undefined, offset, limit: 20 })),
  })
}
export function useIntelDetail(id: string | null) {
  return useQuery<IntelDetail, ApiRequestError>({
    queryKey: ['th-intel', 'detail', id], queryFn: () => api.get(`${URL}/${id}`), enabled: !!id,
  })
}
export function useIntelImports() {
  return useQuery<{ items: IntelImport[] }, ApiRequestError>({
    queryKey: ['th-intel', 'imports'], queryFn: () => api.get(URL + '/imports'),
  })
}
export function useImportIntel() {
  const qc = useQueryClient()
  return useMutation<IntelImport, ApiRequestError, File>({
    mutationFn: (file) => { const form = new FormData(); form.append('file', file); return api.postForm(URL + '/import', form) },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th-intel'] }),
  })
}
