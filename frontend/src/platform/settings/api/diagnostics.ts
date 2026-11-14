import { api, ApiRequestError, buildQuery, formatDetail } from '@/api/client'
import type { SearchInput, SearchResult } from '@/platform/search/api'

export type DiagnosticKind = 'user' | 'host'
export interface Candidate { id: number; kind: DiagnosticKind; title: string; subtitle: string }
export interface Summary { counts: Record<string, number>; limitations: string[] }
export interface DiagnosticImport {
  id: string
  created_at: string
  summary: Summary
  root: { kind: DiagnosticKind; id: number; title: string }
}
export interface PreparedExport { id: string; summary: Summary; expires_at: string }
const BASE = '/api/settings/diagnostics'
export const diagnosticApi = {
  candidates: (query: string, kind: DiagnosticKind) => api.get<{ items: Candidate[] }>(`${BASE}/candidates${buildQuery({ query, kind })}`),
  prepare: (candidate: Candidate) => api.post<PreparedExport>(`${BASE}/exports`, { kind: candidate.kind, entity_id: candidate.id }),
  imports: () => api.get<{ items: DiagnosticImport[] }>(`${BASE}/imports`),
  upload: (file: File) => { const form = new FormData(); form.append('file', file); return api.postForm<DiagnosticImport>(`${BASE}/imports`, form) },
  remove: (id: string) => api.del<void>(`${BASE}/imports/${encodeURIComponent(id)}`),
  search: (id: string, input: SearchInput) => api.post<SearchResult>(`${BASE}/imports/${encodeURIComponent(id)}/search`, input),
  download: async (id: string) => {
    const response = await fetch(`${BASE}/exports/${encodeURIComponent(id)}/download`, { credentials: 'include' })
    if (!response.ok) {
      const payload = await response.json().catch(() => null)
      throw new ApiRequestError(response.status, payload?.detail ? formatDetail(payload.detail) : 'Не удалось скачать пакет. Подготовьте его заново.')
    }
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url; link.download = 'diagnostic-package.zip'; document.body.appendChild(link); link.click(); link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  },
}
