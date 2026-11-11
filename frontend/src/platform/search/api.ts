import { useMutation } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
interface LookupEvidence {
  id: string; title: string; reason: string; source: string; href: string
  observed_at: string | null; date_label: string; facts: { label: string; value: string }[]
}
interface LookupGroup {
  id: string; title: string; status: 'searched' | 'denied' | 'not_applicable'
  note: string; items: LookupEvidence[]; has_more: boolean
}
export type Kind = 'auto' | 'ip' | 'host' | 'domain' | 'cve' | 'user' | 'group'
export interface Entity {
  id: string; kind: 'host' | 'user' | 'group'; title: string; domain: string; href: string
  facts: { label: string; value: string }[]
}
export interface Row extends LookupEvidence { target?: Entity | null }
export interface Section { id: string; title: string; note: string; items: Row[]; has_more: boolean }
export interface Dossier { entity: Entity; sections: Section[]; notes: string[] }
export interface SearchInput { query: string; kind: Kind; entity_id?: string }
export interface SearchResult { query: string; matches: Entity[]; dossier: Dossier | null; groups: LookupGroup[]; has_more: boolean; notes: string[] }
export function useSearch() {
  return useMutation<SearchResult, ApiRequestError, SearchInput>({ mutationFn: body => api.post('/api/search', body), gcTime: 0 })
}
