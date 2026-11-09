import { useMutation } from '@tanstack/react-query'
import { api, ApiRequestError } from '@/api/client'

export type LookupKind = 'auto' | 'ip' | 'host' | 'domain' | 'cve'
export interface LookupEvidence {
  id: string
  title: string
  reason: string
  source: string
  href: string
  observed_at: string | null
  date_label: string
  facts: { label: string; value: string }[]
}
export interface LookupGroup {
  id: string
  title: string
  status: 'searched' | 'denied' | 'not_applicable'
  note: string
  items: LookupEvidence[]
  has_more: boolean
}
export interface LookupResult {
  query: string
  kind: LookupKind | 'name'
  searched_at: string
  groups: LookupGroup[]
}

export function useLookup() {
  return useMutation<LookupResult, ApiRequestError, { query: string; kind: LookupKind }>({
    mutationFn: input => api.post('/api/toolbox/lookup', input),
    gcTime: 0,
  })
}
