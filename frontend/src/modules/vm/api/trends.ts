import type { PocItem } from '../pages/trends/PocEvidence'
import type { Enrichment, Applicability } from '../pages/trends/ApplicabilityPanel'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { FindingStatus } from '@/platform/findings/types'
import { api, buildQuery } from '@/api/client'

export const TREND_BASE = '/api/vm/trends'
export const reasons: Record<string, string> = { confirmed_exploitation: 'Эксплуатация подтверждена', independent_reports: 'Независимое освещение', needs_review: 'Обсуждение / на проверку' }
export const when = (value: string | null | undefined) => value ? new Date(value).toLocaleString('ru-RU') : 'Нет данных'

export type TrendPeriod = 'today' | '24h' | '3d' | '90d' | '7d' | '30d' | 'custom' | 'all'
export interface TrendScope { period: TrendPeriod; tz: string; date_from?: string; date_to?: string }
export const DEFAULT_TREND_SCOPE: TrendScope = { period: '7d', tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Europe/Moscow' }
export const trendPeriods: { value: TrendPeriod; label: string }[] = [
  { value: 'today', label: 'Сегодня' }, { value: '24h', label: '24 часа' }, { value: '3d', label: '3 дня' }, { value: '7d', label: '7 дней' }, { value: '30d', label: '30 дней' },
  { value: '90d', label: '90 дней' }, { value: 'custom', label: 'Свой период' }, { value: 'all', label: 'Архив · всё время' },
]
export function trendPeriodLabel(scope: TrendScope) {
  return scope.period === 'custom' ? `${scope.date_from} — ${scope.date_to}` : trendPeriods.find(item => item.value === scope.period)?.label
}

export interface TrendConnection {
  url: string; token?: string; token_set: boolean; ca_pem: string; configured: boolean
  proxy_enabled: boolean; proxy_scheme: 'http' | 'https'; proxy_host: string; proxy_port: number
  proxy_username: string; proxy_password?: string; proxy_password_set: boolean; proxy_ca_pem: string
  clear_token?: boolean; clear_proxy_password?: boolean
}
export interface TrendSource {
  id?: string; name: string; publisher_id: string; adapter: string; url: string; language: string; region: string
  enabled: boolean; interval_minutes: number; version: number; llm_allowed: boolean
  content_scope?: string; importance?: number; proxy_profile?: string; telegram_mode?: string; telegram_channel?: string
  fallback_urls?: string[]; retired?: boolean; replacement_key?: string
  status?: { system_paused?: boolean; failures?: number; last_success?: string; error?: string; next_attempt?: string; new_versions?: number }
}
export interface Trend {
  cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'
  cvss_source: string; cvss_vector: string; cvss_version: string
  id: string; title: string; source_name: string; source_url: string; status: string; version: number; active: boolean; active_until: string | null
  last_event_at: string | null; reason: string; independent_sources: number; hosts: number; images: number; risk: number
  publication_count: number; publisher_count: number; news_count: number
}
export interface Evidence {
  publication_key: string; revision: number; title: string; url: string; text: string; publisher_id: string; source_name: string
  published_at: string | null; updated_at?: string; language?: string; links: string[]; full_text?: boolean
  evidence_kind?: string; origin_adapter?: string; exploitation_confirmed?: boolean; exploitation_verified?: boolean; independent?: boolean; retracted?: boolean; rejected?: boolean; processing: string; error?: string
  classification?: { category: string; reasons: string[] }; identifier_role?: string; included_manually?: boolean; suppressed?: boolean; suppression_reason?: string
  analysis: { summary_ru?: string; product?: string; affected_versions?: string; quote?: string; machine_generated?: boolean }
}
export interface TrendDetail extends Trend {
  pocs: PocItem[]; enrichment?: Enrichment | null; applicability: Applicability[]
  candidates: { type: string; id: number; name: string; product: string; reason: string }[]
  evidence: Evidence[]; evidence_total: number
  matches: {
    coverage: string; host_data_at: string | null; host_total: number; image_finding_total: number
    hosts: { id: number; hostname: string; ip: string; os: string; risk: number; status: FindingStatus }[]
    images: { id: number; name: string; digest: string; package: string; installed_version: string; fixed_version: string | null; scanned_at: string | null; scan_status: string; sync_error: string | null }[]
  }
  reviews: { actor: string; at: string; decision: { note?: string; status?: string; linked_identifier?: string } }[]
}

export function useTrends(params: Record<string, string | number | boolean | undefined>, enabled = true) {
  return useQuery({ queryKey: ['vm-trends', 'list', params], queryFn: () => api.get<{ items: Trend[]; total: number; received_at: string | null }>(TREND_BASE + buildQuery(params)), enabled, staleTime: 60_000, placeholderData: keepPreviousData })
}
export function useTrend(id: string, scope: TrendScope = DEFAULT_TREND_SCOPE) {
  return useQuery({ queryKey: ['vm-trends', 'detail', id, scope], queryFn: () => api.get<TrendDetail>(TREND_BASE + '/' + encodeURIComponent(id) + buildQuery({ ...scope })), enabled: Boolean(id) })
}
export function useTrendMutation<T>(action: (value: T) => Promise<unknown>) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn: action, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vm-trends'] }) })
}
export function useTrendBadges(ids: string[]) {
  const unique = [...new Set(ids)].sort()
  return useQuery({ queryKey: ['vm-trends', 'badges', unique], queryFn: async () => {
    const result: Record<string, { id: string; reason: string }> = {}
    for (let start = 0; start < unique.length; start += 100) Object.assign(result, await api.get(TREND_BASE + '/badges' + buildQuery({ ids: unique.slice(start, start + 100).join(',') })))
    return result
  }, enabled: unique.length > 0, staleTime: 60_000 })
}
