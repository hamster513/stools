import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { TREND_BASE, type TrendSource } from './trends'
export interface MonitoringOptions { collection_enabled: boolean; enrichment_enabled: boolean; poc_enabled: boolean }
export interface SourceRun {
  id: string; source_id: string; state: string; stage: string; created_at: string; finished_at?: string; error?: string
  counters: Record<string, number>; coverage: { kind?: string; partial?: boolean; historical_complete?: boolean; total?: number; from?: string; to?: string }
  continuation?: unknown; sample?: { title: string; url: string; published_at?: string; identifiers?: string[]; text: string; classification?: { category: string; reasons: string[] } }[]
}
export interface CatalogRow { index: number; line?: number; action: string; source: TrendSource; existing_id?: string; selected: boolean; changed_fields: string[]; conflicting_ids: string[]; error?: string }
export interface CatalogPlan { expected_revision: string; rows: CatalogRow[] }
export interface MonitoringData {
  info: { protocol_version: number; last_seq: number }
  sources: Record<string, { checks: number; successful: number; success_ratio: number | null; relevant: number; background: number }>
  pending: Record<string, number>; settings: MonitoringOptions; sample: string; runs: SourceRun[]
  poc_search: { id: string; cve_id: string; checked_at?: string; error?: string; truncated?: boolean; total?: number; next_attempt?: string }[]
}
export const useMonitoring = (enabled = true) => useQuery({ enabled, queryKey: ['vm-trends', 'monitoring'], queryFn: () => api.get<MonitoringData>(TREND_BASE + '/monitoring'), refetchInterval: enabled ? 15000 : false })
export const useSources = () => useQuery({ queryKey: ['vm-trends', 'sources'], queryFn: () => api.get<{ items: TrendSource[] }>(TREND_BASE + '/sources'), refetchInterval: 30000 })
export const useProfiles = () => useQuery({ queryKey: ['vm-trends', 'outbound-profiles'], queryFn: () => api.get<{ name: string; ready: boolean; route?: string; error?: string }[]>(TREND_BASE + '/outbound-profiles') })
