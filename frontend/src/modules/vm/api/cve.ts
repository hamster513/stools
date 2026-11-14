import { useQuery } from '@tanstack/react-query'
import { api, buildQuery } from '@/api/client'

export const CVE_BASE = '/api/vm/cve'
export interface RiskProfile { score: number; criticality: string; internet: boolean; confidential: boolean }
export interface HostMatch { identifier: string; identifiers: string[]; id: number; hostname: string; ip: string; os: string; criticality: string; zone: string; internet: boolean; risk: number; level: string }
export interface HostMatches { hosts_total: number; risk_min: number | null; risk_max: number | null; hosts: HostMatch[] }
export interface SoftwareMatches { total: number; items: { id: number; hostname: string; host_id: string; server_id: number; software: string; version: string; state: string; reason: string; checked_at: string }[] }
export interface GhsaPackage { ghsa_id: string; ecosystem: string; name: string; purl: string | null; ranges: { type: string; events: Record<string, string>[] }[]; versions: string[]; fixed_versions: string[] }
export interface ImageMatches { total: number; items: { id: number; project: string; repository: string; digest: string; risk: number | null; identifiers: string[]; packages: string[] }[] }
export interface CveDetail {
  primary_url: string; aliases: string[]; withdrawn: string | null; advisories: { id: string; url: string; summary: string; reviewed: boolean; withdrawn: string | null }[]; packages: GhsaPackage[]; images: ImageMatches
  id: string; cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'; cvss_source: string; cvss_version: string
  description: string; description_source: string; epss: number | null; known_exploited: boolean | null; published: string | null; modified: string | null; av: string | null
  sources: { id: string; name: string; url: string; loaded_at: string | null }[]
  exploits: { id: number; type: string; verified: boolean; url: string }[]; msf_modules: { name: string; title: string }[]; attack: string[]; images_total: number
  risk: { min: number; max: number; min_level: string; max_level: string; min_profile: RiskProfile; max_profile: RiskProfile; assumptions: string[]; scenario_count: number }
  matches: HostMatches; software_matches: SoftwareMatches
}
export function useCveSearch(q: string, offset: number) {
  return useQuery({ queryKey: ['vm-cve', 'search', q, offset], queryFn: () => api.get<{ items: { id: string; sources: string[] }[]; has_more: boolean }>(CVE_BASE + buildQuery({ q, offset, limit: 20 })), enabled: Boolean(q) })
}
export function useCve(id: string) {
  return useQuery({ queryKey: ['vm-cve', id], queryFn: () => api.get<CveDetail>(`${CVE_BASE}/${encodeURIComponent(id)}`), enabled: Boolean(id) })
}
export function useCveHosts(id: string, offset: number) {
  return useQuery({ queryKey: ['vm-cve', id, 'hosts', offset], queryFn: () => api.get<HostMatches>(`${CVE_BASE}/${id}/hosts` + buildQuery({ offset, limit: 50 })), enabled: offset > 0 })
}
export function useCveSoftware(id: string, offset: number) {
  return useQuery({ queryKey: ['vm-cve', id, 'software', offset], queryFn: () => api.get<SoftwareMatches>(`${CVE_BASE}/${id}/software` + buildQuery({ offset, limit: 50 })), enabled: offset > 0 })
}

export function useCveImages(id: string, offset: number) {
  return useQuery({ queryKey: ['vm-cve', id, 'images', offset], queryFn: () => api.get<ImageMatches>(`${CVE_BASE}/${id}/images` + buildQuery({ offset, limit: 50 })), enabled: offset > 0 })
}
