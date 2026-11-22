import type { Directive, Target } from './api'

export const PATHS = '/api/radar/paths'
export interface AssetLink { id: number; name: string; ip: string; updated_at: string }
export interface Candidate { snapshot_id: number; server_id: number; hostname: string; site: number; port: number; listen: string; domains: string[]; evidence: string; asset: AssetLink | null; imported_at: string; public_port?: number | null }
export interface PathTarget extends Target { asset: AssetLink | null; asset_ambiguous: boolean; candidates: Candidate[]; candidate_total: number; disabled: boolean }
export interface NginxPath { snapshot_id: number; server_id: number; hostname: string; imported_at: string; site: { names: string[]; listen: string[] }; routes: { match: string; destination: string; action: string; file: string; line: number }[]; route_index: number; route: { match: string; destination: string; action: string; file: string; line: number; settings: Directive[]; parents: string[] }; targets: PathTarget[]; target_total: number; warnings: string[] }
export interface PublicationRow { device_row_id: number; device_name: string; publication_index: number; publication: Record<string, unknown> }
export interface PublicationList { total: number; incomplete_devices: number; items: PublicationRow[]; snapshot: { id: number; snapshot_set_id: string; collected_at: string; warnings: string[] } | null }
export interface PublicationPath { device: { id: string; name: string }; publication: Record<string, unknown>; rule: Record<string, unknown> | null; snapshot: { id: number; snapshot_set_id: string; collected_at: string; policy: unknown }; candidates: Candidate[]; candidate_total: number; warnings: string[] }
export const evidence: Record<string, string> = { loopback: 'Loopback этого же сервера', listen: 'Явный IP в listen', manual: 'Ручная привязка IP', assets: 'Точное совпадение в Assets', name: 'Совпадение имени; DNS не проверен' }

export const candidateKey = (items: Candidate[], total: number) => JSON.stringify([total, items.map(c => [c.snapshot_id, c.site, c.port, c.evidence])])
