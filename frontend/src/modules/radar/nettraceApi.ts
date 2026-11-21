import { api } from '@/api/client'

export const NETTRACE = '/api/radar/nettrace'
export interface Connection { url: string; api_token_set: boolean; ca_pem: string; enabled: boolean; generation: number }
export interface PathRequest { source: { address: string; entry_device_id?: string; entry_interface?: string }; destination: { address: string; port: number }; protocol: 'tcp' | 'udp' }
export interface Device { id: number; device_id: string; name: string; interfaces_count: number; rules_count: number; publications_count: number; publications_status: string }
export interface Inventory { configured: boolean; total: number; items: Device[]; snapshot: { id: number; snapshot_set_id: string; collected_at: string; checked_at: string; warnings: string[]; source: { oldest_collected_at: string | null; newest_collected_at: string | null } } | null }
export interface Evaluation { id: number; request: PathRequest; created_at: string; finished_at: string | null; run_id: number | null; status: string; message: string; verdict: string; consistent: boolean; snapshot_set_id: string; warnings: string[]; cached_from: number | null; connection_changed: boolean; response?: Record<string, unknown> | null; snapshot_set?: Record<string, unknown> }
export const verdicts: Record<string, string> = { allowed: 'Прямой путь разрешён по модели', blocked: 'Путь заблокирован', conditional: 'Условно разрешён', unknown: 'Недостаточно данных' }
export const statuses: Record<string, string> = { queued: 'В очереди', running: 'Выполняется', done: 'Завершён', failed: 'Ошибка', cancelled: 'Отменён', cancelling: 'Отменяется' }
export const active = (status: string) => ['queued', 'running', 'cancelling'].includes(status)
export const display = (value: unknown): string => value == null ? '—' : typeof value === 'string' ? value : JSON.stringify(value)
export const objects = (value: unknown): Record<string, unknown>[] => Array.isArray(value) ? value.filter((v): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)) : []
export const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
export const nettraceSync = () => api.post<{ run_id: number }>(`${NETTRACE}/sync`)
