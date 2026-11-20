import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface Directive { name: string; value: string; file: string; line: number; depth?: number; block?: boolean }
export interface Target { address: string; host: string; port: number | null; local: boolean; dynamic: boolean; parameters: string; file: string; line: number }
export interface Route { match: string; parents: string[]; action: string; destination: string; targets: Target[]; settings: Directive[]; file: string; line: number }
export interface VirtualServer { id: number; names: string[]; listen: string[]; exposure: string; settings: Directive[]; routes: Route[]; file: string; line: number }
export interface NginxDocument { hostname: string; servers: VirtualServer[]; sources: { path: string; directives: Directive[] }[]; warnings: string[]; exposure: string }
export interface Snapshot { id: number; server_id: number; hostname: string; filename: string; sha256: string; imported_at: string; virtual_servers: number; routes: number; domains: string[]; listen: string[]; warnings: number; exposure: string; unchanged?: boolean }
export interface Detail extends Snapshot { document: NginxDocument; asset: { id: number; name: string } | null; asset_ambiguous: boolean }
export interface Preview { filename: string; sha256: string; error: string | null; document?: NginxDocument }
export const BASE = '/api/radar/nginx'
export function useServers(q: string, offset: number) {
  return useQuery({ queryKey: ['radar', 'servers', q, offset], queryFn: () => api.get<{ total: number; items: Snapshot[] }>(`${BASE}/servers?q=${encodeURIComponent(q)}&offset=${offset}&limit=50`) })
}
export function useSnapshot(id: number) {
  return useQuery({ queryKey: ['radar', 'snapshot', id], queryFn: () => api.get<Detail>(`${BASE}/snapshots/${id}`) })
}
export function useHistory(id: number) {
  return useQuery({ queryKey: ['radar', 'history', id], queryFn: () => api.get<{ items: Snapshot[] }>(`${BASE}/servers/${id}/snapshots`), enabled: id > 0 })
}
export function sendFiles<T>(kind: 'preview' | 'import', files: File[]) {
  const form = new FormData()
  files.forEach(file => form.append('files', file))
  return api.postForm<T>(`${BASE}/${kind}`, form)
}
export const dateText = (value: string) => new Date(value).toLocaleString('ru-RU')
export const ACTION: Record<string, string> = { proxy: 'Проксирование', static: 'Локальные файлы', return: 'Ответ / перенаправление', unknown: 'Не определено' }
