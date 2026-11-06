export type RegistryOrigin = 'corporate' | 'external' | 'mixed' | 'unknown'
export type RegistryInfo = { registry_origin: RegistryOrigin; registries: string[]; external_registries: string[] }

export type Source = 'harbor' | 'mp_vm'
export type State = 'running' | 'stopped' | 'unused' | 'unknown'
export type Image = RegistryInfo & {
  id: number; source: Source; title: string; image_id: string; tags: string[]; platform: string | null;
  size: number | null; collected_at: string; status: State; host_count: number | null; container_count: number | null
}
export type Container = {
  id: string; name: string; status: string; created_at: string; started_at: string;
  ports: { container_port: string; host_ports: string; protocol: string }[]
}
export type Host = {
  hostname: string; ip: string; os_name: string; host_created_at: string; host_updated_at: string;
  status: State; inventory_present: boolean; containers: Container[]
}
export type Detail = RegistryInfo & {
  source: Source; source_address: string; image_id: string; hash_kind: string; size: number | null;
  collected_at: string; pushed_at?: string; scanned_at?: string; scan_status?: string; sync_error?: string;
  references: { registry: string; repo: string; tag: string }[]; platforms: string[]; hosts: Host[]
}
export type Catalog = {
  items: Image[]; total: number;
  facets: { source: Record<Source, number>; status: Record<State, number> } | null;
  mp_vm: { collected_at: string | null; attempted_at: string; error: string } | null
}

export const SOURCES = { harbor: 'Harbor', mp_vm: 'MaxPatrol VM' }
export const STATES: Record<State, string> = {
  running: 'Есть запущенные', stopped: 'Контейнеры не запущены', unused: 'Без контейнеров', unknown: 'Нет данных о запуске',
}
export const CONTAINER_STATES: Record<string, string> = {
  running: 'Запущен', exited: 'Остановлен', created: 'Создан', dead: 'Завершён', paused: 'Приостановлен',
  restarting: 'Перезапускается', removing: 'Удаляется',
}
export const when = (value?: string | null) => value ? new Date(value).toLocaleString('ru-RU') : '—'
export const sizeText = (value: number | null) => value === null ? '—' : `${(value / 1024 / 1024).toLocaleString('ru-RU', { maximumFractionDigits: 1 })} МиБ`
