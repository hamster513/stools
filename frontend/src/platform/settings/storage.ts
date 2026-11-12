export interface StorageTable { name: string; data_bytes: number; index_bytes: number; total_bytes: number; estimated_rows: number | null }
export interface StorageModule { id: string; title: string; data_bytes: number; index_bytes: number; file_bytes: number | null; external_bytes: number; total_bytes: number; complete: boolean; tables: StorageTable[] }
export interface HistoryPoint { measured_at: string; total_bytes: number; complete: boolean; coverage: string; modules: { id: string; total_bytes: number | null; complete: boolean }[] }
export interface StorageSample extends HistoryPoint { id: number; database_bytes: number; file_bytes: number | null; collector_bytes: number | null; collector_status: string; warnings: string[]; disk: { total_bytes: number; free_bytes: number } | null; modules: StorageModule[] }
export interface StorageResponse { latest: StorageSample | null; history: HistoryPoint[]; tz: string }
export function bytes(value: number | null | undefined): string {
  if (value == null) return 'Нет данных'
  const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ']
  let size = Math.abs(value), i = 0
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++ }
  return `${value < 0 ? '−' : ''}${size.toLocaleString('ru-RU', { maximumFractionDigits: i ? 2 : 0 })} ${units[i]}`
}
export function historyValue(point: HistoryPoint, module: string) {
  return module === 'all' ? point : point.modules.find(m => m.id === module)
}
export function growth(points: HistoryPoint[], module: string): number | null {
  if (points.length < 2) return null
  const first = historyValue(points[0], module), last = historyValue(points[points.length - 1], module)
  if (!first?.complete || !last?.complete || first.total_bytes == null || last.total_bytes == null || module === 'all' && points[0].coverage !== points[points.length - 1].coverage) return null
  return last.total_bytes - first.total_bytes
}
