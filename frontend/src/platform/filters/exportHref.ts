import { buildQuery, type QueryValue } from '@/api/client'

/**
 * Адрес выгрузки для ExportButton: ручка `<список>/export` с теми же
 * фильтрами и сортировкой, что у списка, и `format`. `limit/offset` сюда не
 * передаются — выгружается весь отбор, а не загруженная страница.
 */
export function exportHref<P extends { [K in keyof P]: QueryValue }>(path: string, params: P): (fmt: 'csv' | 'xlsx') => string {
  return (fmt) => `${path}${buildQuery({ format: fmt, ...(params as Record<string, QueryValue>) })}`
}
