/** Форматы дат, размеров и вероятностей на страницах образов. */

export function date(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

export function megabytes(size: number | null): string {
  if (size === null) return '—'
  return `${(size / 1024 / 1024).toLocaleString('ru-RU', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} МБ`
}

/** Вероятность EPSS (0…1) в процентах: `0,04 %`. */
export function epssPercent(epss: number | null): string {
  return epss === null ? '—' : `${(epss * 100).toLocaleString('ru-RU', { maximumFractionDigits: 2 })} %`
}
