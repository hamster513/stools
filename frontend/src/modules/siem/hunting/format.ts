/** Дата `YYYY-MM-DD` из API — в привычный вид `ДД.ММ.ГГГГ`, без сдвига поясом. */
export function ruDay(value: string | null | undefined): string {
  return value ? value.split('-').reverse().join('.') : '—'
}

/** Момент времени (ISO) — в местных дате и времени. */
export function ruStamp(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })
}
