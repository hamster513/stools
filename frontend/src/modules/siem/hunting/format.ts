import { ApiRequestError } from '@/api/client'

/** Дата `YYYY-MM-DD` из API — в привычный вид `ДД.ММ.ГГГГ`, без сдвига поясом. */
export function ruDay(value: string | null | undefined): string {
  return value ? value.split('-').reverse().join('.') : '—'
}

/**
 * Момент времени (ISO) — в местных дате и времени. С `timeZone` — по часам этого пояса: расписание задано
 * в поясе сервера, и срок запуска в нём совпадает с введённым временем старта. Неизвестный браузеру пояс — местное время.
 */
export function ruStamp(value: string | null | undefined, timeZone?: string): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  try {
    return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short', timeZone })
  } catch {
    return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })
  }
}

/** Сколько прошло между двумя моментами (ISO); конец не задан — до сейчас. Пустое начало — прочерк. */
export function ruSpan(from: string | null | undefined, to?: string | null): string {
  if (!from) return '—'
  const start = new Date(from).getTime()
  const end = to ? new Date(to).getTime() : Date.now()
  if (Number.isNaN(start) || Number.isNaN(end)) return '—'
  const minutes = Math.max(0, Math.round((end - start) / 60_000))
  if (minutes < 1) return 'меньше минуты'
  const days = Math.floor(minutes / 1440)
  const hours = Math.floor((minutes % 1440) / 60)
  const rest = minutes % 60
  return [days ? `${days} д` : '', hours ? `${hours} ч` : '', rest && !days ? `${rest} мин` : ''].filter(Boolean).join(' ')
}

/** Период с точностью до минуты: `от — до`. */
export function ruPeriod(from: string, to: string): string {
  return `${ruStamp(from)} — ${ruStamp(to)}`
}

/** Текст ошибки запроса для строки на странице: сообщение сервера или запасная фраза. */
export function apiMessage(e: unknown, fallback: string): string {
  return e instanceof ApiRequestError ? e.message : fallback
}
