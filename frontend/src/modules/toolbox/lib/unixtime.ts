// Unix time: метка → дата и обратно. Единица метки угадывается по числу цифр, как в логах разных систем.

export type TsUnit = 's' | 'ms' | 'us' | 'ns'
export const UNIT_LABELS: Record<TsUnit, string> = { s: 'секунды', ms: 'миллисекунды', us: 'микросекунды', ns: 'наносекунды' }
const DIVISOR: Record<TsUnit, number> = { s: 1e-3, ms: 1, us: 1e3, ns: 1e6 }

export type TsResult = { ok: true; ms: number; unit: TsUnit } | { ok: false; error: string }

/** Самая поздняя дата, которую умеет Date: ±100 млн дней от 1970 года. */
const MAX_MS = 8.64e15

/**
 * Метка в секундах (до 11 цифр, можно с дробью), миллисекундах (12–14), микросекундах (15–17) или наносекундах (18–19).
 * Пробелы и подчёркивания между цифрами игнорируются: так метки копируются из логов и таблиц.
 */
export function parseTimestamp(input: string): TsResult {
  const text = input.replace(/[\s_]/g, '')
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(text)
  if (!m) return { ok: false, error: 'Метка — целое число, например 1761734400; у секунд можно дробную часть через точку' }
  const digits = m[2].replace(/^0+(?=\d)/, '').length
  const unit: TsUnit | null = digits <= 11 ? 's' : digits <= 14 ? 'ms' : digits <= 17 ? 'us' : digits <= 19 ? 'ns' : null
  if (!unit) return { ok: false, error: 'Слишком длинное число: больше 19 цифр не бывает даже у наносекунд' }
  if (m[3] !== undefined && unit !== 's') return { ok: false, error: 'Дробная часть бывает только у секунд' }
  const ms = Math.trunc(Number(text) / DIVISOR[unit])
  if (Math.abs(ms) > MAX_MS) return { ok: false, error: 'Дата вне диапазона, который умеет браузер' }
  return { ok: true, ms: ms === 0 ? 0 : ms, unit }
}

/** «2025-10-29 10:40:00 UTC», миллисекунды — только если есть. */
export function formatUtc(ms: number): string {
  const iso = new Date(ms).toISOString()
  const frac = iso.slice(19, 23)
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}${frac === '.000' ? '' : frac} UTC`
}

/** Местное время браузера: «29.10.2025, 13:40:00». */
export function formatLocal(ms: number): string {
  return new Date(ms).toLocaleString('ru-RU', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function weekday(ms: number, utc: boolean): string {
  return new Date(ms).toLocaleDateString('ru-RU', { weekday: 'long', ...(utc ? { timeZone: 'UTC' } : {}) })
}

/** Часовой пояс браузера: «Europe/Moscow, UTC+3». */
export function localZone(ms: number): string {
  const name = Intl.DateTimeFormat().resolvedOptions().timeZone
  const off = -new Date(ms).getTimezoneOffset()
  const sign = off < 0 ? '−' : '+'
  const h = Math.floor(Math.abs(off) / 60)
  const min = Math.abs(off) % 60
  return `${name}, UTC${sign}${h}${min ? `:${String(min).padStart(2, '0')}` : ''}`
}

const RELATIVE_STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 86_400_000],
  ['month', 30 * 86_400_000],
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
  ['second', 1000],
]

/**
 * «5 минут назад», «через 3 дня»; меньше секунды — «сейчас». Округление, а не отсечение, и всегда число: «через 43 часа»
 * не должно читаться как «завтра».
 */
export function relative(ms: number, now: number): string {
  const diff = ms - now
  if (Math.abs(diff) < 1000) return 'сейчас'
  const fmt = new Intl.RelativeTimeFormat('ru', { numeric: 'always' })
  const [unit, size] = RELATIVE_STEPS.find(([, sz]) => Math.abs(diff) >= sz) ?? RELATIVE_STEPS[RELATIVE_STEPS.length - 1]
  return fmt.format(Math.round(diff / size), unit)
}

/** Значение поля `datetime-local` («2025-10-29T10:40[:00]») → миллисекунды; `utc` — считать введённое временем UTC. */
export function fromDateInput(value: string, utc: boolean): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value)
  if (!m) return null
  const [y, mo, d, h, mi, s] = m.slice(1).map((x) => Number(x ?? 0))
  const ms = utc ? Date.UTC(y, mo - 1, d, h, mi, s) : new Date(y, mo - 1, d, h, mi, s).getTime()
  return Number.isNaN(ms) ? null : ms
}
