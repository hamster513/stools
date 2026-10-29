// Разбор и описание строки crontab (5 полей, синтаксис Vixie cron / cronie) по-русски, ближайшие запуски.
// Секунды, «L», «W», «#», «?» (Quartz) не поддерживаются — это не crontab Linux.

export interface CronFieldDef {
  label: string
  min: number
  max: number
  /** Имена значений (JAN…, SUN…) — индекс 0 соответствует `min`. */
  names?: readonly string[]
}

export const CRON_FIELDS: readonly CronFieldDef[] = [
  { label: 'минута', min: 0, max: 59 },
  { label: 'час', min: 0, max: 23 },
  { label: 'день', min: 1, max: 31 },
  { label: 'месяц', min: 1, max: 12, names: ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'] },
  { label: 'день недели', min: 0, max: 7, names: ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'] },
]

export const CRON_ALIASES: Readonly<Record<string, string>> = {
  '@yearly': '0 0 1 1 *',
  '@annually': '0 0 1 1 *',
  '@monthly': '0 0 1 * *',
  '@weekly': '0 0 * * 0',
  '@daily': '0 0 * * *',
  '@midnight': '0 0 * * *',
  '@hourly': '0 * * * *',
}

/** Элемент списка поля: `*`, `*\/n`, `a`, `a-b`, `a-b/n`, `a/n` (= от a до максимума с шагом n). */
interface Item {
  a: number
  b: number
  step: number
  star: boolean
  single: boolean
}

interface Field {
  text: string
  items: Item[]
  /** Поле начинается со `*` — так cron решает, складывать ли день месяца и день недели через «и». */
  star: boolean
  values: number[]
}

export interface CronSchedule {
  kind: 'schedule'
  /** Пять полей, к которым свелась строка (для `@daily` — `0 0 * * *`). */
  expanded: string
  alias?: string
  fields: [Field, Field, Field, Field, Field]
}
export type Cron = CronSchedule | { kind: 'reboot' }
export type CronResult = { ok: true; cron: Cron } | { ok: false; error: string; field?: number }

class FieldError extends Error {}

function parseNumber(token: string, def: CronFieldDef): number {
  const byName = def.names?.indexOf(token.toUpperCase()) ?? -1
  if (byName >= 0) return def.min + byName
  if (!/^\d+$/.test(token)) {
    if (/^(\?|L|LW|\d+[LW]|\d+#\d+|L-\d+)$/i.test(token)) throw new FieldError(`«${token.replace(/[\d-]/g, '').toUpperCase()}» — синтаксис Quartz, в crontab Linux его нет`)
    throw new FieldError(`«${token}» не число${def.names ? ' и не имя' : ''}`)
  }
  const n = Number(token)
  if (n < def.min || n > def.max) throw new FieldError(`${n} вне диапазона ${def.min}–${def.max}`)
  return n
}

function parseItem(part: string, def: CronFieldDef): Item {
  if (!part) throw new FieldError('пустое значение в списке')
  const [base, stepText, extra] = part.split('/')
  if (extra !== undefined) throw new FieldError(`«${part}»: два шага`)
  let step = 1
  if (stepText !== undefined) {
    if (!/^\d+$/.test(stepText)) throw new FieldError(`«${part}»: шаг должен быть числом`)
    step = Number(stepText)
    if (step < 1) throw new FieldError(`«${part}»: шаг должен быть больше нуля`)
  }
  if (base === '*') return { a: def.min, b: def.max === 7 ? 6 : def.max, step, star: true, single: false }
  const [from, to, more] = base.split('-')
  if (more !== undefined || from === '' || to === '') throw new FieldError(`«${part}»: непонятный диапазон`)
  const a = parseNumber(from, def)
  if (to === undefined) {
    return stepText === undefined ? { a, b: a, step, star: false, single: true } : { a, b: def.max, step, star: false, single: false }
  }
  const b = parseNumber(to, def)
  if (a > b) throw new FieldError(`«${part}»: начало диапазона больше конца`)
  return { a, b, step, star: false, single: false }
}

function parseField(text: string, def: CronFieldDef): Field {
  const items = text.split(',').map((p) => parseItem(p, def))
  const set = new Set<number>()
  for (const it of items) for (let v = it.a; v <= it.b; v += it.step) set.add(def.max === 7 && v === 7 ? 0 : v)
  return { text, items, star: text.startsWith('*'), values: [...set].sort((x, y) => x - y) }
}

/** Разбирает строку crontab: пять полей через пробел или специальную строку `@…`. */
export function parseCron(input: string): CronResult {
  const text = input.trim()
  if (text.startsWith('@')) {
    const alias = text.toLowerCase()
    if (alias === '@reboot') return { ok: true, cron: { kind: 'reboot' } }
    const expanded = CRON_ALIASES[alias]
    if (!expanded) return { ok: false, error: `Неизвестная специальная строка «${text}»: есть ${[...Object.keys(CRON_ALIASES), '@reboot'].join(', ')}` }
    const r = parseCron(expanded)
    return r.ok && r.cron.kind === 'schedule' ? { ok: true, cron: { ...r.cron, alias } } : r
  }
  const parts = text ? text.split(/\s+/) : []
  if (parts.length !== 5) {
    const hint = parts.length === 6 ? ' — поле секунд в crontab Linux не поддерживается' : ''
    return { ok: false, error: `Ожидается 5 полей через пробел: минута, час, день, месяц, день недели; в строке ${parts.length}${hint}` }
  }
  const fields: Field[] = []
  for (let i = 0; i < 5; i++) {
    try {
      fields.push(parseField(parts[i], CRON_FIELDS[i]))
    } catch (e) {
      if (!(e instanceof FieldError)) throw e
      return { ok: false, error: `Поле «${CRON_FIELDS[i].label}»: ${e.message}`, field: i }
    }
  }
  return { ok: true, cron: { kind: 'schedule', expanded: parts.join(' '), fields: fields as CronSchedule['fields'] } }
}

/** Значения поля после раскрытия шагов и диапазонов; у дня недели 7 сведено к 0. */
export function fieldValues(c: CronSchedule, index: number): number[] {
  return c.fields[index].values
}

// ---------- описание ----------

const MONTH_PREP = ['январе', 'феврале', 'марте', 'апреле', 'мае', 'июне', 'июле', 'августе', 'сентябре', 'октябре', 'ноябре', 'декабре']
const MONTH_GEN = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря']
const MONTH_ACC = ['январь', 'февраль', 'март', 'апрель', 'май', 'июнь', 'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь']
export const MONTH_SHORT = ['янв', 'фев', 'мар', 'апр', 'май', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек']
// День недели: индекс 0 и 7 — воскресенье.
const DOW_DAT = ['воскресеньям', 'понедельникам', 'вторникам', 'средам', 'четвергам', 'пятницам', 'субботам', 'воскресеньям']
const DOW_GEN = ['воскресенья', 'понедельника', 'вторника', 'среды', 'четверга', 'пятницы', 'субботы', 'воскресенья']
const DOW_ACC = ['воскресенье', 'понедельник', 'вторник', 'среду', 'четверг', 'пятницу', 'субботу', 'воскресенье']
export const DOW_SHORT = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб', 'вс']

/** Форма слова по числу: 1 минуту, 2 минуты, 5 минут. */
export function plural(n: number, one: string, few: string, many: string): string {
  const d = n % 10
  const h = n % 100
  if (d === 1 && h !== 11) return one
  if (d >= 2 && d <= 4 && (h < 12 || h > 14)) return few
  return many
}

export function joinRu(list: string[]): string {
  return list.length <= 1 ? (list[0] ?? '') : `${list.slice(0, -1).join(', ')} и ${list[list.length - 1]}`
}

const pad = (n: number) => String(n).padStart(2, '0')
const hm = (h: number, m: number) => `${pad(h)}:${pad(m)}`

const isAny = (f: Field) => f.items.length === 1 && f.items[0].star && f.items[0].step === 1
const allSingle = (f: Field) => f.items.every((i) => i.single)
const only = (f: Field) => (f.items.length === 1 ? f.items[0] : null)
const singleStep = (f: Field) => { const i = only(f); return i && i.step > 1 ? i : null }
const singleRange = (f: Field) => { const i = only(f); return i && !i.single && !i.star && i.step === 1 ? i : null }

/** Элементы списка для фраз «в минуты …», «в часы …»: 5, 0–10, каждую 20-ю. */
function listText(f: Field, nth: (n: number) => string, name: (v: number) => string = String): string {
  return joinRu(f.items.map((i) => {
    if (i.single) return name(i.a)
    const range = `${name(i.a)}–${name(i.b)}`
    if (i.step === 1) return range
    return i.star ? nth(i.step) : `${nth(i.step)} из ${range}`
  }))
}

/** Хвост про часы после фразы о минутах. */
function hourSuffix(h: Field, anyText: string): string {
  if (isAny(h)) return anyText
  const one = only(h)
  if (one?.single) return ` с ${hm(one.a, 0)} по ${hm(one.a, 59)}`
  const range = singleRange(h)
  if (range) return ` с ${hm(range.a, 0)} по ${hm(range.b, 59)}`
  const step = singleStep(h)
  if (step) return ` в каждый ${step.step}-й час${step.star ? '' : ` с ${step.a} по ${step.b}`}`
  return ` в часы ${listText(h, (n) => `каждый ${n}-й`)}`
}

function timePhrase(m: Field, h: Field): string {
  if (allSingle(m) && allSingle(h) && m.values.length * h.values.length <= 8) {
    return `в ${joinRu(h.values.flatMap((hh) => m.values.map((mm) => hm(hh, mm))))}`
  }
  if (allSingle(m)) {
    const last = m.values[m.values.length - 1]
    const minutes = `${joinRu(m.values.map(String))} ${plural(last, 'минуту', 'минуты', 'минут')}`
    if (isAny(h)) return `каждый час в ${minutes}`
    const step = singleStep(h)
    if (step?.star) return `каждые ${step.step} ${plural(step.step, 'час', 'часа', 'часов')} в ${minutes}`
    const range = singleRange(h)
    if (range && m.values.length === 1) return `каждый час с ${hm(range.a, m.values[0])} по ${hm(range.b, m.values[0])}`
    return `в ${minutes},${hourSuffix(h, '')}`
  }
  if (isAny(m)) return `каждую минуту${hourSuffix(h, '')}`
  const step = singleStep(m)
  if (step) {
    const base = `каждые ${step.step} ${plural(step.step, 'минуту', 'минуты', 'минут')}${step.star ? '' : ` в минуты ${step.a}–${step.b}`}`
    return base + hourSuffix(h, '')
  }
  return `в минуты ${listText(m, (n) => `каждую ${n}-ю`)}${hourSuffix(h, ' каждого часа')}`
}

function domPhrase(d: Field): string | null {
  if (isAny(d)) return null
  if (allSingle(d)) return `${joinRu(d.values.map((v) => `${v}-го`))} числа`
  const range = singleRange(d)
  if (range) return `с ${range.a}-го по ${range.b}-е число`
  const step = singleStep(d)
  if (step) return `в каждый ${step.step}-й день месяца${step.star ? '' : ` с ${step.a}-го по ${step.b}-е число`}`
  return `в дни месяца ${listText(d, (n) => `каждый ${n}-й`)}`
}

function dowPhrase(w: Field): string | null {
  if (isAny(w)) return null
  if (allSingle(w)) {
    const days = [...new Set(w.items.map((i) => (i.a === 7 ? 0 : i.a)))].sort((x, y) => ((x + 6) % 7) - ((y + 6) % 7))
    return `по ${joinRu(days.map((v) => DOW_DAT[v]))}`
  }
  const range = singleRange(w)
  if (range) return `с ${DOW_GEN[range.a]} по ${DOW_ACC[range.b]}`
  const step = singleStep(w)
  if (step?.star) return `в каждый ${step.step}-й день недели`
  return `по дням недели: ${listText(w, (n) => `каждый ${n}-й`, (v) => DOW_SHORT[v])}`
}

function monthPhrase(mo: Field): string | null {
  if (isAny(mo)) return null
  if (allSingle(mo)) return `в ${joinRu(mo.values.map((v) => MONTH_PREP[v - 1]))}`
  const range = singleRange(mo)
  if (range) return `с ${MONTH_GEN[range.a - 1]} по ${MONTH_ACC[range.b - 1]}`
  const step = singleStep(mo)
  if (step) return `в каждый ${step.step}-й месяц${step.star ? '' : ` с ${MONTH_GEN[step.a - 1]} по ${MONTH_ACC[step.b - 1]}`}`
  return `в месяцы ${listText(mo, (n) => `каждый ${n}-й`, (v) => MONTH_SHORT[v - 1])}`
}

/** Описание расписания одной фразой: «В 04:05 по понедельникам.» */
export function describeCron(c: Cron): string {
  if (c.kind === 'reboot') return 'При загрузке системы.'
  const [m, h, d, mo, w] = c.fields
  const parts = [timePhrase(m, h)]
  const dom = domPhrase(d)
  const dow = dowPhrase(w)
  // cron: если оба поля заданы и ни одно не начинается со «*», срабатывает по любому из них.
  if (dom && dow) parts.push(d.star || w.star ? `${dom} и только ${dow}` : `${dom} или ${dow}`)
  else if (dom ?? dow) parts.push((dom ?? dow) as string)
  const month = monthPhrase(mo)
  if (month) parts.push(month)
  const text = parts.join(' ')
  return `${text[0].toUpperCase()}${text.slice(1)}.`
}

/** Значения поля сжато: «0–5, 10», у месяцев и дней недели — короткие имена. */
export function compactValues(c: CronSchedule, index: number): string {
  const def = CRON_FIELDS[index]
  const values = c.fields[index].values
  const full = index === 4 ? 7 : def.max - def.min + 1
  if (values.length === full) return 'любое'
  const name = (v: number) => (index === 3 ? MONTH_SHORT[v - 1] : index === 4 ? DOW_SHORT[v] : String(v))
  const runs: string[] = []
  for (let i = 0; i < values.length; i++) {
    let j = i
    while (j + 1 < values.length && values[j + 1] === values[j] + 1) j++
    runs.push(j - i >= 2 ? `${name(values[i])}–${name(values[j])}` : values.slice(i, j + 1).map(name).join(', '))
    i = j
  }
  return runs.join(', ')
}

// ---------- ближайшие запуски ----------

/** Сколько дней вперёд искать: 29 февраля бывает раз в 4 года (и реже — 2100 не високосный). */
const HORIZON_DAYS = 366 * 8

/**
 * Ближайшие `count` запусков строго после `from` по местному времени браузера. Пустой список — расписание
 * не сработает никогда (30 февраля). День месяца и день недели — по правилу cron: оба заданы без «*» — «или».
 */
export function nextRuns(c: CronSchedule, from: Date, count: number): Date[] {
  const [m, h, d, mo, w] = c.fields
  const months = new Set(mo.values)
  const doms = new Set(d.values)
  const dows = new Set(w.values)
  const either = !d.star && !w.star
  const out: Date[] = []
  const y = from.getFullYear()
  const mon = from.getMonth()
  const day = from.getDate()
  for (let off = 0; off <= HORIZON_DAYS && out.length < count; off++) {
    const date = new Date(y, mon, day + off)
    if (!months.has(date.getMonth() + 1)) continue
    const domOk = doms.has(date.getDate())
    const dowOk = dows.has(date.getDay())
    if (either ? !(domOk || dowOk) : !(domOk && dowOk)) continue
    for (const hh of h.values) {
      for (const mm of m.values) {
        const t = new Date(date.getFullYear(), date.getMonth(), date.getDate(), hh, mm)
        // Переход на летнее время: несуществующий час браузер сдвигает — такой запуск пропускаем.
        if (t.getHours() !== hh || t <= from) continue
        out.push(t)
        if (out.length === count) return out
      }
    }
  }
  return out
}
