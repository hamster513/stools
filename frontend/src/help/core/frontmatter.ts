// Разбор статьи справки: фронтматтер (небольшое подмножество YAML) + секции тела.
// Поддержано только: `ключ: значение` (в кавычках и без), `ключ: [a, b, "c d"]`,
// вложенный блок `levels:` с отступом в два пробела, `#`-комментарии, пустые строки.
// Всё остальное — HelpParseError(file, line, message).

import type { Article, Group } from './types.ts'

export class HelpParseError extends Error {
  file: string
  line: number

  constructor(file: string, line: number, message: string) {
    super(`${file}:${line}: ${message}`)
    this.name = 'HelpParseError'
    this.file = file
    this.line = line
  }
}

const GROUPS: readonly string[] = ['start', 'module', 'settings', 'glossary']
const STRING_KEYS = ['slug', 'title', 'group', 'module', 'where', 'section'] as const
const LIST_KEYS = ['routes', 'concepts'] as const
const LEVEL_KEYS = ['read', 'write', 'admin', 'any'] as const

/** Строка-ограждение кодового блока (``` или ~~~): внутри него `## ` не заголовок. */
export function isFenceLine(line: string): boolean {
  const t = line.trimStart()
  return t.startsWith('```') || t.startsWith('~~~')
}

/** Отрезает `# комментарий`: `#` в начале строки или после пробела, вне кавычек. */
function stripComment(line: string): string {
  let quote = ''
  let prev = '' // последний непробельный символ перед текущим
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === '\\' && quote === '"') i++
      else if (c === quote) quote = ''
    } else if ((c === '"' || c === "'") && (prev === ':' || prev === '[' || prev === ',')) {
      quote = c
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i)
    }
    if (c.trim()) prev = c
  }
  return line
}

/** Строка в кавычках, начиная с text[pos]; возвращает значение и позицию после закрывающей кавычки. */
function readQuoted(text: string, pos: number): [string, number] {
  const quote = text[pos]
  let out = ''
  for (let i = pos + 1; i < text.length; i++) {
    const c = text[i]
    if (quote === '"' && c === '\\') {
      const n = text[++i]
      if (n === undefined) break
      out += n === 'n' ? '\n' : n === 't' ? '\t' : n
    } else if (quote === "'" && c === "'" && text[i + 1] === "'") {
      out += "'"
      i++
    } else if (c === quote) {
      return [out, i + 1]
    } else {
      out += c
    }
  }
  throw new Error('не закрыта кавычка')
}

function parseScalar(text: string): string {
  if (text[0] === '"' || text[0] === "'") {
    const [value, end] = readQuoted(text, 0)
    if (text.slice(end).trim()) throw new Error('после значения в кавычках лишний текст')
    return value
  }
  return text
}

function parseList(text: string): string[] {
  if (!text.endsWith(']')) throw new Error('не закрыта скобка списка «]»')
  const inner = text.slice(1, -1)
  if (!inner.trim()) return []
  const items: string[] = []
  let pos = 0
  for (;;) {
    while (inner[pos] === ' ') pos++
    let item: string
    if (inner[pos] === '"' || inner[pos] === "'") {
      ;[item, pos] = readQuoted(inner, pos)
      while (inner[pos] === ' ') pos++
      if (pos < inner.length && inner[pos] !== ',') throw new Error('после элемента в кавычках лишний текст')
    } else {
      const comma = inner.indexOf(',', pos)
      const end = comma === -1 ? inner.length : comma
      item = inner.slice(pos, end).trim()
      pos = end
    }
    if (!item) throw new Error('пустой элемент списка')
    items.push(item)
    if (pos >= inner.length) return items
    pos++ // запятая
  }
}

/** Делит markdown по `## ` заголовкам: { 'Что это': 'текст блока', … }. Текст до первого `##` отбрасывается. */
export function splitSections(body: string): Record<string, string> {
  const result: Record<string, string> = {}
  let title: string | null = null
  let buf: string[] = []
  let fenced = false
  const flush = () => {
    if (title !== null) result[title] = buf.join('\n').trim()
  }
  for (const line of body.split(/\r?\n/)) {
    if (isFenceLine(line)) fenced = !fenced
    const m = fenced ? null : /^## +(.+?)\s*$/.exec(line)
    if (m) {
      flush()
      title = m[1]
      buf = []
    } else {
      buf.push(line)
    }
  }
  flush()
  return result
}

export function parseArticle(file: string, raw: string): Article {
  const lines = raw.replace(/^\uFEFF/, '').split(/\r?\n/)
  if (lines[0]?.trimEnd() !== '---') throw new HelpParseError(file, 1, 'статья должна начинаться с фронтматтера «---»')
  const end = lines.findIndex((l, i) => i > 0 && l.trimEnd() === '---')
  if (end === -1) throw new HelpParseError(file, 1, 'не закрыт фронтматтер: нет строки «---»')

  const strings: Record<string, string> = {}
  const lists: Record<string, string[]> = {}
  const levels: NonNullable<Article['levels']> = {}
  let hasLevels = false
  let order: number | undefined
  let inLevels = false
  const seen = new Set<string>()
  const seenLevels = new Set<string>()
  let group: Group | undefined

  for (let i = 1; i < end; i++) {
    const lineNo = i + 1
    try {
      const text = stripComment(lines[i]).trimEnd()
      if (!text.trim()) continue
      const indentText = /^\s*/.exec(text)![0]
      if (indentText.includes('\t')) throw new Error('табуляция в отступе: используйте пробелы')
      const indent = indentText.length
      if (indent !== 0 && indent !== 2) throw new Error('отступ должен быть 0 или 2 пробела')
      const m = /^([A-Za-z][A-Za-z0-9_-]*):(?:\s+(.*))?$/.exec(text.trim())
      if (!m) throw new Error('ожидалось «ключ: значение»')
      const key = m[1]
      const value = (m[2] ?? '').trim()

      if (indent === 2) {
        if (!inLevels) throw new Error('вложенная строка допустима только внутри блока «levels:»')
        if (!(LEVEL_KEYS as readonly string[]).includes(key)) throw new Error(`неизвестный уровень «${key}» (read, write, admin, any)`)
        if (seenLevels.has(key)) throw new Error(`уровень «${key}» указан дважды`)
        seenLevels.add(key)
        if (!value) throw new Error(`пустое значение уровня «${key}»`)
        levels[key as (typeof LEVEL_KEYS)[number]] = parseScalar(value)
        continue
      }

      inLevels = false
      if (seen.has(key)) throw new Error(`ключ «${key}» указан дважды`)
      seen.add(key)
      if (key === 'levels') {
        if (value) throw new Error('«levels» — блок: read/write/admin/any пишутся ниже с отступом в два пробела')
        hasLevels = inLevels = true
      } else if ((STRING_KEYS as readonly string[]).includes(key)) {
        if (!value) throw new Error(`пустое значение «${key}»`)
        if (value.startsWith('[')) throw new Error(`«${key}» — строка, а не список`)
        strings[key] = parseScalar(value)
        if (key === 'group') {
          if (!GROUPS.includes(strings[key])) throw new Error(`group: неизвестная группа «${strings[key]}» (${GROUPS.join(', ')})`)
          group = strings[key] as Group
        }
      } else if ((LIST_KEYS as readonly string[]).includes(key)) {
        if (!value.startsWith('[')) throw new Error(`«${key}» — список вида [a, b]`)
        lists[key] = parseList(value)
      } else if (key === 'order') {
        if (!/^-?\d+$/.test(value)) throw new Error('«order» — целое число')
        order = Number(value)
      } else {
        throw new Error(`неизвестное поле «${key}»`)
      }
    } catch (e) {
      if (e instanceof Error) throw new HelpParseError(file, lineNo, e.message)
      throw e
    }
  }

  for (const key of ['slug', 'title', 'group']) {
    if (!(key in strings)) throw new HelpParseError(file, end + 1, `нет обязательного поля «${key}»`)
  }

  const body = lines.slice(end + 1).join('\n')
  return {
    slug: strings.slug,
    title: strings.title,
    group: group as Group,
    module: strings.module,
    routes: lists.routes ?? [],
    where: strings.where,
    levels: hasLevels ? levels : undefined,
    concepts: lists.concepts ?? [],
    order,
    section: strings.section,
    body,
    file,
    sections: splitSections(body),
  }
}
