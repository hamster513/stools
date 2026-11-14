export const MAX_INPUT_BYTES = 1024 * 1024
export const TABLE_LIMIT = 200
const OUTPUT_LIMIT = 8 * MAX_INPUT_BYTES
const MAX_DEPTH = 128
export type DataFormat = 'json' | 'jsonl' | 'csv' | 'xml'
export type DataRow = Record<string, unknown>
export interface DataDocument {
  format: DataFormat
  text: string
  rows: DataRow[]
  fields: string[]
  value?: unknown
}
export interface DataChange { kind: 'added' | 'removed' | 'changed'; path: string; before?: string; after?: string }
export interface DataComparison { changes: DataChange[]; total: number }

function checkInput(text: string) {
  if (new TextEncoder().encode(text).length > MAX_INPUT_BYTES) throw new Error('Размер ввода превышает 1 МиБ.')
  if (!text.trim()) throw new Error('Документ пуст.')
}
function checkedOutput(text: string) {
  if (text.length > OUTPUT_LIMIT) throw new Error('Форматированный результат превышает 8 МиБ. Уменьшите документ.')
  return text
}
function object(value: unknown): value is DataRow { return value !== null && typeof value === 'object' && !Array.isArray(value) }
function checkDepth(value: unknown, depth = 0): void {
  if (depth > MAX_DEPTH) throw new Error('Слишком большая вложенность: максимум 128 уровней.')
  if (value && typeof value === 'object') for (const child of Object.values(value)) checkDepth(child, depth + 1)
}
/** Exact decimal normalization, without expanding large positive/negative exponents. */
function decimalValue(token: string): string {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token)!
  const fraction = match[3] ?? ''
  const digits = (match[2] + fraction).replace(/^0+/, '')
  if (!digits) return '0'
  const coefficient = digits.replace(/0+$/, '')
  const exponent = BigInt((match[4] ?? '0').replace(/^([+-]?)0+(?=\d)/, '$1'))
    - BigInt(fraction.length) + BigInt(digits.length - coefficient.length)
  return `${match[1]}${coefficient}e${exponent}`
}

function parseJson(source: string): unknown {
  const value: unknown = JSON.parse(source)
  // Consume complete quoted strings first so digits in keys/values are never treated as numbers.
  const tokens = /"(?:\\.|[^"\\])*"|(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/g
  for (const match of source.matchAll(tokens)) {
    const token = match[1]
    if (token === undefined) continue
    const number = Number(token)
    if (!Number.isFinite(number) || (Number.isInteger(number) && !Number.isSafeInteger(number))) {
      throw new Error('Число вне поддерживаемого диапазона: нужны конечные значения и целые от −9007199254740991 до 9007199254740991. Передайте точное значение строкой.')
    }
    const underflow = number === 0 && /[1-9]/.test(token.split(/[eE]/, 1)[0])
    if (Object.is(number, -0) || underflow || decimalValue(token) !== decimalValue(String(number))) {
      throw new Error('Число теряет точность при преобразовании в JavaScript Number. Передайте точное значение строкой.')
    }
  }
  return value
}

export function cellText(value: unknown): string {
  return typeof value === 'string' ? value : value === undefined ? '' : JSON.stringify(value)
}

interface CsvResult { rows: string[][]; lines: number[] }
function readCsv(source: string, delimiter: string): CsvResult {
  if (![',', ';', '\t', '|'].includes(delimiter)) throw new Error('Недопустимый разделитель CSV.')
  const text = source.replace(/^\uFEFF/, '')
  const rows: string[][] = [], lines: number[] = []
  let row: string[] = [], field = '', quoted = false, closed = false, line = 1, rowLine = 1
  const fail = (message: string): never => { throw new Error(`CSV, строка ${line}: ${message}`) }
  const pushField = () => { row.push(field); field = ''; closed = false }
  const pushRow = () => { pushField(); rows.push(row); lines.push(rowLine); row = [] }
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++ } else { quoted = false; closed = true }
      } else {
        field += c
        if (c === '\n' || (c === '\r' && text[i + 1] !== '\n')) line++
      }
      continue
    }
    if (c === delimiter) { pushField(); continue }
    if (c === '\r' || c === '\n') {
      pushRow()
      if (c === '\r' && text[i + 1] === '\n') i++
      line++; rowLine = line
      continue
    }
    if (closed) fail('после закрывающей кавычки ожидается разделитель или конец строки.')
    if (c === '"') {
      if (field) fail('кавычка внутри поля без экранирования.')
      quoted = true
    } else field += c
  }
  if (quoted) fail('незакрытое поле в кавычках.')
  if (field || row.length || closed) pushRow()
  return { rows, lines }
}
export function parseCsv(source: string, delimiter = ','): string[][] {
  checkInput(source)
  return readCsv(source, delimiter).rows
}
function encodeCsv(rows: string[][], delimiter: string): string {
  return rows.map(row => row.map(value => (row.length === 1 && value === '') || /["\r\n]/.test(value) || value.includes(delimiter) ? `"${value.replace(/"/g, '""')}"` : value).join(delimiter)).join('\r\n')
}

function formatXml(source: string): string {
  if (/<!\s*(DOCTYPE|ENTITY)\b/i.test(source)) throw new Error('XML: DTD и ENTITY запрещены.')
  if (typeof DOMParser === 'undefined') throw new Error('XML доступен только в браузере.')
  const doc = new DOMParser().parseFromString(source, 'application/xml')
  const errors = doc.getElementsByTagName('parsererror')
  if (errors.length) throw new Error(`XML: ${errors[0].textContent?.slice(0, 400) || 'ошибка синтаксиса'}`)
  const serializer = new XMLSerializer()
  let size = 0
  const pieces: string[] = []
  const append = (text: string) => { size += text.length; if (size > OUTPUT_LIMIT) throw new Error('Форматированный XML превышает 8 МиБ.'); pieces.push(text) }
  const visit = (node: Node, depth: number, preserve = false) => {
    if (depth > MAX_DEPTH) throw new Error('Слишком большая вложенность XML: максимум 128 уровней.')
    if (node.nodeType !== 1) { append(serializer.serializeToString(node)); return }
    const element = node as Element
    const space = element.getAttributeNS('http://www.w3.org/XML/1998/namespace', 'space')
    const keep = space === 'preserve' || (space !== 'default' && preserve)
    const children = Array.from(node.childNodes)
    const mixed = keep || children.some(child => child.nodeType === 4 || (child.nodeType === 3 && !!child.textContent))
    // Serialization of mixed content preserves significant whitespace and avoids adding text nodes.
    if (mixed || !children.some(child => child.nodeType === 1)) {
      const stack: [Node, number][] = [[node, depth]]
      while (stack.length) {
        const [current, d] = stack.pop()!
        if (d > MAX_DEPTH) throw new Error('Слишком большая вложенность XML: максимум 128 уровней.')
        for (const child of Array.from(current.childNodes)) stack.push([child, d + 1])
      }
      append(serializer.serializeToString(node)); return
    }
    const empty = serializer.serializeToString(node.cloneNode(false))
    append(empty.endsWith('/>') ? empty.slice(0, -2) + '>' : empty.replace(/<\/[^>]+>$/, ''))
    for (const child of children) {
      if (child.nodeType === 3 && !child.textContent?.trim()) continue
      append('\n' + '  '.repeat(depth + 1)); visit(child, depth + 1, keep)
    }
    append('\n' + '  '.repeat(depth) + `</${element.tagName}>`)
  }
  for (const child of Array.from(doc.childNodes)) { if (pieces.length) append('\n'); visit(child, 0) }
  return pieces.join('')
}

export function parseDocument(source: string, format: DataFormat, delimiter = ','): DataDocument {
  checkInput(source)
  source = source.replace(/^\uFEFF/, '')
  let value: unknown, rows: DataRow[]
  if (format === 'xml') return { format, text: formatXml(source), rows: [], fields: [] }
  if (format === 'csv') {
    const csv = readCsv(source, delimiter)
    const headers = csv.rows[0] ?? []
    if (!headers.length || headers.some(h => !h.trim()) || new Set(headers).size !== headers.length) throw new Error('CSV: заголовки должны быть непустыми и уникальными.')
    rows = csv.rows.slice(1).map((row, i) => {
      if (row.length !== headers.length) throw new Error(`CSV, строка ${csv.lines[i + 1]}: ожидалось ${headers.length} полей, получено ${row.length}.`)
      return Object.fromEntries(headers.map((header, index) => [header, row[index]]))
    })
    return { format, text: checkedOutput(encodeCsv(csv.rows, delimiter)), rows, fields: headers }
  }
  if (format === 'jsonl') {
    value = source.split(/\r\n|\n|\r/).flatMap((line, index) => {
      if (!line.trim()) return []
      try { return [parseJson(line)] } catch (error) { throw new Error(`JSONL, строка ${index + 1}: ${error instanceof Error ? error.message : 'некорректный JSON'}`) }
    })
  } else {
    try { value = parseJson(source) } catch (error) { throw new Error(`JSON: ${error instanceof Error ? error.message : 'ошибка синтаксиса'}`) }
  }
  checkDepth(value)
  const text = format === 'jsonl' ? (value as unknown[]).map(row => JSON.stringify(row)).join('\n') : JSON.stringify(value, null, 2)
  rows = (Array.isArray(value) ? value : [value]).map(row => object(row) ? row : { value: row })
  return { format, text: checkedOutput(text), rows, fields: [...new Set(rows.flatMap(row => Object.keys(row)))], value }
}
export function selectRows(rows: DataRow[], fields: string[], filter: string): DataRow[] {
  const needle = filter.toLocaleLowerCase()
  return rows.filter(row => !needle || fields.some(field => Object.hasOwn(row, field) && cellText(row[field]).toLocaleLowerCase().includes(needle)))
    .map(row => Object.fromEntries(fields.map(field => [field, Object.hasOwn(row, field) ? row[field] : null])))
}

export function compareDocuments(a: DataDocument, b: DataDocument, limit = 200): DataComparison {
  const result: DataComparison = { changes: [], total: 0 }
  const add = (kind: DataChange['kind'], path: string, before?: unknown, after?: unknown) => {
    result.total++
    if (result.changes.length < limit) result.changes.push({ kind, path, before: before === undefined ? undefined : cellText(before).slice(0, 500), after: after === undefined ? undefined : cellText(after).slice(0, 500) })
  }
  if (a.format === 'json' && b.format === 'json') {
    const visit = (left: unknown, right: unknown, path: string) => {
      if (Object.is(left, right)) return
      if ((object(left) && object(right)) || (Array.isArray(left) && Array.isArray(right))) {
        const l = left as DataRow, r = right as DataRow
        for (const key of new Set([...Object.keys(l), ...Object.keys(r)])) {
          const nextPath = path.length >= 1024 ? path : `${path}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`
          const p = nextPath.length > 1024 ? nextPath.slice(0, 1023) + '…' : nextPath
          if (!Object.hasOwn(l, key)) add('added', p, undefined, r[key])
          else if (!Object.hasOwn(r, key)) add('removed', p, l[key])
          else visit(l[key], r[key], p)
        }
      } else add('changed', path, left, right)
    }
    visit(a.value, b.value, '')
  } else {
    const left = a.text.split(/\r\n|\n|\r/), right = b.text.split(/\r\n|\n|\r/)
    let start = 0, endA = left.length, endB = right.length
    while (start < endA && start < endB && left[start] === right[start]) start++
    while (endA > start && endB > start && left[endA - 1] === right[endB - 1]) { endA--; endB-- }
    for (let i = start; i < Math.max(endA, endB); i++) {
      const l = i < endA ? left[i] : undefined, r = i < endB ? right[i] : undefined
      if (l !== r) add(l === undefined ? 'added' : r === undefined ? 'removed' : 'changed', `строка ${i + 1}`, l, r)
    }
  }
  return result
}
