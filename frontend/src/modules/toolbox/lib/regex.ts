/** Pure JavaScript RegExp runner. Run untrusted patterns ONLY inside a disposable Worker. */
export const MAX_INPUT_BYTES = 100 * 1024
export const MAX_PATTERN_LENGTH = 2000
export const MAX_MATCHES = 200
export const MAX_OUTPUT_LENGTH = 256 * 1024
export const REGEX_TIMEOUT_MS = 2000
const MAX_RESULT_LENGTH = 1024 * 1024

export interface RegexRequest {
  pattern: string
  flags: string
  input: string
  replacement: string
  positive: string
  negative: string
}
export interface RegexMatch {
  start: number
  end: number
  text: string
  groups: (string | undefined)[]
  named: Record<string, string | undefined> | undefined
}
export interface RegexResult {
  matches: RegexMatch[]
  truncated: boolean
  replacement: string | null
  replacementError: string | null
  samples: { text: string; expected: boolean; matched: boolean; pass: boolean }[]
}
export type RegexReply = { ok: true; result: RegexResult } | { ok: false; error: string }

/** Size checks are safe on the main thread; compilation/execution are worker-only. */
export function validateRegexRequest(request: RegexRequest): void {
  if (request.pattern.length > MAX_PATTERN_LENGTH) throw new Error(`Шаблон: максимум ${MAX_PATTERN_LENGTH} символов.`)
  if (request.flags.length > 8) throw new Error('Слишком много флагов. Допустимы d g i m s u v y без повторов.')
  const bytes = Object.values(request).reduce((sum, value) => sum + new TextEncoder().encode(value).length, 0)
  if (bytes > MAX_INPUT_BYTES) throw new Error('Суммарный ввод превышает 100 КиБ UTF-8.')
  const lines = [request.positive, request.negative].flatMap(text => text.split(/\r?\n/).filter(line => line.length > 0))
  if (lines.length > 200) throw new Error('Максимум 200 непустых строк примеров суммарно.')
}

/** ECMAScript GetSubstitution for a replacement string (never interpreted as code). */
function substitute(template: string, match: RegexMatch, input: string): string {
  return template.replace(/\$(\$|&|`|'|\d{1,2}|<[^>]*>)/g, (whole: string, token: string) => {
    if (token === '$') return '$'
    if (token === '&') return match.text
    if (token === '`') return input.slice(0, match.start)
    if (token === "'") return input.slice(match.end)
    if (token.startsWith('<')) {
      if (match.named === undefined) return whole
      const name = token.slice(1, -1)
      return Object.hasOwn(match.named, name) ? (match.named[name] ?? '') : ''
    }
    const index = Number(token)
    if (index > 0 && index <= match.groups.length) return match.groups[index - 1] ?? ''
    const first = Number(token[0])
    if (token.length === 2 && first > 0 && first <= match.groups.length) return (match.groups[first - 1] ?? '') + token[1]
    return whole
  })
}

export function runRegex(request: RegexRequest): RegexResult {
  validateRegexRequest(request)
  const regex = new RegExp(request.pattern, request.flags)
  const matches: RegexMatch[] = []
  let truncated = false
  let resultLength = 0
  while (true) {
    const found = regex.exec(request.input)
    if (!found) break
    if (matches.length === MAX_MATCHES) { truncated = true; break }
    const groups = found.slice(1)
    resultLength += found[0].length + groups.reduce((sum, group) => sum + (group?.length ?? 0), 0)
    if (resultLength > MAX_RESULT_LENGTH) throw new Error('Совпадения и группы превышают лимит 1 Ми символов. Сократите ввод или количество групп.')
    matches.push({ start: found.index, end: found.index + found[0].length, text: found[0], groups, named: found.groups ? { ...found.groups } : undefined })
    if (!regex.global) break
    if (found[0].length === 0) {
      const point = request.input.codePointAt(regex.lastIndex)
      regex.lastIndex += (regex.unicode || request.flags.includes('v')) && point !== undefined && point > 0xffff ? 2 : 1
    }
  }

  let replacement: string | null = null
  let replacementError: string | null = truncated ? `Более ${MAX_MATCHES} совпадений: предпросмотр замены отключён. Сократите ввод.` : null
  if (!truncated) {
    let preview = ''
    let cursor = 0
    for (const match of matches) {
      // Check an upper bound before expanding potentially numerous prefix/suffix tokens.
      let expansionLength = 0
      const chunks: string[] = []
      // Expand one token at a time, so amplification cannot allocate an unbounded string.
      const tokenPattern = match.named === undefined
        ? /\$(?:\$|&|`|'|\d{1,2})|[^$]+|\$/g
        : /\$(?:\$|&|`|'|\d{1,2}|<[^>]*>)|[^$]+|\$/g
      const tokens = request.replacement.match(tokenPattern) ?? []
      for (const token of tokens) {
        const chunk = token.startsWith('$') ? substitute(token, match, request.input) : token
        expansionLength += chunk.length
        if (preview.length + match.start - cursor + expansionLength > MAX_OUTPUT_LENGTH) break
        chunks.push(chunk)
      }
      if (preview.length + match.start - cursor + expansionLength > MAX_OUTPUT_LENGTH) {
        replacementError = `Результат замены превышает ${MAX_OUTPUT_LENGTH} символов. Сократите ввод или замену.`
        break
      }
      preview += request.input.slice(cursor, match.start) + chunks.join('')
      cursor = match.end
    }
    if (!replacementError && preview.length + request.input.length - cursor > MAX_OUTPUT_LENGTH) replacementError = `Результат замены превышает ${MAX_OUTPUT_LENGTH} символов.`
    if (!replacementError) replacement = preview + request.input.slice(cursor)
  }

  const samples: RegexResult['samples'] = []
  for (const [text, expected] of [[request.positive, true], [request.negative, false]] as const) {
    for (const line of text.split(/\r?\n/).filter(line => line.length > 0)) {
      regex.lastIndex = 0
      const matched = regex.test(line)
      samples.push({ text: line, expected, matched, pass: matched === expected })
    }
  }
  return { matches, truncated, replacement, replacementError, samples }
}
