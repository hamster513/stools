// Base64 текста в UTF-8: кодирование (обычный алфавит или URL-safe без «=») и разбор любого из двух алфавитов.

export type Decoded = { ok: true; bytes: Uint8Array; text: string | null } | { ok: false; error: string }

/** Байты → двоичная строка для btoa кусками: String.fromCharCode(...огромный массив) переполняет стек. */
function binary(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return out
}

export function encodeBase64(text: string, urlSafe: boolean): string {
  const b64 = btoa(binary(new TextEncoder().encode(text)))
  return urlSafe ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64
}

/** Пробелы и переносы строк пропускаются, «-» и «_» читаются как «+» и «/», недостающие «=» дописываются. */
export function decodeBase64(input: string): Decoded {
  const clean = input.replace(/\s+/g, '')
  const body = clean.replace(/={1,2}$/, '')
  const bad = /[^A-Za-z0-9+/\-_]/.exec(body)
  if (bad) {
    // Позиция — в исходном тексте, чтобы её можно было найти глазами.
    const pos = input.indexOf(bad[0]) + 1
    return { ok: false, error: `Недопустимый символ «${bad[0]}» в позиции ${pos}` }
  }
  if (body.length % 4 === 1) return { ok: false, error: 'Строка обрывается посреди группы: длина без «=» не может давать остаток 1 при делении на 4' }
  const std = body.replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
  let text: string | null
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    text = null
  }
  return { ok: true, bytes, text }
}

/** Шестнадцатеричный вид первых `limit` байт по 16 в строке. */
export function hexDump(bytes: Uint8Array, limit: number): string {
  const lines: string[] = []
  const shown = bytes.subarray(0, limit)
  for (let i = 0; i < shown.length; i += 16) {
    lines.push([...shown.subarray(i, i + 16)].map((b) => b.toString(16).padStart(2, '0')).join(' '))
  }
  if (bytes.length > limit) lines.push(`… ещё ${bytes.length - limit} байт`)
  return lines.join('\n')
}
