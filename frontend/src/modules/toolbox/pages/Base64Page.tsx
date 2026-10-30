import { useMemo, useState } from 'react'
import { AlertTriangle, ArrowDownUp } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { CopyButton } from '../components/CopyButton'
import { decodeBase64, encodeBase64, hexDump } from '../lib/base64'

const AREA = cn(FIELD, 'min-h-[280px] resize-y font-mono text-xs')
const SEG = 'rounded px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
/** Сколько байт не-текста показывать шестнадцатерично: дальше браузеру тяжело, а человеку бесполезно. */
const HEX_LIMIT = 4096

type Mode = 'encode' | 'decode'

/** Base64: кодирование текста в UTF-8 и обратно. Считается в браузере — текст на сервер не уходит. */
export function Base64Page() {
  const [mode, setMode] = useState<Mode>('encode')
  const [urlSafe, setUrlSafe] = useState(false)
  const [input, setInput] = useState('')

  const out = useMemo(() => {
    if (mode === 'encode') return { text: encodeBase64(input, urlSafe), error: null, binary: null as Uint8Array | null }
    const r = decodeBase64(input)
    if (!r.ok) return { text: '', error: r.error, binary: null }
    return r.text === null ? { text: hexDump(r.bytes, HEX_LIMIT), error: null, binary: r.bytes } : { text: r.text, error: null, binary: null }
  }, [mode, urlSafe, input])

  function swap() {
    if (out.error || out.binary) return
    setInput(out.text)
    setMode(mode === 'encode' ? 'decode' : 'encode')
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <p className="mb-4 max-w-2xl text-xs text-text-secondary">
        Кодирование текста в Base64 и обратно, текст — в UTF-8. Всё считается в браузере: текст на сервер не отправляется и нигде не сохраняется.
      </p>

      <div className="mb-4 flex flex-wrap items-center gap-4">
        <div role="radiogroup" aria-label="Направление" className="flex gap-1 rounded border border-border p-0.5">
          {(['encode', 'decode'] as const).map((m) => (
            <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}
              className={cn(SEG, mode === m ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
              {m === 'encode' ? 'Кодировать' : 'Декодировать'}
            </button>
          ))}
        </div>
        {mode === 'encode' && (
          <label className="flex items-center gap-2 text-xs text-text">
            <input type="checkbox" checked={urlSafe} onChange={(e) => setUrlSafe(e.target.checked)} />
            URL-safe (base64url: «-» и «_» вместо «+» и «/», без «=»)
          </label>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text">{mode === 'encode' ? 'Текст' : 'Base64'}</span>
          <textarea className={AREA} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false}
            placeholder={mode === 'encode' ? 'Текст для кодирования' : 'Строка Base64: пробелы и переносы строк не мешают, подходят оба алфавита'} />
          <span className="mt-1 block font-mono text-xs tabular-nums text-text-secondary">символов: {input.length}</span>
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text">{mode === 'encode' ? 'Base64' : out.binary ? 'Байты (шестнадцатерично)' : 'Текст'}</span>
          <textarea className={AREA} value={out.text} readOnly spellCheck={false} placeholder="Здесь появится результат" />
          <span className="mt-1 block font-mono text-xs tabular-nums text-text-secondary">
            {out.binary ? `байт: ${out.binary.length}` : `символов: ${out.text.length}`}
          </span>
        </label>
      </div>

      {out.error && <div role="alert" className="mt-4 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{out.error}</div>}
      {out.binary && <p className="mt-4 text-xs text-text-secondary" role="status">Результат — не текст в UTF-8 (файл, ключ, сжатые данные): показаны байты{out.binary.length > HEX_LIMIT ? `, первые ${HEX_LIMIT}` : ''}.</p>}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <CopyButton text={out.binary ? '' : out.text} />
        <Button onClick={swap} disabled={!out.text || !!out.error || !!out.binary}><ArrowDownUp size={14} aria-hidden />Результат — во ввод</Button>
      </div>
    </div>
  )
}
