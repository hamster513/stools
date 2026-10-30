import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/Button'

/** «Скопировать» с отметкой результата; без доступа к буферу просит выделить текст вручную. */
export function CopyButton({ text, label = 'Скопировать', compact = false }: { text: string; label?: string; compact?: boolean }) {
  const [state, setState] = useState<'ok' | 'fail' | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('ok')
    } catch {
      // Буфер недоступен (не защищённый контекст, запрет браузера) — текст остаётся выделяемым.
      setState('fail')
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState(null), 2500)
  }

  return (
    <span className="inline-flex items-center gap-2">
      <Button variant={compact ? 'ghost' : 'secondary'} onClick={copy} disabled={!text} aria-label={compact ? label : undefined} title={compact ? label : undefined}>
        <Copy size={14} aria-hidden />{!compact && label}
      </Button>
      {state === 'ok' && <span className="flex items-center gap-1 text-xs text-kind-accepted" role="status"><Check size={13} aria-hidden />Скопировано</span>}
      {state === 'fail' && <span className="text-xs text-kind-1" role="status">Не удалось — выделите вручную</span>}
    </span>
  )
}
