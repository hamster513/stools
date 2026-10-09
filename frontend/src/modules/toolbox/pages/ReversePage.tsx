import { useState } from 'react'
import { AlertTriangle, Check, Copy, Lock } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useReverse } from '../api/queries'

const AREA = cn(FIELD, 'min-h-[320px] resize-y font-mono text-xs')

/**
 * Обратный перевод: ответ, полученный по очищенному тексту, возвращается к настоящим значениям.
 * Текст не сохраняется ни на сервере, ни в кэше запросов. Аудитору страница закрыта: результат
 * содержит настоящие значения, а запрос он всё равно получил бы с 403.
 */
export function ReversePage() {
  const { write } = useCan()
  const reverse = useReverse()
  const [input, setInput] = useState('')
  const [copied, setCopied] = useState<'ok' | 'fail' | null>(null)

  if (!write) {
    return <div className="p-6"><EmptyState icon={Lock} title="Доступно аналитику и администратору" description="Результат перевода содержит настоящие значения — аудитору он не открывается." /></div>
  }

  const result = reverse.data
  // Результат относится к тексту, который переводили; правка поля делает его устаревшим только визуально — кнопка «Перевести» остаётся доступной.
  function run() {
    if (!input.trim() || reverse.isPending) return
    setCopied(null)
    reverse.mutate(input)
  }
  async function copy() {
    if (!result) return
    try {
      await navigator.clipboard.writeText(result.text)
      setCopied('ok')
    } catch {
      // Буфер недоступен (не защищённый контекст, запрет браузера) — текст остаётся выделяемым в поле.
      setCopied('fail')
    }
    setTimeout(() => setCopied(null), 2500)
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <h1 className="text-base font-semibold text-text">Обратный перевод</h1>
      <p className="mb-4 max-w-2xl text-xs text-text-secondary">
        Вставьте ответ, полученный по очищенному тексту: псевдонимы из таблицы соответствий заменятся настоящими значениями. Забытые псевдонимы не переводятся.
      </p>

      <div className="grid gap-4 lg:grid-cols-2">
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text">Вставьте ответ</span>
          <textarea className={AREA} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} placeholder="Текст с псевдонимами" />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-text">Результат</span>
          <textarea className={AREA} value={result?.text ?? ''} readOnly spellCheck={false} placeholder="Здесь появится текст с настоящими значениями" />
        </label>
      </div>

      {reverse.error && <div role="alert" className="mt-4 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{reverse.error.message}</div>}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={run} disabled={!input.trim()} loading={reverse.isPending}>Перевести</Button>
        <Button onClick={copy} disabled={!result}><Copy size={14} aria-hidden />Скопировать</Button>
        {copied === 'ok' && <span className="flex items-center gap-1 text-xs text-kind-accepted" role="status"><Check size={13} aria-hidden />Скопировано</span>}
        {copied === 'fail' && <span className="text-xs text-kind-1" role="status">Не удалось скопировать — выделите текст в поле вручную</span>}
        {result && <span className="font-mono text-xs tabular-nums text-text-secondary">замен: {result.replaced}</span>}
      </div>
    </div>
  )
}
