import { Fragment, useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { CopyButton } from '../components/CopyButton'
import { MAX_MATCHES, REGEX_TIMEOUT_MS, validateRegexRequest, type RegexReply, type RegexRequest, type RegexResult } from '../lib/regex'

const AREA = cn(FIELD, 'min-h-28 resize-y font-mono text-xs')
const EMPTY: RegexRequest = { pattern: '', flags: 'g', input: '', replacement: '', positive: '', negative: '' }

function Highlight({ text, result }: { text: string; result: RegexResult }) {
  let cursor = 0
  const parts = result.matches.map((match, index) => {
    const before = text.slice(cursor, match.start)
    cursor = match.end
    return <Fragment key={index}>{before}<mark className="rounded bg-row-selected text-text underline decoration-primary" title={`[${match.start}, ${match.end})`}>{match.text || <span aria-label={`Пустое совпадение в позиции ${match.start}`}>∅</span>}</mark></Fragment>
  })
  return <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-grid bg-surface p-3 font-mono text-xs">{parts}{text.slice(cursor)}</pre>
}

/** Explicit runs in disposable workers keep catastrophic backtracking away from the UI. */
export function RegexPage() {
  const [fields, setFields] = useState<RegexRequest>(EMPTY)
  const [result, setResult] = useState<RegexResult | null>(null)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('Введите шаблон и текст, затем нажмите «Проверить». Пустой шаблон тоже допустим.')
  const [running, setRunning] = useState(false)
  const worker = useRef<Worker | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  function dispose() {
    clearTimeout(timer.current)
    timer.current = undefined
    worker.current?.terminate()
    worker.current = null
  }
  useEffect(() => () => {
    clearTimeout(timer.current)
    worker.current?.terminate()
    worker.current = null
  }, [])

  function edit(key: keyof RegexRequest, value: string) {
    dispose()
    setRunning(false)
    setFields(previous => ({ ...previous, [key]: value }))
    setResult(null)
    setError('')
    setStatus('Ввод изменён — нажмите «Проверить».')
  }
  function cancel() {
    dispose()
    setRunning(false)
    setStatus('Выполнение отменено.')
  }
  function clear() {
    cancel()
    setFields(EMPTY)
    setResult(null)
    setError('')
    setStatus('Поля очищены.')
  }
  function run() {
    dispose()
    setResult(null)
    setError('')
    setRunning(false)
    try {
      validateRegexRequest(fields)
      const current = new Worker(new URL('../lib/regex.worker.ts', import.meta.url), { type: 'module' })
      worker.current = current
      setRunning(true)
      setStatus('Выполняется…')
      const fail = (message: string) => {
        if (worker.current !== current) return
        dispose()
        setRunning(false)
        setError(message)
        setStatus('Проверка завершилась с ошибкой.')
      }
      timer.current = setTimeout(() => fail('Превышен лимит 2 секунды. Worker завершён. Упростите шаблон или сократите текст.'), REGEX_TIMEOUT_MS)
      current.onmessage = (event: MessageEvent<RegexReply>) => {
        if (worker.current !== current) return
        dispose()
        setRunning(false)
        if (event.data.ok) {
          setResult(event.data.result)
          setStatus('Проверка завершена.')
        } else {
          setError(event.data.error)
          setStatus('Ошибка шаблона или ввода.')
        }
      }
      current.onerror = () => fail('Не удалось запустить или выполнить Worker. Попробуйте ещё раз.')
      current.onmessageerror = () => fail('Не удалось прочитать ответ Worker.')
      current.postMessage(fields)
    } catch (cause) {
      dispose()
      setRunning(false)
      setError(cause instanceof Error ? cause.message : 'Не удалось запустить проверку.')
      setStatus('Ошибка ввода или запуска.')
    }
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <p className="mb-4 max-w-3xl text-xs text-text-secondary">Движок JavaScript RegExp текущего браузера. Проверка выполняется локально в отдельном Worker, без отправки или сохранения данных. Суммарно до 100 КиБ UTF-8, шаблон до 2000 символов, выполнение до 2 секунд.</p>
      <div className="grid gap-4 md:grid-cols-[1fr_180px]">
        <label className="block"><span className="mb-1 block text-xs font-medium text-text">Шаблон (без /…/)</span><input id="regex-pattern" className={cn(FIELD, 'font-mono')} value={fields.pattern} onChange={e => edit('pattern', e.target.value)} spellCheck={false} autoComplete="off" placeholder="(?<word>\w+)" /></label>
        <label className="block"><span className="mb-1 block text-xs font-medium text-text">Флаги</span><input id="regex-flags" className={cn(FIELD, 'font-mono')} value={fields.flags} onChange={e => edit('flags', e.target.value)} spellCheck={false} autoComplete="off" aria-describedby="regex-flag-help" /></label>
      </div>
      <p id="regex-flag-help" className="my-3 max-w-4xl text-xs text-text-secondary">g — все совпадения, без g — только первое; i — без учёта регистра; m — ^/$ для каждой строки; s — точка включает перенос; u/v — Unicode (взаимоисключающие); y — только с текущей позиции; d — индексы движка. Поддержка флагов зависит от браузера.</p>
      <label className="mb-4 block"><span className="mb-1 block text-xs font-medium text-text">Текст для проверки</span><textarea aria-label="Текст для проверки" id="regex-input" className={cn(AREA, 'min-h-40')} value={fields.input} onChange={e => edit('input', e.target.value)} spellCheck={false} /></label>
      <label className="block"><span className="mb-1 block text-xs font-medium text-text">Строка замены (пустая строка удаляет совпадение)</span><textarea aria-label="Строка замены (пустая строка удаляет совпадение)" id="regex-replacement" className={AREA} value={fields.replacement} onChange={e => edit('replacement', e.target.value)} spellCheck={false} aria-describedby="regex-replacement-help" /></label>
      <p id="regex-replacement-help" className="my-3 text-xs text-text-secondary">{'Синтаксис JavaScript: $$ — знак $, $& — совпадение, $1…$99 — группы, $<name> — именованная группа, $` — текст до, $\' — текст после совпадения.'}</p>
      <details className="mb-4 rounded border border-grid p-3">
        <summary className="cursor-pointer text-sm text-text">Положительные и отрицательные примеры (необязательно)</summary>
        <p className="my-3 text-xs text-text-secondary">Одна проверка на строку; пустые строки пропускаются, пробелы сохраняются. До 200 строк суммарно. Положительный пример должен содержать совпадение, отрицательный — не должен. Для проверки всей строки используйте ^ и $.</p>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="block"><span className="mb-1 block text-xs font-medium text-text">Положительные примеры</span><textarea aria-label="Положительные примеры" id="regex-positive" className={AREA} value={fields.positive} onChange={e => edit('positive', e.target.value)} spellCheck={false} /></label>
          <label className="block"><span className="mb-1 block text-xs font-medium text-text">Отрицательные примеры</span><textarea aria-label="Отрицательные примеры" id="regex-negative" className={AREA} value={fields.negative} onChange={e => edit('negative', e.target.value)} spellCheck={false} /></label>
        </div>
      </details>
      <div className="flex flex-wrap items-center gap-3"><Button variant="primary" onClick={run}>{running ? 'Запустить заново' : 'Проверить'}</Button>{running && <Button onClick={cancel}>Отменить</Button>}<Button onClick={clear}>Очистить</Button></div>
      <p role="status" className="my-3 text-xs text-text-secondary">{status}</p>
      {error && <p role="alert" className="my-3 rounded border border-kind-1/40 p-3 text-sm text-kind-1">{error}</p>}
      {result && <div className="space-y-5">
        <section aria-label="Совпадения">
          <h2 className="mb-2 text-sm font-semibold text-text">Совпадения: {result.matches.length}{result.truncated ? '+' : ''}</h2>
          {result.truncated && <p className="mb-2 text-xs text-kind-1">Показаны только первые {MAX_MATCHES} совпадений; остальные не подсвечены.</p>}
          <p className="mb-2 text-xs text-text-secondary">Позиции с нуля в кодовых единицах UTF-16: [начало, конец). ∅ — пустое совпадение. Без g показано только первое совпадение.</p>
          <Highlight text={fields.input} result={result} />
          {!result.matches.length && <p className="mt-2 text-sm text-text-secondary">Совпадений нет.</p>}
          {!!result.matches.length && <div className="mt-3 max-h-96 overflow-auto"><table className="w-full text-left text-xs"><thead><tr><th className="p-2">Позиция</th><th className="p-2">Совпадение</th><th className="p-2">Группы</th></tr></thead><tbody>{result.matches.map((match, index) => <tr key={index} className="border-t border-grid align-top"><td className="whitespace-nowrap p-2 font-mono">[{match.start}, {match.end})</td><td className="max-w-80 whitespace-pre-wrap break-all p-2 font-mono">{match.text || '∅'}</td><td className="max-w-96 break-all p-2 font-mono">{!match.groups.length && '—'}{match.groups.map((group, groupIndex) => <div key={groupIndex}>${groupIndex + 1}: {group === undefined ? 'не участвовала' : JSON.stringify(group)}</div>)}{Object.entries(match.named ?? {}).map(([name, value]) => <div key={name}>{name}: {value === undefined ? 'не участвовала' : JSON.stringify(value)}</div>)}</td></tr>)}</tbody></table></div>}
        </section>
        <section aria-label="Предпросмотр замены"><h2 className="mb-2 text-sm font-semibold text-text">Предпросмотр замены</h2>{result.replacementError ? <p role="status" className="text-xs text-kind-1">{result.replacementError}</p> : <><textarea className={AREA} aria-label="Результат замены" value={result.replacement ?? ''} readOnly spellCheck={false} /><div className="mt-2"><CopyButton text={result.replacement ?? ''} label="Скопировать замену" /></div></>}</section>
        {!!result.samples.length && <section aria-label="Результаты примеров"><h2 className="mb-2 text-sm font-semibold text-text">Примеры: пройдено {result.samples.filter(sample => sample.pass).length} / {result.samples.length}</h2><ul className="max-h-80 space-y-2 overflow-auto text-xs">{result.samples.map((sample, index) => <li key={index} className="break-all"><strong className={sample.pass ? 'text-kind-accepted' : 'text-kind-1'}>{sample.pass ? 'OK' : 'Ошибка'}</strong> · {sample.expected ? 'Положительный' : 'Отрицательный'} · {sample.matched ? 'есть совпадение' : 'нет совпадения'}: <code>{sample.text}</code></li>)}</ul></section>}
      </div>}
    </div>
  )
}
