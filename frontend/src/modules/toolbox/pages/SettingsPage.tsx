import { useEffect, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, Check, ChevronDown, ChevronRight, Lock, Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'
import { moduleTitle } from '@/platform/modules'
import { useSaveToolboxSettings, useToolboxSettings } from '../api/queries'
import type { ToolboxSettings } from '../api/types'

/** Строка списка с собственным ключом: по индексу поля путались бы при удалении строки из середины. */
interface Row { k: number; a: string; b: string }

const RETENTION_MAX = 3650

/** Настройки: слова, подсети, срок хранения файлов. Только администратору — остальным пояснение. */
export function SettingsPage() {
  const { admin } = useCan()
  const settings = useToolboxSettings(admin)
  if (!admin) {
    return <div className="p-6"><EmptyState icon={Lock} title="Только для администратора" description="Слова, подсети и срок хранения файлов меняет администратор." /></div>
  }
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) return <div className="p-6"><ErrorState message={settings.error?.message ?? 'Не удалось загрузить настройки'} onRetry={() => settings.refetch()} /></div>
  // Форма берёт данные один раз: фоновое обновление запроса не должно затирать правки.
  return <SettingsForm initial={settings.data} />
}

function SettingsForm({ initial }: { initial: ToolboxSettings }) {
  const save = useSaveToolboxSettings()
  const seq = useRef(0)
  const mk = (a = '', b = ''): Row => ({ k: seq.current++, a, b })
  const fromWords = (s: ToolboxSettings) => s.words.map((w) => mk(w.word, w.alias))
  const fromSubnets = (s: ToolboxSettings) => s.subnets.map((n) => mk(n.cidr, n.to))
  const [words, setWords] = useState<Row[]>(() => fromWords(initial))
  const [subnets, setSubnets] = useState<Row[]>(() => fromSubnets(initial))
  const [days, setDays] = useState(String(initial.retention_days))
  const [saved, setSaved] = useState(false)

  const daysNum = Number(days)
  const daysOk = days.trim() !== '' && Number.isInteger(daysNum) && daysNum >= 0 && daysNum <= RETENTION_MAX

  // Псевдоним без слова сервер отвергает английским текстом без номера строки — ловим здесь.
  // Пустое слово возможно только после правки на месте: через «Добавить» и список слово всегда задано.
  const noWord = words.flatMap((r, i) => (r.a.trim() === '' && r.b.trim() !== '' ? [i] : []))

  function touch() { setSaved(false) }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!daysOk || noWord.length > 0 || save.isPending) return
    // Совсем пустые строки (добавили и не заполнили) отбрасываются; остальное проверяет сервер.
    const used = (r: Row) => r.a.trim() !== '' || r.b.trim() !== ''
    setSaved(false)
    save.mutate(
      {
        words: words.filter(used).map((r) => ({ word: r.a.trim(), alias: r.b.trim() })),
        subnets: subnets.filter(used).map((r) => ({ cidr: r.a.trim(), to: r.b.trim() })),
        retention_days: daysNum,
      },
      {
        // Форма показывает то, что сервер сохранил (он мог нормализовать значения), а не то, что отправили.
        onSuccess: (r) => {
          setWords(fromWords(r))
          setSubnets(fromSubnets(r))
          setDays(String(r.retention_days))
          setSaved(true)
        },
      },
    )
  }

  return (
    <form onSubmit={submit} className="h-full overflow-y-auto p-6">
      <h1 className="mb-4 text-base font-semibold text-text">{moduleTitle('toolbox')}</h1>
      <div className="max-w-3xl space-y-4">
        <Section id="words" title="Слова" about="Свои слова: названия проектов, площадок, систем. Слово ищется как часть слова, без учёта регистра — короткое слово заменится и внутри других слов. Псевдоним можно не задавать — тогда он будет вида word-NNNN.">
          <PairEditor cfg={WORDS} rows={words} setRows={setWords} mk={mk} onChange={touch} invalid={noWord} />
          {noWord.map((i) => <p key={i} role="alert" className="mt-2 text-xs text-kind-1">Слово не задано в строке {i + 1}</p>)}
        </Section>

        <Section id="subnets" title="Подсети" about="Дополнительные подсети к сетям модуля «Активы»: адреса первой подсети заменяются адресами второй, которую вы задаёте явно. Длины префиксов в паре должны совпадать.">
          <PairEditor cfg={SUBNETS} rows={subnets} setRows={setSubnets} mk={mk} onChange={touch} />
        </Section>

        <Section id="retention" title="Хранение файлов" about="Файлы задания (исходный, результат, отчёт) удаляются при ежесуточной очистке: через указанное число дней после завершения задания; 0 — при ближайшей очистке. Строка задания, находки и таблица соответствий остаются.">
          <label className="block max-w-[200px]">
            <span className="mb-1 block text-xs font-medium text-text">Срок хранения, дней</span>
            <input type="number" min={0} max={RETENTION_MAX} step={1} className={cn(FIELD, 'font-mono', !daysOk && 'border-kind-1')} value={days} onChange={(e) => { setDays(e.target.value); setSaved(false) }} aria-invalid={!daysOk} />
            <span className={cn('mt-1 block text-xs', daysOk ? 'text-text-secondary' : 'text-kind-1')}>{daysOk ? '0 — при ближайшей очистке' : `Целое число от 0 до ${RETENTION_MAX}`}</span>
          </label>
        </Section>

        {save.error && <div role="alert" className="flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{save.error.message}</div>}

        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={!daysOk || noWord.length > 0} loading={save.isPending}>Сохранить</Button>
          {saved && <span className="flex items-center gap-1 text-xs text-kind-accepted" role="status"><Check size={13} aria-hidden />Сохранено</span>}
        </div>
      </div>
    </form>
  )
}

/** Чем различаются два списка пар: подписи, подсказки и обязательность правой части. */
interface PairCfg {
  leftPh: string
  rightPh: string
  /** aria-label полей правки на месте и добавления; номер строки дописывается к первым двум. */
  edit: [string, string]
  add: [string, string]
  remove: string
  /** Правая часть обязательна (подсети) или может быть пустой (слова: псевдоним создастся сам). */
  requireRight: boolean
  /** Приглушённая подстановка вместо пустой правой части. */
  emptyRight: string
  /** Что считается пропуском при вставке списка: «пропущено <skipNote> K». */
  skipNote: string
  hint: ReactNode
}

const WORDS: PairCfg = {
  leftPh: 'слово',
  rightPh: 'псевдоним (необязательно)',
  edit: ['Слово', 'Псевдоним'],
  add: ['Новое слово', 'Псевдоним нового слова'],
  remove: 'Удалить слово',
  requireRight: false,
  emptyRight: 'word-NNNN',
  skipNote: 'без слова',
  hint: <>По одной паре на строку: <code className="font-mono">{'MSK = WRKST'}</code>. Без <code className="font-mono">=</code> — только слово, псевдоним будет вида word-NNNN.</>,
}

const SUBNETS: PairCfg = {
  leftPh: 'что: 10.1.0.0/16',
  rightPh: 'во что: 10.201.0.0/16',
  edit: ['Подсеть', 'Заменить на'],
  add: ['Новая подсеть', 'Заменить новую подсеть на'],
  remove: 'Удалить подсеть',
  requireRight: true,
  emptyRight: '—',
  skipNote: 'без второй подсети',
  hint: <>По одной паре на строку: <code className="font-mono">{'10.1.0.0/16 = 10.201.0.0/16'}</code>. Вторая подсеть обязательна: строки без неё пропускаются.</>,
}

/** Разбор вставленного списка: «левое => правое» по строке; для слов без разделителя это только слово. */
function parsePairs(text: string, requireRight: boolean) {
  const pairs: { left: string; right: string }[] = []
  let skipped = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line === '') continue
    // Разделитель — «=» (как в файле правил скрипта); «=>», «->» и «→» тоже принимаются, чтобы вставка из старых заметок не ломалась. Делим по первому.
    const m = /=>|->|→|=/.exec(line)
    const left = (m ? line.slice(0, m.index) : line).trim()
    const right = m ? line.slice(m.index + m[0].length).trim() : ''
    if (left === '' || (requireRight && right === '')) skipped++
    else pairs.push({ left, right })
  }
  return { pairs, skipped }
}

const ROW_BTN = 'rounded px-1 font-mono hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

type Editing = { k: number; field: 'a' | 'b' } | null

/** Список пар компактно + добавление по одной и списком; общий для слов и подсетей, меняется только набор подписей. */
function PairEditor({ cfg, rows, setRows, mk, onChange, invalid = [] }: {
  cfg: PairCfg
  rows: Row[]
  setRows: React.Dispatch<React.SetStateAction<Row[]>>
  mk: (a?: string, b?: string) => Row
  /** Любая правка: сбрасывает «Сохранено». */
  onChange: () => void
  /** Номера строк (с нуля), у которых левая часть не заполнена. */
  invalid?: number[]
}) {
  // Какая строка правится на месте (и какое поле в фокусе); остальные показываются компактным списком.
  const [editing, setEditing] = useState<Editing>(null)

  /**
   * Добавляет пары; левая часть, уже стоящая в списке (без учёта регистра), не дублируется,
   * а получает новую правую — так сервер не отвергнет повтор, а вставка списка работает как обновление.
   */
  function addPairs(pairs: { left: string; right: string }[]) {
    const next = [...rows]
    let added = 0
    let updated = 0
    for (const p of pairs) {
      const at = next.findIndex((r) => r.a.trim().toLowerCase() === p.left.toLowerCase())
      if (at >= 0) {
        next[at] = { ...next[at], b: p.right }
        updated++
      } else {
        next.push(mk(p.left, p.right))
        added++
      }
    }
    onChange()
    setRows(next)
    return { added, updated }
  }
  function commit(k: number, a: string, b: string) {
    onChange()
    setEditing(null)
    // Строка, из которой стёрли всё, исчезает: пустышку в компактном списке не показать, а сервер ей не нужен.
    setRows((rs) => (a.trim() === '' && b.trim() === '' ? rs.filter((r) => r.k !== k) : rs.map((r) => (r.k === k ? { ...r, a, b } : r))))
  }
  function remove(k: number) {
    onChange()
    setEditing(null)
    setRows((rs) => rs.filter((r) => r.k !== k))
  }
  return (
    <>
      {rows.length === 0 ? (
        <p className="mb-3 text-xs text-text-secondary">Список пуст.</p>
      ) : (
        // Длинный список (вставили сотню строк) прокручивается внутри блока, а не растягивает страницу.
        <ul className="mb-3 max-h-72 overflow-y-auto">
          {rows.map((r, i) => (
            <li key={r.k} className="flex min-h-7 items-center gap-2 rounded px-1 text-xs hover:bg-row-hover/50">
              {editing?.k === r.k ? (
                <PairEditRow cfg={cfg} row={r} index={i} focus={editing.field} invalid={invalid.includes(i)} onCommit={(a, b) => commit(r.k, a, b)} onCancel={() => setEditing(null)} />
              ) : (
                <>
                  <button type="button" onClick={() => setEditing({ k: r.k, field: 'a' })} title="Изменить" className={cn(ROW_BTN, 'text-text', invalid.includes(i) && 'text-kind-1')}>{r.a || '—'}</button>
                  <span className="text-text-secondary" aria-hidden>→</span>
                  <button type="button" onClick={() => setEditing({ k: r.k, field: 'b' })} title="Изменить" className={cn(ROW_BTN, r.b ? 'text-text' : 'text-text-secondary')}>{r.b || cfg.emptyRight}</button>
                  <button type="button" onClick={() => remove(r.k)} aria-label={`${cfg.remove} ${i + 1}`} title="Удалить" className="ml-auto rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"><X size={12} aria-hidden /></button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      <PairAdd cfg={cfg} onAdd={addPairs} />
    </>
  )
}

/** Правка строки на месте: Enter и уход фокуса принимают, Esc отменяет. Пока правится, значения живут здесь, а не в списке. */
function PairEditRow({ cfg, row, index, focus, invalid, onCommit, onCancel }: {
  cfg: PairCfg
  row: Row
  index: number
  focus: 'a' | 'b'
  invalid: boolean
  onCommit: (a: string, b: string) => void
  onCancel: () => void
}) {
  const [a, setA] = useState(row.a)
  const [b, setB] = useState(row.b)
  const aRef = useRef<HTMLInputElement>(null)
  const bRef = useRef<HTMLInputElement>(null)
  // После Enter/Esc строка исчезает вместе с фокусом и может вызвать blur ещё раз — второй вызов не нужен.
  const done = useRef(false)
  useEffect(() => { (focus === 'b' ? bRef : aRef).current?.focus() }, [focus])

  function finish(commit: boolean) {
    if (done.current) return
    done.current = true
    if (commit) onCommit(a, b)
    else onCancel()
  }
  function onKeyDown(e: React.KeyboardEvent) {
    // Enter в форме настроек отправил бы всю форму.
    if (e.key === 'Enter') { e.preventDefault(); finish(true) }
    else if (e.key === 'Escape') { e.preventDefault(); finish(false) }
  }
  // Фокус между двумя полями одной строки правку не завершает.
  function onBlur(e: React.FocusEvent) {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) finish(true)
  }
  const field = cn(FIELD, 'py-0.5 font-mono text-xs')
  return (
    <div className="flex flex-1 items-center gap-2" onKeyDown={onKeyDown} onBlur={onBlur}>
      <input ref={aRef} className={cn(field, invalid && 'border-kind-1')} aria-invalid={invalid} value={a} onChange={(e) => setA(e.target.value)} placeholder={cfg.leftPh} aria-label={`${cfg.edit[0]} ${index + 1}`} spellCheck={false} />
      <span className="text-text-secondary" aria-hidden>→</span>
      <input ref={bRef} className={field} value={b} onChange={(e) => setB(e.target.value)} placeholder={cfg.rightPh} aria-label={`${cfg.edit[1]} ${index + 1}`} spellCheck={false} />
    </div>
  )
}

/** Добавление пар: по одной и списком «левое => правое». Попадает в форму, сохраняется общей кнопкой. */
function PairAdd({ cfg, onAdd }: { cfg: PairCfg; onAdd: (pairs: { left: string; right: string }[]) => { added: number; updated: number } }) {
  const [left, setLeft] = useState('')
  const [right, setRight] = useState('')
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [status, setStatus] = useState('')
  const leftRef = useRef<HTMLInputElement>(null)
  const rightRef = useRef<HTMLInputElement>(null)

  const canAdd = left.trim() !== '' && (!cfg.requireRight || right.trim() !== '')
  function addOne() {
    if (!canAdd) return
    onAdd([{ left: left.trim(), right: right.trim() }])
    setLeft('')
    setRight('')
    leftRef.current?.focus()
  }
  function addList() {
    const { pairs, skipped } = parsePairs(text, cfg.requireRight)
    if (pairs.length === 0) {
      setStatus(skipped > 0 ? `Пропущено ${cfg.skipNote}: ${skipped}` : 'В списке нет строк')
      return
    }
    const { added, updated } = onAdd(pairs)
    setStatus(`Добавлено ${added}, обновлено ${updated}` + (skipped > 0 ? `, пропущено ${cfg.skipNote} ${skipped}` : ''))
    setText('')
  }
  // Enter в полях добавления не должен отправлять всю форму настроек.
  const enter = (fn: () => void) => (e: React.KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); fn() } }
  const field = cn(FIELD, 'py-1 font-mono text-xs')
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <input ref={leftRef} className={field} value={left} onChange={(e) => setLeft(e.target.value)} onKeyDown={enter(() => rightRef.current?.focus())} placeholder={cfg.leftPh} aria-label={cfg.add[0]} spellCheck={false} />
        <span className="text-text-secondary" aria-hidden>→</span>
        <input ref={rightRef} className={field} value={right} onChange={(e) => setRight(e.target.value)} onKeyDown={enter(addOne)} placeholder={cfg.rightPh} aria-label={cfg.add[1]} spellCheck={false} />
        <Button type="button" onClick={addOne} disabled={!canAdd} className="shrink-0"><Plus size={14} aria-hidden />Добавить</Button>
      </div>

      <div>
        <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open} className="flex items-center gap-1 rounded text-xs font-medium text-text hover:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          {open ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}Вставить списком
        </button>
        {open && (
          <div className="mt-2 space-y-2">
            <textarea className={cn(FIELD, 'min-h-24 font-mono text-xs')} value={text} onChange={(e) => { setText(e.target.value); setStatus('') }} aria-label="Список пар" spellCheck={false} />
            <p className="text-xs text-text-secondary">{cfg.hint}</p>
            <div className="flex items-center gap-3">
              <Button type="button" onClick={addList} disabled={text.trim() === ''}>Добавить из списка</Button>
              {status && <span role="status" className="text-xs text-text-secondary">{status}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
