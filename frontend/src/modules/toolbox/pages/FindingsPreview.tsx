import { useEffect, useRef, useState, type FormEvent } from 'react'
import { AlertTriangle, ChevronDown, ChevronLeft, ChevronRight, Plus, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { ExportButton } from '@/platform/filters/ExportButton'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { FINDINGS_PAGE_SIZE, findingsExportUrl, useApply, useFindings, useUpdateFindings } from '../api/queries'
import { KIND_LABELS, type Finding, type FindingsPatch } from '../api/types'

const CELL = 'px-2 py-1.5 align-top'
const EMPTY: FindingsPatch = { checks: {}, aliases: {}, words: [] }

const CHECK: ColumnDef = { key: 'check', label: 'Заменять', width: 32, resizable: false }
const VALUE: ColumnDef[] = [
  { key: 'value', label: 'Значение', width: 280 },
  { key: 'alias', label: 'Псевдоним', width: 256 },
  { key: 'count', label: 'Вхождений', width: 96, align: 'right' },
]
const CONTEXT: ColumnDef = { key: 'context', label: 'Контекст', width: 320 }
const FILE: ColumnDef = { key: 'file', label: 'Файл', width: 200, flex: true }
// Контекст показывается по переключателю — два набора колонок, ширины у них общие (ключ хранения один).
const COLUMNS: ColumnDef[] = [CHECK, ...VALUE, FILE]
const COLUMNS_WITH_CONTEXT: ColumnDef[] = [CHECK, ...VALUE, CONTEXT, FILE]

/** Буфер без отправленного: правки, сделанные пока шёл PATCH, остаются несохранёнными. */
function withoutSent(b: FindingsPatch, sent: FindingsPatch): FindingsPatch {
  const same = <T,>(rec: Record<number, T>, done: Record<number, T>) =>
    Object.fromEntries(Object.entries(rec).filter(([k, v]) => !(k in done) || done[Number(k)] !== v)) as Record<number, T>
  return { checks: same(b.checks, sent.checks), aliases: same(b.aliases, sent.aliases), words: b.words.filter((w) => !sent.words.includes(w)) }
}

function Banner({ children }: { children: React.ReactNode }) {
  return <div role="alert" className="flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden /><div className="flex-1">{children}</div></div>
}

/**
 * Предпросмотр находок: группы по категориям, галочки, псевдонимы, свои слова. Правки копятся здесь
 * и уходят одним PATCH по «Сохранить» — так сервер проверяет псевдонимы разом, а «Очистить» не
 * запускается поверх несохранённого. `readOnly` — аудитор или задание, которое уже не правится.
 */
export function FindingsPreview({ id, readOnly, showContexts }: { id: number; readOnly: boolean; showContexts: boolean }) {
  // undefined — ещё не выбирали: открыта первая группа; null — все свёрнуты.
  const [openKind, setOpenKind] = useState<string | null | undefined>(undefined)
  const [search, setSearch] = useState('')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [buffer, setBuffer] = useState<FindingsPatch>(EMPTY)
  const [word, setWord] = useState('')
  const [aliasError, setAliasError] = useState<{ id: number; value: string; message: string } | null>(null)
  // Значения строк с правленым псевдонимом: строки может не быть на экране, а отказ назвать нужно.
  const aliasValues = useRef<Record<number, string>>({})
  const [added, setAdded] = useState<number | null>(null)
  const cols = useColumnWidths('toolbox-findings-columns', showContexts ? COLUMNS_WITH_CONTEXT : COLUMNS)

  // Поиск уходит на сервер не на каждую букву.
  useEffect(() => {
    const t = setTimeout(() => { setQ(search.trim()); setOffset(0) }, 300)
    return () => clearTimeout(t)
  }, [search])

  const summary = useFindings(id, { limit: 1 })
  const groups = summary.data?.groups ?? []
  const current = openKind === undefined ? groups[0]?.kind : openKind
  const page = useFindings(id, { kind: current ?? undefined, q, offset }, !!current)
  const update = useUpdateFindings(id)
  const apply = useApply(id)

  const dirty = Object.keys(buffer.checks).length + Object.keys(buffer.aliases).length + buffer.words.length
  // placeholderData держит прошлую страницу: строки другой группы не показываются под этой.
  const rows = (page.data?.items ?? []).filter((f) => f.kind === current)
  const isChecked = (f: Finding) => buffer.checks[f.id] ?? f.checked

  function toggle(kind: string) {
    setOpenKind(current === kind ? null : kind)
    setOffset(0)
  }
  function setCheck(f: Finding, value: boolean) {
    setBuffer((b) => {
      const checks = { ...b.checks }
      if (value === f.checked) delete checks[f.id]
      else checks[f.id] = value
      return { ...b, checks }
    })
  }
  function setAlias(f: Finding, value: string) {
    // Поправили псевдоним, на который пришёл отказ, — отказ больше не про него и не всплывает баннером.
    if (aliasError?.id === f.id) { setAliasError(null); update.reset() }
    aliasValues.current[f.id] = f.value
    setBuffer((b) => {
      const aliases = { ...b.aliases }
      if (value === f.alias) delete aliases[f.id]
      else aliases[f.id] = value
      return { ...b, aliases }
    })
  }
  function addWord(e: FormEvent) {
    e.preventDefault()
    const w = word.trim()
    if (w && !buffer.words.includes(w) && buffer.words.length < 100) setBuffer((b) => ({ ...b, words: [...b.words, w] }))
    setWord('')
  }
  function save() {
    setAliasError(null)
    setAdded(null)
    const sent = buffer
    update.mutate(sent, {
      onSuccess: (r) => { setBuffer((b) => withoutSent(b, sent)); setAdded(sent.words.length ? r.added : null) },
      onError: (err) => {
        // Сервер не говорит, к какой строке отказ; если правился один псевдоним — он и есть.
        const ids = Object.keys(sent.aliases).map(Number)
        if (err.status === 422 && ids.length === 1) setAliasError({ id: ids[0], value: aliasValues.current[ids[0]] ?? `#${ids[0]}`, message: err.message })
      },
    })
  }

  const allOn = rows.length > 0 && rows.every(isChecked)
  const someOn = rows.some(isChecked)
  const total = page.data?.total ?? 0
  // Баннер — всегда: строки с отказом может не быть на экране (другая группа, страница, поиск).
  const bannerError = aliasError ? `Псевдоним для ${aliasError.value}: ${aliasError.message}` : update.error?.message ?? null

  if (summary.isLoading) return <div className="flex justify-center py-10"><Spinner /></div>
  if (summary.isError) return <Banner>{summary.error.message}</Banner>

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <label className="relative w-72">
          <Search size={14} className="pointer-events-none absolute top-2 left-2.5 text-text-secondary" aria-hidden />
          <input className={cn(FIELD, 'pl-8')} value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Поиск по значению" aria-label="Поиск по значению" />
        </label>
        {/* Выгрузка — с настоящими значениями, она аналитику (как и контексты); группы выгружаются все. */}
        {showContexts && <ExportButton href={(fmt) => findingsExportUrl(id, q, fmt)} total={groups.reduce((n, g) => n + g.total, 0)} />}
        {!readOnly && <WordsForm disabled={update.isPending} word={word} setWord={setWord} onSubmit={addWord} words={buffer.words} remove={(w) => setBuffer((b) => ({ ...b, words: b.words.filter((x) => x !== w) }))} />}
      </div>

      {groups.length === 0 ? (
        <div className="rounded border border-dashed border-grid px-6 py-10 text-center text-sm text-text-secondary">
          Ничего не найдено: в тексте нет адресов, имён, учётных записей и секретов, которые знают детекторы.{!readOnly && ' Можно добавить свои слова.'}
        </div>
      ) : (
      <div className="rounded border border-grid">
        {groups.map((g) => {
          const open = g.kind === current
          return (
            <div key={g.kind} className="border-t border-grid first:border-t-0">
              <button type="button" onClick={() => toggle(g.kind)} aria-expanded={open} className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring">
                {open ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
                <span className="font-medium">{KIND_LABELS[g.kind] ?? g.kind}</span>
                <span className="font-mono text-xs tabular-nums text-text-secondary" title="включено / всего">{g.checked.toLocaleString('ru-RU')} / {g.total.toLocaleString('ru-RU')}</span>
                {g.kind === 'secret' && <span className="text-xs text-text-secondary">· метки, в таблицу соответствий не пишутся</span>}
              </button>
              {open && (
                <div className="border-t border-grid">
                  {page.isError ? <div className="p-3"><Banner>{page.error.message}</Banner></div> : !page.data ? <div className="flex justify-center py-6"><Spinner /></div> : rows.length === 0 ? (
                    <div className="px-3 py-4 text-xs text-text-secondary">{q ? 'Под поиск ничего не попало.' : 'Пусто.'}</div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs" style={cols.tableStyle}>
                        <ColGroup cols={cols} />
                        <thead className="bg-surface text-[11px] tracking-wide text-text-secondary uppercase">
                          <tr>
                            <ResizableHeader cols={cols} className={CELL} content={{
                              check: <input type="checkbox" checked={allOn} disabled={readOnly} aria-label="Все строки на странице" title="Все строки на странице"
                                ref={(el) => { if (el) el.indeterminate = someOn && !allOn }}
                                onChange={(e) => { for (const f of rows) setCheck(f, e.target.checked) }} />,
                            }} />
                          </tr>
                        </thead>
                        <tbody>
                          {rows.map((f) => {
                            const aliasValue = buffer.aliases[f.id] ?? f.alias
                            const editable = !readOnly && f.kind !== 'secret' && !f.stored
                            const err = aliasError?.id === f.id ? aliasError.message : null
                            return (
                              <tr key={f.id} className={cn('border-t border-grid', !isChecked(f) && 'text-text-secondary')}>
                                <td className={CELL}><input type="checkbox" checked={isChecked(f)} disabled={readOnly} onChange={(e) => setCheck(f, e.target.checked)} aria-label={`Заменять ${f.value}`} /></td>
                                <td className={cn(CELL, 'font-mono break-all text-text')}>
                                  {f.value}
                                  {f.auto && <span className="ml-1.5 rounded border border-border px-1 font-sans text-[10px] text-text-secondary" title="Найдено авто-поиском, не по словарю: проверьте, что это значение">авто</span>}
                                </td>
                                <td className={CELL}>
                                  {editable ? (
                                    <>
                                      <input className={cn(FIELD, 'py-1 font-mono text-xs', aliasValue !== f.alias && 'border-primary', err && 'border-kind-1')} value={aliasValue} onChange={(e) => setAlias(f, e.target.value)} aria-label={`Псевдоним для ${f.value}`} aria-invalid={err ? true : undefined} />
                                      {err && <div role="alert" className="mt-1 text-[11px] text-kind-1">{err}</div>}
                                    </>
                                  ) : (
                                    <span className="font-mono text-text" title={f.stored ? 'Уже в таблице соответствий — сменить можно только через «забыть»' : undefined}>{f.alias}</span>
                                  )}
                                </td>
                                <td className={cn(CELL, 'text-right font-mono tabular-nums')}>{f.count.toLocaleString('ru-RU')}</td>
                                {showContexts && <td className={cn(CELL, 'truncate font-mono text-text-secondary')} title={f.contexts.join('\n')}>{f.contexts[0] ?? ''}</td>}
                                <td className={cn(CELL, 'truncate text-text-secondary')} title={f.first_file}>{f.first_file}</td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                  {total > FINDINGS_PAGE_SIZE && (
                    <div className="flex items-center gap-2 border-t border-grid px-3 py-2">
                      <Button variant="ghost" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - FINDINGS_PAGE_SIZE))}><ChevronLeft size={14} aria-hidden />Назад</Button>
                      <Button variant="ghost" disabled={offset + FINDINGS_PAGE_SIZE >= total} onClick={() => setOffset((o) => o + FINDINGS_PAGE_SIZE)}>Вперёд<ChevronRight size={14} aria-hidden /></Button>
                      <span className="font-mono text-xs tabular-nums text-text-secondary">{offset + 1}–{Math.min(offset + FINDINGS_PAGE_SIZE, total)} из {total.toLocaleString('ru-RU')}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
      )}

      {bannerError && <Banner>{bannerError}</Banner>}
      {apply.error && <Banner>{apply.error.message}</Banner>}
      {added !== null && <p className="text-xs text-text-secondary">Новых находок по словам: {added}.</p>}

      {!readOnly && (
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={save} disabled={dirty === 0} loading={update.isPending}>Сохранить{dirty > 0 && <span className="font-mono tabular-nums">· {dirty}</span>}</Button>
          {dirty > 0 && <Button variant="ghost" onClick={() => { setBuffer(EMPTY); setAliasError(null); update.reset() }}>Сбросить правки</Button>}
          <Button variant="primary" onClick={() => apply.mutate()} disabled={dirty > 0} loading={apply.isPending} title={dirty > 0 ? 'Сначала сохраните правки' : undefined}>Очистить</Button>
          <span className="text-xs text-text-secondary">{dirty > 0 ? 'Есть несохранённые правки — «Очистить» станет доступна после сохранения.' : 'Заменяются только отмеченные значения; новые псевдонимы попадут в таблицу соответствий.'}</span>
        </div>
      )}
    </div>
  )
}

function WordsForm({ disabled, word, setWord, onSubmit, words, remove }: {
  /** Пока идёт сохранение: слова пересканируют весь вход, новое слово ушло бы мимо этого PATCH. */
  disabled: boolean
  word: string
  setWord: (w: string) => void
  onSubmit: (e: FormEvent) => void
  words: string[]
  remove: (w: string) => void
}) {
  return (
    <form onSubmit={onSubmit} className="flex flex-wrap items-center gap-2">
      <input className={cn(FIELD, 'w-56')} disabled={disabled} value={word} onChange={(e) => setWord(e.target.value)} placeholder="Своё слово: фамилия, проект…" aria-label="Добавить слово" />
      <Button type="submit" disabled={disabled || word.trim() === ''}><Plus size={14} aria-hidden />Добавить слово</Button>
      {words.map((w) => (
        <button key={w} type="button" disabled={disabled} onClick={() => remove(w)} title="Убрать" className="flex items-center gap-1 rounded border border-primary/60 px-1.5 py-0.5 text-[11px] text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          {w} <X size={11} className="text-text-secondary" aria-hidden />
        </button>
      ))}
    </form>
  )
}
