import { useMemo, useState } from 'react'
import { ArrowLeft, ChevronLeft, ChevronRight } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCloneCompare } from '@/modules/siem/api/queries'
import type { CloneCompare, CloneEntry, CloneSide, DiffLine, SignatureSplit } from '@/modules/siem/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

//: Строк контекста вокруг расхождения в режиме «только расхождения».
const CONTEXT = 2

interface CompareViewProps {
  snapshotId: number
  ruleA: string
  ruleB: string
  pairs: CloneEntry[]
}

export function CompareView({ snapshotId, ruleA, ruleB, pairs }: CompareViewProps) {
  const compare = useCloneCompare(snapshotId, ruleA, ruleB)
  const [onlyDiff, setOnlyDiff] = useState(false)

  //: Соседи по списку пар — чтобы пройти все клоны подряд, не возвращаясь.
  const index = pairs.findIndex(
    (p) => (p.rule_a === ruleA && p.rule_b === ruleB) || (p.rule_a === ruleB && p.rule_b === ruleA),
  )
  const prev = index > 0 ? pairs[index - 1] : null
  const next = index >= 0 && index < pairs.length - 1 ? pairs[index + 1] : null
  const pairHref = (p: CloneEntry) =>
    `/siem/snapshots/${snapshotId}/clones?a=${encodeURIComponent(p.rule_a)}&b=${encodeURIComponent(p.rule_b)}`

  if (compare.isLoading) return <FullPageSpinner />
  if (compare.isError || !compare.data) {
    const message =
      compare.error instanceof ApiRequestError ? compare.error.message : 'Не удалось загрузить сравнение'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => compare.refetch()} />
      </div>
    )
  }
  const data = compare.data

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Link
            to={`/siem/snapshots/${snapshotId}/clones`}
            className="inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text"
          >
            <ArrowLeft size={14} aria-hidden /> все пары
          </Link>
          <h1 className="text-base font-semibold text-text">Сравнение клонов</h1>
          {data.similarity !== null && (
            <span className="font-mono text-xs tabular-nums text-text-secondary">
              похожесть {Math.round(data.similarity * 100)}%
            </span>
          )}
          <span className="font-mono text-xs tabular-nums text-text-secondary">
            расхождений в теле: {data.changed_lines}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-text-secondary">
            <input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} />
            только расхождения
          </label>
          <PairNav label="предыдущая пара" icon={ChevronLeft} to={prev ? pairHref(prev) : null} />
          <PairNav label="следующая пара" icon={ChevronRight} to={next ? pairHref(next) : null} />
        </div>
      </div>

      <div className="mb-4 grid gap-3 md:grid-cols-2">
        <SideHeader side={data.a} letter="A" snapshotId={snapshotId} />
        <SideHeader side={data.b} letter="B" snapshotId={snapshotId} />
      </div>

      <SignatureBlock signature={data.signature} />

      <BodyDiff data={data} onlyDiff={onlyDiff} />
    </div>
  )
}

function PairNav({ label, icon: Icon, to }: { label: string; icon: typeof ChevronLeft; to: string | null }) {
  const cls = 'inline-flex h-7 w-7 items-center justify-center rounded border border-grid'
  if (!to) {
    return (
      <span className={cn(cls, 'cursor-not-allowed text-text-secondary opacity-40')} aria-disabled="true" title={label}>
        <Icon size={14} aria-hidden />
      </span>
    )
  }
  return (
    <Link to={to} className={cn(cls, 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-label={label} title={label}>
      <Icon size={14} aria-hidden />
    </Link>
  )
}

function SideHeader({ side, letter, snapshotId }: { side: CloneSide; letter: 'A' | 'B'; snapshotId: number }) {
  return (
    <div className="rounded border border-grid bg-surface px-3 py-2">
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] text-text-secondary">{letter}</span>
        <span className="truncate font-mono text-sm text-text" title={side.name}>{side.name}</span>
      </div>
      <div className="mt-0.5 flex items-center justify-between gap-2 text-xs text-text-secondary">
        <span className="truncate">{side.title ?? 'без заголовка'}</span>
        <Link
          to={`/siem/snapshots/${snapshotId}/rules?q=${encodeURIComponent(side.name)}`}
          className="shrink-0 text-primary hover:text-text"
        >
          в инвентаре →
        </Link>
      </div>
    </div>
  )
}

const SIGNATURE_ROWS: { key: keyof CloneCompare['signature']; label: string }[] = [
  { key: 'msgids', label: 'msgid' },
  { key: 'fields', label: 'поля' },
  { key: 'filters', label: 'фильтры' },
]

/** Расхождения сигнатуры: то, по чему пара и признана клонами. */
function SignatureBlock({ signature }: { signature: CloneCompare['signature'] }) {
  const same = SIGNATURE_ROWS.every(({ key }) => signature[key].only_a.length === 0 && signature[key].only_b.length === 0)
  return (
    <section className="mb-4 rounded border border-grid bg-surface p-3">
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-xs font-semibold tracking-wide text-text-secondary uppercase">Сигнатура</h2>
        {same && <span className="text-xs text-text-secondary">совпадает полностью — разница только в теле</span>}
      </div>
      <div className="grid gap-x-4 gap-y-1.5 text-xs md:grid-cols-[auto_1fr_1fr]">
        <div className="hidden md:block" />
        <div className="hidden text-[11px] text-text-secondary md:block">только в A</div>
        <div className="hidden text-[11px] text-text-secondary md:block">только в B</div>
        {SIGNATURE_ROWS.map(({ key, label }) => (
          <SignatureRow key={key} label={label} split={signature[key]} />
        ))}
      </div>
    </section>
  )
}

function SignatureRow({ label, split }: { label: string; split: SignatureSplit }) {
  return (
    <>
      <div className="text-text-secondary">
        {label}
        <span className="ml-1.5 font-mono text-[11px]" title="общих">{split.common.length} общ.</span>
      </div>
      <Chips items={split.only_a} empty="—" />
      <Chips items={split.only_b} empty="—" />
    </>
  )
}

function Chips({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <div className="text-text-secondary">{empty}</div>
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((v) => (
        <span key={v} className="rounded border border-kind-1/60 bg-kind-1/10 px-1.5 py-0.5 font-mono text-text">
          {v}
        </span>
      ))}
    </div>
  )
}

const LINE_BG: Record<DiffLine['kind'], string> = {
  equal: '',
  replace: 'bg-kind-1/15',
  insert: 'bg-kind-3/15',
  delete: 'bg-kind-3/15',
}

type Row = { line: DiffLine; na: number | null; nb: number | null } | { gap: number }

/** Тела построчно, бок о бок. Номера строк считаются по каждой стороне. */
function BodyDiff({ data, onlyDiff }: { data: CloneCompare; onlyDiff: boolean }) {
  const rows = useMemo<Row[]>(() => {
    let na = 0
    let nb = 0
    const numbered = data.lines.map((line) => {
      if (line.a !== null) na += 1
      if (line.b !== null) nb += 1
      return { line, na: line.a !== null ? na : null, nb: line.b !== null ? nb : null }
    })
    if (!onlyDiff) return numbered
    const keep = new Set<number>()
    numbered.forEach((r, i) => {
      if (r.line.kind === 'equal') return
      for (let k = Math.max(0, i - CONTEXT); k <= Math.min(numbered.length - 1, i + CONTEXT); k++) keep.add(k)
    })
    const out: Row[] = []
    let hidden = 0
    numbered.forEach((r, i) => {
      if (keep.has(i)) {
        if (hidden > 0) out.push({ gap: hidden })
        hidden = 0
        out.push(r)
      } else {
        hidden += 1
      }
    })
    if (hidden > 0) out.push({ gap: hidden })
    return out
  }, [data.lines, onlyDiff])

  if (data.a.body === null && data.b.body === null) {
    return <p className="text-xs text-text-secondary">Тела обоих правил не разобраны — сравнивать нечего.</p>
  }

  return (
    <div className="overflow-x-auto rounded border border-grid bg-app-bg">
      <table className="w-full table-fixed font-mono text-xs">
        <colgroup>
          <col className="w-10" />
          <col />
          <col className="w-10" />
          <col />
        </colgroup>
        <tbody>
          {rows.map((r, i) =>
            'gap' in r ? (
              <tr key={`gap-${i}`} className="border-y border-grid text-center text-[11px] text-text-secondary">
                <td colSpan={4} className="py-0.5">… {r.gap} одинаковых строк скрыто …</td>
              </tr>
            ) : (
              <tr key={i} className={cn(LINE_BG[r.line.kind], r.line.kind === 'equal' && 'text-text-secondary')}>
                <td className="select-none px-1.5 text-right text-[11px] text-text-secondary/70">{r.na ?? ''}</td>
                <td className="border-r border-grid px-2 whitespace-pre-wrap">{r.line.a ?? ''}</td>
                <td className="select-none px-1.5 text-right text-[11px] text-text-secondary/70">{r.nb ?? ''}</td>
                <td className="px-2 whitespace-pre-wrap">{r.line.b ?? ''}</td>
              </tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  )
}
