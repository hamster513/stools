import { useState } from 'react'
import type { ChangeKind } from '@/modules/ksc/api/types'

const LIMIT = 400

interface SettingSide {
  value?: unknown
  locked?: boolean | null
  removed?: unknown[]
  added?: unknown[]
}

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null
}

/** Сжатый JSON; длиннее ~400 знаков — обрезан с переключателем «показать всё». */
function JsonBlock({ value }: { value: unknown }) {
  const [full, setFull] = useState(false)
  const text = JSON.stringify(value, null, 1) ?? ''
  const long = text.length > LIMIT
  return (
    <div>
      <pre className="max-h-96 overflow-auto rounded border border-grid bg-app-bg px-2 py-1 font-mono text-[11px] whitespace-pre-wrap break-all text-text">
        {long && !full ? `${text.slice(0, LIMIT)}…` : text}
      </pre>
      {long && (
        <button type="button" onClick={() => setFull(!full)} className="mt-0.5 text-[11px] text-primary hover:underline">{full ? 'свернуть' : 'показать всё'}</button>
      )}
    </div>
  )
}

/** Одно значение: объект или список — блоком JSON, остальное строкой. */
function Value({ v }: { v: unknown }) {
  if (isObject(v)) return <JsonBlock value={v} />
  if (v === null || v === undefined || v === '') return <span className="text-text-secondary">пусто</span>
  if (typeof v === 'boolean') return <span className="font-mono text-text">{v ? 'да' : 'нет'}</span>
  return <span className="font-mono break-all text-text">{String(v)}</span>
}

function Items({ title, items }: { title: string; items: unknown[] }) {
  if (items.length === 0) return null
  return (
    <div>
      <div className="text-[11px] text-text-secondary">{title}</div>
      <ul className="ml-4 list-disc">
        {items.map((x, i) => <li key={i}><Value v={x} /></li>)}
      </ul>
    </div>
  )
}

/** «было → стало»: отсутствующая сторона — «нет». */
function BeforeAfter({ before, after, hasBefore, hasAfter }: { before: unknown; after: unknown; hasBefore: boolean; hasAfter: boolean }) {
  return (
    <div className="flex flex-wrap items-start gap-1.5">
      {hasBefore ? <Value v={before} /> : <span className="text-text-secondary">нет</span>}
      <span className="text-text-secondary">→</span>
      {hasAfter ? <Value v={after} /> : <span className="text-text-secondary">нет</span>}
    </div>
  )
}

/** Изменение настройки: значение «было → стало», смена замка, убранные и добавленные элементы списка. */
function SettingValue({ before, after }: { before: SettingSide | null; after: SettingSide | null }) {
  const hasB = !!before && 'value' in before
  const hasA = !!after && 'value' in after
  let lock: string | null = null
  if (before && after && 'locked' in before && 'locked' in after && before.locked !== after.locked) {
    lock = after.locked ? 'замок поставлен' : before.locked ? 'замок снят' : 'признак замка изменился'
  } else if (!after && before?.locked) lock = 'была под замком'
  else if (!before && after?.locked) lock = 'под замком'
  return (
    <div className="flex flex-col gap-1">
      {(hasB || hasA) && <BeforeAfter before={before?.value} after={after?.value} hasBefore={hasB} hasAfter={hasA} />}
      {lock && <span className="text-risk-medium">{lock}</span>}
      <Items title="убрано" items={before?.removed ?? []} />
      <Items title="добавлено" items={after?.added ?? []} />
    </div>
  )
}

/** Значение записи журнала изменений по виду: у настройки — человеческий вид, у остальных — значения или JSON. */
export function ChangeValue({ kind, before, after }: { kind: ChangeKind; before: unknown; after: unknown }) {
  if (kind === 'setting') {
    return <SettingValue before={isObject(before) ? (before as SettingSide) : null} after={isObject(after) ? (after as SettingSide) : null} />
  }
  if (before == null && after == null) return <span className="text-text-secondary">—</span>
  if (!isObject(before) && !isObject(after) && before != null && after != null) {
    return <BeforeAfter before={before} after={after} hasBefore hasAfter />
  }
  return (
    <div className="flex flex-col gap-1">
      {before != null && <div><div className="text-[11px] text-text-secondary">было</div><Value v={before} /></div>}
      {after != null && <div><div className="text-[11px] text-text-secondary">стало</div><Value v={after} /></div>}
    </div>
  )
}
