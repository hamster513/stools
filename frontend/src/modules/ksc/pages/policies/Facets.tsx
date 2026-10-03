import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

/** Строка фасета боковой панели фильтров, как на странице хостов; без `count` — переключатель без счётчика; строка вместо числа — для «—». */
export function FacetRow({ active, count, onClick, children }: { active: boolean; count?: number | string; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} className={cn('flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {count !== undefined && <span className="font-mono text-[11px] tabular-nums text-text-secondary">{count}</span>}
    </button>
  )
}

export function FacetSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="border-b border-grid px-2 py-3">
      <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  )
}

/** Боковая панель фильтров списка: счётчик сверху, секции фасетов ниже. */
export function FacetPanel({ total, noun, children }: { total: number; noun: string; children: ReactNode }) {
  return (
    <div className="flex h-full w-64 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
      <div className="border-b border-grid px-4 py-3 text-xs text-text-secondary">{noun} <span className="font-mono tabular-nums text-text">{total}</span></div>
      {children}
    </div>
  )
}
