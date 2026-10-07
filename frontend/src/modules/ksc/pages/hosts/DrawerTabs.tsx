import type { KeyboardEvent } from 'react'
import { cn } from '@/lib/cn'
import type { TabDef } from '../policies/TabBar'

/**
 * Вкладки боковой панели: текущая — состояние родителя, адрес не трогается (в отличие от `TabBar`).
 * Стрелки ←/→, Home и End переключают вкладку и переводят на неё фокус; фокус по Tab попадает только на текущую.
 */
export function DrawerTabs({ tabs, current, onSelect, label }: { tabs: TabDef[]; current: string; onSelect: (key: string) => void; label: string }) {
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const i = tabs.findIndex((t) => t.key === current)
    let next: number
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = tabs.length - 1
    else return
    e.preventDefault()
    onSelect(tabs[next].key)
    e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus()
  }
  return (
    <div role="tablist" aria-label={label} onKeyDown={onKeyDown} className="flex shrink-0 gap-1 overflow-x-auto border-b border-grid px-4">
      {tabs.map((t) => (
        <button
          key={t.key}
          type="button"
          role="tab"
          aria-selected={t.key === current}
          tabIndex={t.key === current ? 0 : -1}
          onClick={() => onSelect(t.key)}
          className={cn(
            '-mb-px shrink-0 border-b-2 px-3 py-2 text-xs whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
            t.key === current ? 'border-primary font-medium text-text' : 'border-transparent text-text-secondary hover:text-text',
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}
