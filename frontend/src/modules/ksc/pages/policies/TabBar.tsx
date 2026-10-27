import { useRouter, useSearchParams } from '@/lib/router'
import { cn } from '@/lib/cn'
import type { TabDef } from '@/platform/tabs/DrawerTabs'

export type { TabDef }

/** Ряд вкладок страницы: вкладка — параметр `?tab=`, остальные параметры адреса сохраняются. */
export function TabBar({ tabs, current, label }: { tabs: TabDef[]; current: string; label: string }) {
  const { path, navigate } = useRouter()
  const params = useSearchParams()
  function select(key: string) {
    const next = new URLSearchParams(params)
    next.set('tab', key)
    navigate(`${path}?${next.toString()}`)
  }
  return (
    <div role="tablist" aria-label={label} className="flex gap-1">
      {tabs.map((t) => (
        <button
          key={t.key}
          type="button"
          role="tab"
          aria-selected={t.key === current}
          onClick={() => select(t.key)}
          className={cn(
            '-mb-px border-b-2 px-3 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
            t.key === current ? 'border-primary font-medium text-text' : 'border-transparent text-text-secondary hover:text-text',
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}
