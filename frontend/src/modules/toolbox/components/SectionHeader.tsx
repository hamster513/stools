import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import type { ToolboxSection } from '../nav'

const TAB = 'rounded px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Шапка раздела ToolBox: заголовок и вкладки-ссылки, как у «Сетей» в Активах. */
export function SectionHeader({ section, path }: { section: ToolboxSection; path: string }) {
  return (
    <header className="flex shrink-0 items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
      <h1 className="text-sm font-semibold text-text">{section.label}</h1>
      {section.tabs.length > 0 && (
        <nav className="flex gap-1" aria-label="Вкладки">
          {section.tabs.map((t) => {
            const on = t.match(path)
            return (
              <Link key={t.to} to={t.to} aria-current={on ? 'page' : undefined}
                className={cn(TAB, on ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
                {t.label}
              </Link>
            )
          })}
        </nav>
      )}
    </header>
  )
}
