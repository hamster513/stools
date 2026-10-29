import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { TOOLBOX_SECTIONS } from './nav'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Второй уровень навигации модуля ToolBox: по пункту на инструмент, вкладки инструмента — сверху над страницей. */
export function ToolboxSidebar() {
  const { path } = useRouter()
  const linkClass = (on: boolean) =>
    cn(LINK, on ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">ToolBox</div>
        <div className="text-xs text-text-secondary">утилиты ИБ-специалиста</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {TOOLBOX_SECTIONS.map(({ to, label, icon: Icon, match }) => (
          <Link key={to} to={to} className={linkClass(match(path))} aria-current={match(path) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
      </nav>
    </aside>
  )
}
