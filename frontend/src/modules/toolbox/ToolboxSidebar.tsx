import { BookKey, Eraser, Settings2, Undo2 } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

const ITEMS = [
  // Карточка и форма задания живут под /toolbox/scrub/… — это тоже «Очистка файлов».
  { to: '/toolbox', label: 'Очистка файлов', icon: Eraser, match: (p: string) => p === '/toolbox' || p.startsWith('/toolbox/scrub/') },
  { to: '/toolbox/reverse', label: 'Обратный перевод', icon: Undo2, match: (p: string) => p === '/toolbox/reverse' },
  { to: '/toolbox/aliases', label: 'Соответствия', icon: BookKey, match: (p: string) => p === '/toolbox/aliases' },
]

/** Второй уровень навигации модуля ToolBox; настройки — только администратору. */
export function ToolboxSidebar() {
  const { path } = useRouter()
  const { admin } = useCan()
  const linkClass = (on: boolean) =>
    cn(LINK, on ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')
  const settingsOn = path === '/toolbox/settings'

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">ToolBox</div>
        <div className="text-xs text-text-secondary">утилиты ИБ-специалиста</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {ITEMS.map(({ to, label, icon: Icon, match }) => (
          <Link key={to} to={to} className={linkClass(match(path))} aria-current={match(path) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
        {admin && (
          <Link to="/toolbox/settings" className={cn(linkClass(settingsOn), 'mt-2 border-t border-grid pt-3')} aria-current={settingsOn ? 'page' : undefined}>
            <Settings2 size={16} strokeWidth={2} aria-hidden />
            Настройки
          </Link>
        )}
      </nav>
    </aside>
  )
}
