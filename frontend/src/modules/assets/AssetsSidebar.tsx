import { LayoutDashboard, ListChecks, Monitor, Network, Settings2, Users } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

const ITEMS = [
  { to: '/assets', label: 'Обзор', icon: LayoutDashboard, exact: true },
  { to: '/assets/list', label: 'Активы', icon: Monitor, exact: false },
  { to: '/assets/users', label: 'Пользователи', icon: Users, exact: false },
  { to: '/assets/networks', label: 'Сети', icon: Network, exact: false },
]

/** Второй уровень навигации модуля Assets: реестр один, выбирать сервер или домен не нужно. */
export function AssetsSidebar() {
  const { path } = useRouter()
  const active = (to: string, exact: boolean) => (exact ? path === to : path === to || path.startsWith(`${to}/`))
  const linkClass = (to: string, exact: boolean) =>
    cn(LINK, active(to, exact) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Активы</div>
        <div className="text-xs text-text-secondary">хосты из всех источников</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <Link key={to} to={to} className={linkClass(to, exact)} aria-current={active(to, exact) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
        <Link to="/assets/jobs" className={cn(linkClass('/assets/jobs', false), 'mt-2 border-t border-grid pt-3')} aria-current={active('/assets/jobs', false) ? 'page' : undefined}>
          <ListChecks size={16} strokeWidth={2} aria-hidden />
          Задачи
        </Link>
        <Link to="/assets/settings" className={linkClass('/assets/settings', false)} aria-current={active('/assets/settings', false) ? 'page' : undefined}>
          <Settings2 size={16} strokeWidth={2} aria-hidden />
          Настройки и данные
        </Link>
      </nav>
    </aside>
  )
}
