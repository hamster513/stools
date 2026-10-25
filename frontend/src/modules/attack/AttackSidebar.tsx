import { Grid3x3, ListChecks, MapPin, Waypoints } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

const ITEMS = [
  { to: '/attack', label: 'Матрица', icon: Grid3x3, exact: true },
  { to: '/attack/chains', label: 'Цепочки', icon: Waypoints, exact: false },
  { to: '/attack/ru', label: 'РФ TTP', icon: MapPin, exact: false },
]

/** Второй уровень навигации модуля. Выбирать нечего: матрица одна и
 *  показывает текущее состояние — селекта снапшота здесь нет. */
export function AttackSidebar() {
  const { path } = useRouter()
  const active = (to: string, exact: boolean) => (exact ? path === to : path === to || path.startsWith(`${to}/`))

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Матрица ATT&CK</div>
        <div className="text-xs text-text-secondary">покрытие и экспозиция всех модулей</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <Link key={to} to={to} className={cn(LINK, active(to, exact) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active(to, exact) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
        <Link to="/attack/jobs" className={cn(LINK, 'mt-2 border-t border-grid pt-3', active('/attack/jobs', false) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active('/attack/jobs', false) ? 'page' : undefined}>
          <ListChecks size={16} strokeWidth={2} aria-hidden />
          Задачи
        </Link>
      </nav>
    </aside>
  )
}
