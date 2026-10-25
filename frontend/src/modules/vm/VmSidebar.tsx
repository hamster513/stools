import { LayoutDashboard, ListChecks, ShieldAlert } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'

const NAV_ITEMS = [
  { to: '/vm', label: 'Обзор', icon: LayoutDashboard, exact: true },
  { to: '/vm/vulns', label: 'Уязвимости', icon: ShieldAlert, exact: false },
  { to: '/vm/jobs', label: 'Задачи', icon: ListChecks, exact: false },
] as const

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Второй уровень навигации: разделы модуля VM. */
export function VmSidebar() {
  const { path } = useRouter()
  const isActive = (to: string, exact: boolean) => (exact ? path === to : path === to || path.startsWith(`${to}/`))

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Vulnerability Management</div>
        <div className="text-xs text-text-secondary">MaxPatrol VM</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {NAV_ITEMS.map(({ to, label, icon: Icon, exact }) => {
          const active = isActive(to, exact)
          return (
            <Link
              key={to}
              to={to}
              className={cn(LINK, active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={16} strokeWidth={2} aria-hidden />
              {label}
            </Link>
          )
        })}
      </nav>
    </aside>
  )
}
