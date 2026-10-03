import { Camera, FileCog, History, LayoutDashboard, ListChecks, ListX, Monitor, Network, ServerCog, Settings2, ShieldAlert } from 'lucide-react'
import type { Server } from '@/modules/ksc/api/types'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Второй уровень навигации: сервер KSC и его разделы. */
export function KscSidebar({ servers, serverId }: { servers: Server[]; serverId: number | null }) {
  const { path, navigate } = useRouter()
  const base = serverId !== null ? `/ksc/servers/${serverId}` : null
  const items = base
    ? [
        { to: base, label: 'Обзор', icon: LayoutDashboard, exact: true },
        { to: `${base}/hosts`, label: 'Хосты', icon: Monitor, exact: false },
        { to: `${base}/findings`, label: 'Находки', icon: ShieldAlert, exact: false },
        { to: `${base}/policies`, label: 'Политики и задачи', icon: FileCog, exact: false },
        { to: `${base}/exclusions`, label: 'Исключения', icon: ListX, exact: false },
        { to: `${base}/netrules`, label: 'Сетевые правила', icon: Network, exact: false },
        { to: `${base}/changes`, label: 'Изменения', icon: History, exact: false },
        { to: `${base}/server`, label: 'Сервер KSC', icon: ServerCog, exact: false },
        { to: `${base}/snapshots`, label: 'Снапшоты', icon: Camera, exact: false },
      ]
    : []
  const active = (to: string, exact: boolean) => (exact ? path === to : path === to || path.startsWith(`${to}/`))

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Антивирус</div>
        {servers.length > 0 ? (
          <select
            aria-label="Сервер"
            value={serverId ?? ''}
            onChange={(e) => navigate(`/ksc/servers/${e.target.value}`)}
            className="mt-1.5 w-full rounded border border-border bg-app-bg px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            {servers.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        ) : (
          <div className="text-xs text-text-secondary">серверов ещё нет</div>
        )}
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {items.map(({ to, label, icon: Icon, exact }) => (
          <Link key={to} to={to} className={cn(LINK, active(to, exact) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active(to, exact) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
        {servers.length === 0 && (
          <p className="px-3 py-2 text-xs leading-relaxed text-text-secondary">Разделы появятся после первой выгрузки или сбора из KSC.</p>
        )}
        <Link to="/ksc/jobs" className={cn(LINK, items.length ? 'mt-2 border-t border-grid pt-3' : '', active('/ksc/jobs', false) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active('/ksc/jobs', false) ? 'page' : undefined}>
          <ListChecks size={16} strokeWidth={2} aria-hidden />
          Задачи
        </Link>
        <Link to="/ksc/settings" className={cn(LINK, active('/ksc/settings', false) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active('/ksc/settings', false) ? 'page' : undefined}>
          <Settings2 size={16} strokeWidth={2} aria-hidden />
          Настройки и данные
        </Link>
      </nav>
    </aside>
  )
}
