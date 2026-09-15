import { Camera, LayoutDashboard, ListChecks, Settings2, ShieldAlert } from 'lucide-react'
import type { Domain } from '@/modules/ad/api/types'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Второй уровень навигации: домен и его разделы. */
export function AdSidebar({ domains, domainId }: { domains: Domain[]; domainId: number | null }) {
  const { path, navigate } = useRouter()
  const base = domainId !== null ? `/ad/domains/${domainId}` : null
  const items = base
    ? [
        { to: base, label: 'Обзор', icon: LayoutDashboard, exact: true },
        { to: `${base}/findings`, label: 'Находки', icon: ShieldAlert, exact: false },
        { to: `${base}/snapshots`, label: 'Снапшоты', icon: Camera, exact: false },
      ]
    : []
  const active = (to: string, exact: boolean) => (exact ? path === to : path === to || path.startsWith(`${to}/`))

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Active Directory</div>
        {domains.length > 0 ? (
          <select
            aria-label="Домен"
            value={domainId ?? ''}
            onChange={(e) => navigate(`/ad/domains/${e.target.value}`)}
            className="mt-1.5 w-full rounded border border-border bg-app-bg px-2 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            {domains.map((d) => (
              <option key={d.id} value={d.id}>
                {d.dns_root || d.netbios || d.sid}
              </option>
            ))}
          </select>
        ) : (
          <div className="text-xs text-text-secondary">доменов ещё нет</div>
        )}
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {items.map(({ to, label, icon: Icon, exact }) => (
          <Link key={to} to={to} className={cn(LINK, active(to, exact) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active(to, exact) ? 'page' : undefined}>
            <Icon size={16} strokeWidth={2} aria-hidden />
            {label}
          </Link>
        ))}
        {domains.length === 0 && (
          <p className="px-3 py-2 text-xs leading-relaxed text-text-secondary">Разделы появятся после первой выгрузки или сбора по LDAP.</p>
        )}
        <Link to="/ad/jobs" className={cn(LINK, items.length ? 'mt-2 border-t border-grid pt-3' : '', active('/ad/jobs', false) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active('/ad/jobs', false) ? 'page' : undefined}>
          <ListChecks size={16} strokeWidth={2} aria-hidden />
          Задачи
        </Link>
        <Link to="/ad/settings" className={cn(LINK, active('/ad/settings', false) ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')} aria-current={active('/ad/settings', false) ? 'page' : undefined}>
          <Settings2 size={16} strokeWidth={2} aria-hidden />
          Настройки и данные
        </Link>
      </nav>
    </aside>
  )
}
