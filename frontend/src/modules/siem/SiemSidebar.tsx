import { CalendarClock, Copy, Crosshair, LayoutDashboard, Library, Newspaper, ListTree, Radar, SlidersHorizontal, Telescope } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { useThFindings } from './hunting/api/queries'

//: Разбор находок отдельным разделом не стоит: путь к находке начинается
//: с правила, у которого что-то не так, а не с общего списка. Экран
//: находок остался — в него уводит маркировка в инвентаре правил.
const NAV_ITEMS = [
  { key: 'overview', label: 'Обзор', icon: LayoutDashboard },
  { key: 'rules', label: 'Инвентарь правил', icon: ListTree },
  { key: 'clones', label: 'Клоны правил', icon: Copy },
  { key: 'attack', label: 'Разметка ATT&CK', icon: Crosshair },
  { key: 'profile', label: 'Профиль инсталляции', icon: SlidersHorizontal },
] as const

//: Threat Hunting от снапшота правил не зависит — пункты всегда активны.
const HUNTING_ITEMS = [
  { key: 'findings', label: 'Находки', to: '/siem/hunting', prefix: '/siem/hunting/findings', icon: Radar },
  { key: 'library', label: 'Библиотека хантов', to: '/siem/hunting/library', prefix: '/siem/hunting/library', icon: Library },
  { key: 'materials', label: 'Материалы', to: '/siem/hunting/materials', prefix: '/siem/hunting/materials', icon: Newspaper },
  { key: 'deep', label: 'Большой хант', to: '/siem/hunting/deep', prefix: '/siem/hunting/deep', icon: Telescope },
  { key: 'scheduler', label: 'Планировщик', to: '/siem/hunting/scheduler', prefix: '/siem/hunting/scheduler', icon: CalendarClock },
] as const

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Второй уровень навигации: разделы снапшота модуля SIEM.
 *
 * Без выгрузки разделы показываются, но не ведут никуда: спрятанный
 * пункт меню выглядит как отсутствующая возможность, а неактивный с
 * подписью — как следующий шаг.
 */
export function SiemSidebar({ snapshotId }: { snapshotId: number | null }) {
  const { path } = useRouter()
  // Счётчик новых находок; пока не загрузился (или запрос упал) — без значка.
  const newFindings = useThFindings({ status: ['new'], limit: 1 }).data?.total ?? 0

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">SIEM Rules Analyzer</div>
        <div className="text-xs text-text-secondary">
          {snapshotId === null ? 'выгрузки ещё нет' : `снапшот #${snapshotId}`}
        </div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы">
        {NAV_ITEMS.map(({ key, label, icon: Icon }) => {
          if (snapshotId === null) {
            return (
              <span
                key={key}
                aria-disabled="true"
                title="Недоступно: сначала загрузите выгрузку правил"
                className={cn(LINK, 'cursor-not-allowed text-text-secondary opacity-50')}
              >
                <Icon size={16} strokeWidth={2} aria-hidden />
                {label}
              </span>
            )
          }
          const to = `/siem/snapshots/${snapshotId}/${key}`
          const active = path === to || path.startsWith(`${to}?`)
          return (
            <Link
              key={key}
              to={to}
              className={cn(
                LINK,
                active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
              )}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={16} strokeWidth={2} aria-hidden />
              {label}
            </Link>
          )
        })}
        {snapshotId === null && (
          <p className="px-3 pt-1 pb-2 text-xs leading-relaxed text-text-secondary">
            Разделы откроются, когда в настройках будет загружена выгрузка правил.
          </p>
        )}
        <div className="mt-2 border-t border-grid px-3 pt-3 pb-1 text-sm font-semibold tracking-wide text-text">Threat Hunting</div>
        {HUNTING_ITEMS.map(({ key, label, to, prefix, icon: Icon }) => {
          // Карточка ночи (`/siem/hunting/runs/:id`) открывается из истории планировщика — подсвечивается он.
          const active = path === to || path.startsWith(`${prefix}/`) || (key === 'scheduler' && path.startsWith('/siem/hunting/runs/'))
          return (
            <Link
              key={key}
              to={to}
              className={cn(
                LINK,
                active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
              )}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={16} strokeWidth={2} aria-hidden />
              {label}
              {key === 'findings' && newFindings > 0 && (
                <span
                  className="ml-auto rounded-full bg-primary px-1.5 font-mono text-[11px] leading-5 tabular-nums text-primary-text"
                  title="Новых находок"
                  aria-label={`новых находок: ${newFindings}`}
                >
                  {newFindings > 99 ? '99+' : newFindings}
                </span>
              )}
            </Link>
          )
        })}
      </nav>
    </aside>
  )
}
