import {
  Bot,
  Mail,
  Database,
  HardDrive,
  CalendarClock,
  KeyRound,
  ListChecks,
  ScrollText,
  UserRound,
  Crosshair,
  type LucideIcon,
} from 'lucide-react'
import { useMe } from '@/api/auth'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { atLeast, type Area, type Level } from '@/platform/access/types'
import { MODULES } from '@/platform/modules'

/** Разделы платформы: видны при чтении платформы, «Модель LLM» — её администратору. */
const PLATFORM_ITEMS = [
  { key: 'storage', label: 'Хранилище', icon: HardDrive, admin: false },
  { key: 'access', label: 'Доступ', icon: KeyRound, admin: false },
  { key: 'audit', label: 'Журнал действий', icon: ScrollText, admin: false },
  { key: 'mail', label: 'Почта', icon: Mail, admin: true },
  { key: 'llm', label: 'Модель LLM', icon: Bot, admin: true },
] as const

/** Страницы настроек модулей — в порядке рейки, только работающие модули. */
const MODULE_ITEMS = MODULES.filter((m) => m.status === 'available').flatMap((m) => [
  { key: m.id, area: m.id as Area, label: m.title, icon: m.icon },
  ...(m.id === 'siem'
    ? [{ key: 'siem-hunting', area: 'siem' as Area, label: 'SIEM Threat Hunting', icon: Crosshair },
       { key: 'siem-logons', area: 'siem' as Area, label: 'Импорт авторизаций SIEM', icon: Database }]
    : []),
])

const GROUP = 'px-3 pt-1 pb-1 text-xs font-medium text-text-secondary'

const LINK =
  'flex items-center gap-2.5 rounded px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

function NavItem({
  to,
  label,
  icon: Icon,
  className,
}: {
  to: string
  label: string
  icon: LucideIcon
  className?: string
}) {
  const { path } = useRouter()
  // Карточка внутри раздела (/settings/access/roles/3) подсвечивает свой раздел.
  const active = path === to || (to !== '/settings' && path.startsWith(`${to}/`))
  return (
    <Link
      to={to}
      className={cn(
        LINK,
        className,
        active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
      )}
      aria-current={active ? 'page' : undefined}
    >
      <Icon size={16} strokeWidth={2} aria-hidden />
      {label}
    </Link>
  )
}

/**
 * Второй уровень навигации для общих настроек.
 *
 * Недоступные разделы не показываются: здесь, в отличие от разделов
 * снапшота SIEM, неактивный пункт ничего не обещает — доступ даёт не
 * следующий шаг пользователя, а другой человек. Условия — те же, что у
 * SettingsShell.
 */
export function SettingsSidebar() {
  const { data: me } = useMe()
  const has = (area: Area, level: Level) => !!me && atLeast(me.access, area, level)
  const platformItems = PLATFORM_ITEMS.filter((i) => has('platform', i.admin ? 'admin' : 'read'))
  const moduleItems = MODULE_ITEMS.filter((i) => has(i.area, 'write'))
  const anyPlatform = platformItems.length > 0

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Настройки</div>
        <div className="text-xs text-text-secondary">платформа и модули</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы настроек">
        {/* Всем: сводка свежести баз и выгрузок модулей пользователя. */}
        <NavItem to="/settings" label="Данные" icon={Database} />
        <div className={cn(GROUP, 'mt-2 border-t border-grid pt-3')}>Платформа</div>
        <NavItem to="/settings/schedules" label="Расписание" icon={CalendarClock} />
        {platformItems.map(({ key, label, icon }) => (
          <NavItem key={key} to={`/settings/${key}`} label={label} icon={icon} />
        ))}
        {/* Всем: видят, что считается; менять — администратору платформы. */}
        <NavItem to="/settings/findings" label="Статусы находок" icon={ListChecks} />
        <NavItem
          to="/settings/profile"
          label="Мой профиль"
          icon={UserRound}
          className={anyPlatform ? 'mt-2 border-t border-grid pt-3' : undefined}
        />
        {/* Страницы модулей — с уровня «аналитик»: загрузки и сбор; настройку внутри меняет администратор. */}
        {moduleItems.length > 0 && <div className={cn(GROUP, 'mt-2 border-t border-grid pt-3')}>Модули</div>}
        {moduleItems.map(({ key, label, icon }) => (
          <NavItem key={key} to={`/settings/${key}`} label={label} icon={icon} />
        ))}
      </nav>
    </aside>
  )
}
