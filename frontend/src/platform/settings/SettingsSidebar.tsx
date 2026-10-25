import { Bot, Database, KeyRound, ListChecks, ScrollText, ShieldCheck, UserRound, Users, type LucideIcon } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { useCan } from '@/lib/can'
import { MODULES } from '@/platform/modules'

/** Настройки платформы, которые меняет только администратор. */
const ADMIN_ITEMS = [
  { key: 'users', label: 'Пользователи', icon: Users },
  { key: 'security', label: 'Безопасность', icon: ShieldCheck },
  { key: 'oidc', label: 'Вход по OIDC', icon: KeyRound },
  { key: 'audit', label: 'Журнал действий', icon: ScrollText },
  { key: 'llm', label: 'Модель LLM', icon: Bot },
] as const

/** Настройки и данные модулей — в порядке рейки, только работающие модули. */
const MODULE_ITEMS = MODULES.filter((m) => m.status === 'available').map((m) => ({ key: m.id, label: m.title, icon: m.icon }))

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
  const active = path === to
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
 * Разделы администратора остальным ролям не показываются: здесь, в
 * отличие от разделов снапшота SIEM, неактивный пункт ничего не обещает —
 * доступ даёт не следующий шаг пользователя, а другой человек.
 */
export function SettingsSidebar() {
  const { admin } = useCan()

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold tracking-wide text-text">Настройки</div>
        <div className="text-xs text-text-secondary">платформа и модули</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы настроек">
        {/* Всем: сводка свежести баз и выгрузок всех модулей. */}
        <NavItem to="/settings" label="Данные" icon={Database} />
        <div className={cn(GROUP, 'mt-2 border-t border-grid pt-3')}>Платформа</div>
        {admin &&
          ADMIN_ITEMS.map(({ key, label, icon }) => (
            <NavItem key={key} to={`/settings/${key}`} label={label} icon={icon} />
          ))}
        {/* Всем: остальные роли видят, что считается, но не меняют. */}
        <NavItem to="/settings/findings" label="Статусы находок" icon={ListChecks} />
        <NavItem
          to="/settings/profile"
          label="Мой профиль"
          icon={UserRound}
          className={admin ? 'mt-2 border-t border-grid pt-3' : undefined}
        />
        {/* Всем: что загружено и как настроено, видят все роли; менять — по правам на странице модуля. */}
        <div className={cn(GROUP, 'mt-2 border-t border-grid pt-3')}>Модули</div>
        {MODULE_ITEMS.map(({ key, label, icon }) => (
          <NavItem key={key} to={`/settings/${key}`} label={label} icon={icon} />
        ))}
      </nav>
    </aside>
  )
}
