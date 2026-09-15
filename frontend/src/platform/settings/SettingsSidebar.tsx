import { Bot, Grid3x3, KeyRound, ScrollText, ShieldCheck, UserRound, Users, type LucideIcon } from 'lucide-react'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { useCan } from '@/lib/can'

/** Общие настройки продукта — всё, что не привязано к одному модулю. */
const ADMIN_ITEMS = [
  { key: 'users', label: 'Пользователи', icon: Users },
  { key: 'security', label: 'Безопасность', icon: ShieldCheck },
  { key: 'oidc', label: 'Вход по OIDC', icon: KeyRound },
  { key: 'audit', label: 'Журнал действий', icon: ScrollText },
  { key: 'llm', label: 'Модель LLM', icon: Bot },
  { key: 'attack', label: 'База ATT&CK', icon: Grid3x3 },
] as const

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
        <div className="text-xs text-text-secondary">общие для всех модулей</div>
      </div>
      <nav className="flex flex-col gap-0.5 px-2" aria-label="Разделы настроек">
        {admin &&
          ADMIN_ITEMS.map(({ key, label, icon }) => (
            <NavItem key={key} to={`/settings/${key}`} label={label} icon={icon} />
          ))}
        <NavItem
          to="/settings/profile"
          label="Мой профиль"
          icon={UserRound}
          className={admin ? 'mt-2 border-t border-grid pt-3' : undefined}
        />
      </nav>
    </aside>
  )
}
