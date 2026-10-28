import type { Ref } from 'react'
import { ListChecks, Settings2, Shield } from 'lucide-react'
import { useMe } from '@/api/auth'
import { Link, useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { firstReadableModule, useCan } from '@/lib/can'
import { atLeast, type Area } from '@/platform/access/types'
import { useMyFindingsCount } from './findings/queries'
import { MODULES } from './modules'
import { UserMenu } from './UserMenu'

const FOCUS =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-inset'

/**
 * Рейка модулей — первый уровень навигации. Узкая, но не иконочная: под
 * каждой иконкой код модуля, иначе пять похожих значков не различить.
 * Полное имя — в title и для скринридера.
 */
export function ModuleRail({
  helpOpen,
  onHelp,
  helpButtonRef,
}: {
  helpOpen: boolean
  onHelp: () => void
  helpButtonRef: Ref<HTMLButtonElement>
}) {
  const { path } = useRouter()
  const { data: me } = useMe()
  const can = useCan()
  // Модули, закрытые группам пользователя, в рейке не показываются.
  // Заглушки «в разработке» прав не имеют — их видят все.
  const modules = MODULES.filter((m) => m.status === 'planned' || (me && atLeast(me.access, m.id as Area, 'read')))
  const home = firstReadableModule(me?.access)
  // Исполнителем бывает только аналитик или администратор модуля: тому, кто
  // нигде не пишет, значок ни к чему.
  const mine = useMyFindingsCount(can.anyWrite)
  const open = mine.data?.open ?? 0
  const overdue = mine.data?.overdue ?? 0

  return (
    <nav aria-label="Модули" className="flex w-16 shrink-0 flex-col border-r border-grid bg-app-bg">
      {/* Логотип ведёт на матрицу ATT&CK: это общий экран всех модулей,
          и он же — точка входа в продукт. Матрица закрыта — на первый
          открытый модуль, а без модулей — в профиль. */}
      <Link
        to={home ? `/${home}` : '/settings/profile'}
        className={cn(
          'flex h-14 flex-col items-center justify-center gap-0.5 border-b border-grid text-primary',
          FOCUS,
        )}
        aria-label={home === 'attack' ? 'Security Tools, к матрице ATT&CK' : 'Security Tools'}
        title="Security Tools"
      >
        <Shield size={22} strokeWidth={2} aria-hidden />
        <span className="text-[10px] font-semibold tracking-wide text-text">STools</span>
      </Link>

      <ul className="flex flex-col gap-1 px-1.5 py-2">
        {modules.map((m) => {
          const Icon = m.icon
          const active = path === `/${m.id}` || path.startsWith(`/${m.id}/`)
          const planned = m.status === 'planned'
          return (
            <li key={m.id}>
              <Link
                to={`/${m.id}`}
                title={planned ? `${m.title} — в разработке` : m.title}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'flex flex-col items-center gap-1 rounded px-1 py-2 text-[10px] font-medium tracking-wide transition-colors duration-150',
                  FOCUS,
                  active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
                  planned && !active && 'opacity-60',
                )}
              >
                <Icon size={18} strokeWidth={2} aria-hidden />
                <span aria-hidden>{m.code}</span>
                <span className="sr-only">
                  {m.title}
                  {planned ? ', в разработке' : ''}
                </span>
              </Link>
            </li>
          )
        })}
      </ul>

      <div className="mt-auto flex flex-col items-center gap-1 border-t border-grid px-1 py-2">
        {can.anyWrite && (
          <Link
            to="/findings"
            className={cn(
              'relative rounded p-2 text-text-secondary hover:bg-row-hover hover:text-text',
              FOCUS,
              path === '/findings' && 'bg-row-selected text-text',
            )}
            aria-label={`Мои находки: открытых ${open}${overdue ? `, просрочено ${overdue}` : ''}`}
            title={overdue ? `Мои находки — открытых ${open}, просрочено ${overdue}` : `Мои находки — открытых ${open}`}
          >
            <ListChecks size={16} aria-hidden />
            {open > 0 && (
              <span
                aria-hidden
                className={cn(
                  'absolute -top-0.5 -right-1 min-w-4 rounded-full px-1 text-center font-mono text-[9px] leading-4 tabular-nums',
                  overdue ? 'bg-kind-1 text-white' : 'bg-row-selected text-text',
                )}
              >
                {open > 99 ? '99+' : open}
              </span>
            )}
          </Link>
        )}
        {/* Настройки — для всех: в них профиль и сводка «Данные» (строки
            сервер отбирает по модулям пользователя), а у боковых панелей
            модулей своей ссылки на настройки больше нет. Разделы платформы и
            страницы модулей внутри — по уровню. */}
        <Link
          to="/settings"
          className={cn(
            'rounded p-2 text-text-secondary hover:bg-row-hover hover:text-text',
            FOCUS,
            path.startsWith('/settings') && 'bg-row-selected text-text',
          )}
          aria-label="Настройки"
          title="Настройки"
        >
          <Settings2 size={16} aria-hidden />
        </Link>
        {/* Логин — кнопка меню пользователя: подсказка по странице, тема, выход.
            Раздел справки /help открывается из панели подсказки («Вся справка →»). */}
        <UserMenu helpOpen={helpOpen} onHelp={onHelp} helpButtonRef={helpButtonRef} />
        {!can.anyWrite && (
          <span className="text-[9px] text-text-secondary" title="Ни в одном модуле нет права на изменения">
            только чтение
          </span>
        )}
      </div>
    </nav>
  )
}
