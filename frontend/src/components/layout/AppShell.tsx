import { useRef, type ReactNode } from 'react'
import { ModuleRail } from '@/platform/ModuleRail'
import { HelpPanel } from '@/help/HelpPanel'
import { useHelpOpen } from '@/help/useHelpOpen'

interface AppShellProps {
  /** Сайдбар активного модуля; у заглушек его нет. */
  sidebar?: ReactNode
  children: ReactNode
}

/** Оболочка STools: рейка модулей, сайдбар модуля, рабочая область и панель справки справа. */
export function AppShell({ sidebar, children }: AppShellProps) {
  const help = useHelpOpen()
  // Кнопка-логин в рейке открывает панель через меню пользователя; панель возвращает на неё фокус.
  const helpButton = useRef<HTMLButtonElement>(null)
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-app-bg text-text">
      <ModuleRail helpOpen={help.open} onHelp={help.toggle} helpButtonRef={helpButton} />
      {sidebar}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">{children}</main>
      <HelpPanel open={help.open} onClose={help.close} buttonRef={helpButton} />
    </div>
  )
}
