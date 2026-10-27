import { useRef, type ReactNode } from 'react'
import { ModuleRail } from '@/platform/ModuleRail'
import { HelpButton } from '@/help/HelpButton'
import { HelpPanel } from '@/help/HelpPanel'
import { useHelpOpen } from '@/help/useHelpOpen'

interface AppShellProps {
  /** Сайдбар активного модуля; у заглушек его нет. */
  sidebar?: ReactNode
  children: ReactNode
}

/** Оболочка STools: рейка модулей, сайдбар модуля, рабочая область и справка в углу. */
export function AppShell({ sidebar, children }: AppShellProps) {
  const help = useHelpOpen()
  const helpButton = useRef<HTMLButtonElement>(null)
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-app-bg text-text">
      <ModuleRail />
      {sidebar}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">{children}</main>
      {/* Кнопка после панели: при равном z-50 она лежит поверх угла панели. */}
      <HelpPanel open={help.open} onClose={help.close} buttonRef={helpButton} />
      <HelpButton open={help.open} onToggle={help.toggle} buttonRef={helpButton} />
    </div>
  )
}
