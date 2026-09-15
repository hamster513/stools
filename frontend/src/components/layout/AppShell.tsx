import type { ReactNode } from 'react'
import { ModuleRail } from '@/platform/ModuleRail'

interface AppShellProps {
  /** Сайдбар активного модуля; у заглушек его нет. */
  sidebar?: ReactNode
  children: ReactNode
}

/** Оболочка STools: рейка модулей, сайдбар модуля, рабочая область. */
export function AppShell({ sidebar, children }: AppShellProps) {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-app-bg text-text">
      <ModuleRail />
      {sidebar}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">{children}</main>
    </div>
  )
}
