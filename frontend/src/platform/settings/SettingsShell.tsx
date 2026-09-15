import type { ReactNode } from 'react'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { useCan } from '@/lib/can'
import { SettingsSidebar } from './SettingsSidebar'
import { Forbidden } from './Forbidden'
import { ProfilePage } from './pages/ProfilePage'
import { UsersPage } from './pages/UsersPage'
import { SecurityPage } from './pages/SecurityPage'
import { OidcPage } from './pages/OidcPage'
import { AuditPage } from './pages/AuditPage'
import { LlmPage } from './pages/LlmPage'
import { AttackPage } from './pages/AttackPage'

/**
 * Маршруты общих настроек — всё под /settings. Права проверяет сервер;
 * здесь разделы администратора закрыты экраном отказа, чтобы аудитор не
 * упирался в 403 после перехода по чужой ссылке.
 */
export function SettingsShell() {
  const { path } = useRouter()
  const { admin } = useCan()
  const section = matchPath('/settings/:section', path)?.section ?? null

  // Голый /settings и неизвестные разделы уводят на первый раздел, а не
  // показывают его на чужом адресе: иначе в сайдбаре не подсвечен ни один
  // пункт, и непонятно, что именно открыто.
  let page: ReactNode
  if (section === 'profile') page = <ProfilePage />
  else if (!admin) page = <Forbidden />
  else if (section === 'users') page = <UsersPage />
  else if (section === 'security') page = <SecurityPage />
  else if (section === 'oidc') page = <OidcPage />
  else if (section === 'audit') page = <AuditPage />
  else if (section === 'llm') page = <LlmPage />
  else if (section === 'attack') page = <AttackPage />
  else page = <Redirect to="/settings/users" />

  return (
    <AppShell sidebar={<SettingsSidebar />}>
      {/* Ключ по разделу: ошибка одного раздела не должна переезжать в следующий. */}
      <ErrorBoundary key={section ?? ''} resetLabel="Показать снова">
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
