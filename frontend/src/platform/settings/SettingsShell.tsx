import type { ComponentType, ReactNode } from 'react'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { useCan } from '@/lib/can'
import { SettingsPage as SiemSettingsPage } from '@/modules/siem/pages/SettingsPage'
import { SettingsPage as VmSettingsPage } from '@/modules/vm/pages/SettingsPage'
import { SettingsPage as AdSettingsPage } from '@/modules/ad/pages/SettingsPage'
import { SettingsPage as KscSettingsPage } from '@/modules/ksc/pages/SettingsPage'
import { SettingsPage as AssetsSettingsPage } from '@/modules/assets/pages/SettingsPage'
import { SettingsPage as ToolboxSettingsPage } from '@/modules/toolbox/pages/SettingsPage'
import { SettingsSidebar } from './SettingsSidebar'
import { Forbidden } from './Forbidden'
import { ProfilePage } from './pages/ProfilePage'
import { UsersPage } from './pages/UsersPage'
import { SecurityPage } from './pages/SecurityPage'
import { OidcPage } from './pages/OidcPage'
import { AuditPage } from './pages/AuditPage'
import { LlmPage } from './pages/LlmPage'
import { AttackSettingsPage } from './pages/AttackSettingsPage'
import { FindingsSettingsPage } from './pages/FindingsSettingsPage'

/**
 * Разделы, открытые всем ролям. Статусы находок: от них зависят подсчёты,
 * которые видит каждый. Модули: что загружено и как настроено, видят все;
 * менять или загружать — по правам, их проверяет сама страница модуля.
 */
const OPEN_PAGES = new Map<string, ComponentType>([
  ['profile', ProfilePage],
  ['findings', FindingsSettingsPage],
  ['attack', AttackSettingsPage],
  ['siem', SiemSettingsPage],
  ['vm', VmSettingsPage],
  ['ad', AdSettingsPage],
  ['ksc', KscSettingsPage],
  ['assets', AssetsSettingsPage],
  ['toolbox', ToolboxSettingsPage],
])

/** Разделы платформы — только администратору. */
const ADMIN_PAGES = new Map<string, ComponentType>([
  ['users', UsersPage],
  ['security', SecurityPage],
  ['oidc', OidcPage],
  ['audit', AuditPage],
  ['llm', LlmPage],
])

/**
 * Маршруты общих настроек — всё под /settings: разделы платформы и
 * страницы модулей /settings/<модуль>. Права проверяет сервер; здесь
 * разделы администратора закрыты экраном отказа, чтобы аудитор не
 * упирался в 403 после перехода по чужой ссылке.
 */
export function SettingsShell() {
  const { path } = useRouter()
  const { admin } = useCan()
  const section = matchPath('/settings/:section', path)?.section ?? null
  const Open = section ? OPEN_PAGES.get(section) : undefined
  const Admin = section ? ADMIN_PAGES.get(section) : undefined

  // Голый /settings и неизвестные разделы уводят на первый раздел, а не
  // показывают его на чужом адресе: иначе в сайдбаре не подсвечен ни один
  // пункт, и непонятно, что именно открыто.
  let page: ReactNode
  if (Open) page = <Open />
  else if (!admin) page = <Forbidden />
  else if (Admin) page = <Admin />
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
