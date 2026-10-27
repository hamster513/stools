import type { ComponentType, ReactNode } from 'react'
import { useMe } from '@/api/auth'
import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { atLeast, type Area, type Level } from '@/platform/access/types'
import { SettingsPage as SiemSettingsPage } from '@/modules/siem/pages/SettingsPage'
import { SettingsPage as VmSettingsPage } from '@/modules/vm/pages/SettingsPage'
import { SettingsPage as AdSettingsPage } from '@/modules/ad/pages/SettingsPage'
import { SettingsPage as KscSettingsPage } from '@/modules/ksc/pages/SettingsPage'
import { SettingsPage as AssetsSettingsPage } from '@/modules/assets/pages/SettingsPage'
import { SettingsPage as ToolboxSettingsPage } from '@/modules/toolbox/pages/SettingsPage'
import { SettingsSidebar } from './SettingsSidebar'
import { Forbidden } from './Forbidden'
import { ProfilePage } from './pages/ProfilePage'
import { AccessPage } from './pages/AccessPage'
import { AuditPage } from './pages/AuditPage'
import { LlmPage } from './pages/LlmPage'
import { AttackSettingsPage } from './pages/AttackSettingsPage'
import { FindingsSettingsPage } from './pages/FindingsSettingsPage'
import { DataStatusPage } from './pages/DataStatusPage'

/**
 * Раздел → какая область и какой уровень нужны, чтобы его открыть. null —
 * открыт всем: профиль и статусы находок (сохранить их может только
 * администратор платформы — это проверяет сама страница).
 */
const PAGES = new Map<string, { page: ComponentType; nested?: boolean; need: [Area, Level] | null }>([
  ['profile', { page: ProfilePage, need: null }],
  ['findings', { page: FindingsSettingsPage, need: null }],
  // «Доступ» сам разбирает хвост пути: вкладки и карточки групп и ролей.
  ['access', { page: AccessPage, nested: true, need: ['platform', 'read'] }],
  ['audit', { page: AuditPage, need: ['platform', 'read'] }],
  ['llm', { page: LlmPage, need: ['platform', 'admin'] }],
  ['attack', { page: AttackSettingsPage, need: ['attack', 'write'] }],
  // Страница модуля открыта аналитику: загрузки и сбор — его работа. Настройку модуля
  // (подключения, расписания, справочники) сама страница оставляет администратору.
  ['siem', { page: SiemSettingsPage, need: ['siem', 'write'] }],
  ['vm', { page: VmSettingsPage, need: ['vm', 'write'] }],
  ['ad', { page: AdSettingsPage, need: ['ad', 'write'] }],
  ['ksc', { page: KscSettingsPage, need: ['ksc', 'write'] }],
  ['assets', { page: AssetsSettingsPage, need: ['assets', 'write'] }],
  ['toolbox', { page: ToolboxSettingsPage, need: ['toolbox', 'write'] }],
])

/**
 * Маршруты общих настроек — всё под /settings: разделы платформы и
 * страницы модулей /settings/<модуль>. Права проверяет сервер; здесь
 * недоступные разделы закрыты экраном отказа, чтобы пользователь не
 * упирался в 403 после перехода по чужой ссылке.
 */
export function SettingsShell() {
  const { path } = useRouter()
  const { data: me } = useMe()
  // /settings/ с хвостовым слэшем — тот же корень, что и /settings.
  const base = path.length > 1 ? path.replace(/\/+$/, '') : path
  // /settings/<раздел>; у вложенных разделов (nested) дальше идёт их собственный путь.
  const [, section = null, ...rest] = base.split('/').filter(Boolean)
  const entry = section ? PAGES.get(section) : undefined

  // Голый /settings — сводка «Данные», её видят все: строки сервер отбирает
  // по модулям пользователя. Неизвестные разделы уводят на сводку, а не
  // показывают её на чужом адресе: иначе в сайдбаре не подсвечен ни один
  // пункт, и непонятно, что открыто.
  let page: ReactNode
  if (base === '/settings') page = <DataStatusPage />
  else if (!entry || (rest.length > 0 && !entry.nested)) page = <Redirect to="/settings" />
  else if (entry.need && !(me && atLeast(me.access, ...entry.need))) page = <Forbidden kind="settings" />
  else page = <entry.page />

  return (
    <AppShell sidebar={<SettingsSidebar />}>
      {/* Ключ по разделу: ошибка одного раздела не должна переезжать в следующий. */}
      <ErrorBoundary key={section ?? ''} resetLabel="Показать снова">
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
