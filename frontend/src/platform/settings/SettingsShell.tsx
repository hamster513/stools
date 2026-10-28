import type { ReactNode } from 'react'
import { useMe } from '@/api/auth'
import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { atLeast } from '@/platform/access/types'
import { SettingsSidebar } from './SettingsSidebar'
import { Forbidden } from './Forbidden'
import { PAGES } from './pages'
import { DataStatusPage } from './pages/DataStatusPage'

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
