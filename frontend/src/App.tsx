import { useEffect } from 'react'
import { useMe } from '@/api/auth'
import { Redirect, RouterProvider, useRouter } from '@/lib/router'
import { applyTheme, readStoredTheme } from '@/lib/theme'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { LoginPage } from '@/pages/LoginPage'
import { findModule } from '@/platform/modules'
import { ModuleStubPage } from '@/platform/ModuleStubPage'
import { SettingsShell } from '@/platform/settings/SettingsShell'
import { MyFindingsPage } from '@/platform/findings/MyFindingsPage'
import { AttackModule } from '@/modules/attack/AttackModule'
import { SiemModule } from '@/modules/siem/SiemModule'
import { VmModule } from '@/modules/vm/VmModule'
import { AdModule } from '@/modules/ad/AdModule'
import { KscModule } from '@/modules/ksc/KscModule'
import { AssetsModule } from '@/modules/assets/AssetsModule'
import { ToolboxModule } from '@/modules/toolbox/ToolboxModule'

/** Модули, чьи настройки жили на /<модуль>/settings до переезда в общие настройки. */
const MOVED_SETTINGS = new Set(['attack', 'siem', 'vm', 'ad', 'ksc', 'assets', 'toolbox'])

/**
 * Прежние адреса: /snapshots/…, /upload (до появления модулей), /siem/upload
 * и /<модуль>/settings (до переезда настроек в /settings/<модуль>). На них ведут
 * закладки и ссылки в чужих инструкциях — переводим на новые, а не ломаем.
 */
function legacyPath(path: string, search: string): string | null {
  if (path.startsWith('/snapshots/')) return `/siem${path}${search}`
  if (path === '/upload' || path === '/siem/upload') return `/settings/siem${search}`
  const m = /^\/([a-z]+)\/settings$/.exec(path)
  if (m && MOVED_SETTINGS.has(m[1])) return `/settings/${m[1]}${search}`
  return null
}

function Root() {
  const { path, search, navigate } = useRouter()
  const { data: me, isLoading, isError } = useMe()

  useEffect(() => {
    if (isLoading) return
    if (!me && path !== '/login') {
      navigate('/login', { replace: true })
    }
  }, [isLoading, me, path, navigate])

  // Тема из профиля главнее той, что применена до рендера по localStorage:
  // так выбор доезжает до браузера, где его не делали.
  useEffect(() => {
    if (me && me.theme !== readStoredTheme()) applyTheme(me.theme)
  }, [me])

  if (path === '/login') {
    return <LoginPage />
  }

  if (isLoading || isError || !me) {
    // useEffect выше уже планирует переход на /login — не рендерим пусто.
    return <FullPageSpinner />
  }

  const legacy = legacyPath(path, search)
  if (legacy) return <Redirect to={legacy} />

  // Общие настройки — не модуль: они над модулями и живут в своей оболочке.
  if (path === '/settings' || path.startsWith('/settings/')) return <SettingsShell />

  // «Мои находки» — тоже над модулями: находки всех модулей, назначенные мне.
  if (path === '/findings')
    return (
      <AppShell>
        <MyFindingsPage />
      </AppShell>
    )

  // Первый сегмент пути — модуль. Корень и неизвестные пути ведут в SIEM:
  // это единственный работающий модуль, а пустой экран хуже любого выбора.
  const module = findModule(path.split('/')[1] ?? '')
  if (!module) return <Redirect to="/siem" />

  if (module.id === 'attack') return <AttackModule />
  if (module.id === 'siem') return <SiemModule />
  if (module.id === 'vm') return <VmModule />
  if (module.id === 'ad') return <AdModule />
  if (module.id === 'ksc') return <KscModule />
  if (module.id === 'assets') return <AssetsModule />
  if (module.id === 'toolbox') return <ToolboxModule />

  return (
    <AppShell>
      <ModuleStubPage module={module} />
    </AppShell>
  )
}

export default function App() {
  return (
    <RouterProvider>
      {/* Внешняя ловушка на случай ошибки в самой оболочке или роутере. */}
      <ErrorBoundary resetLabel="Перезагрузить" onReset={() => window.location.reload()}>
        <Root />
      </ErrorBoundary>
    </RouterProvider>
  )
}
