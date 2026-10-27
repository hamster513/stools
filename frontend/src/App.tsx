import { useEffect } from 'react'
import { useMe } from '@/api/auth'
import { Redirect, RouterProvider, useRouter } from '@/lib/router'
import { applyTheme, readStoredTheme } from '@/lib/theme'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { LoginPage } from '@/pages/LoginPage'
import { firstReadableModule } from '@/lib/can'
import { atLeast, type Area } from '@/platform/access/types'
import { findModule } from '@/platform/modules'
import { Forbidden } from '@/platform/settings/Forbidden'
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
 * и /<модуль>/settings (до переезда настроек в /settings/<модуль>), а также
 * /settings/users|groups|roles|security|oidc (до объединения в «Доступ»). На них ведут
 * закладки и ссылки в чужих инструкциях — переводим на новые, а не ломаем.
 */
function legacyPath(path: string, tail: string): string | null {
  if (path.startsWith('/snapshots/')) return `/siem${path}${tail}`
  if (path === '/upload' || path === '/siem/upload') return `/settings/siem${tail}`
  const m = /^\/([a-z]+)\/settings$/.exec(path)
  if (m && MOVED_SETTINGS.has(m[1])) return `/settings/${m[1]}${tail}`
  const access = /^\/settings\/(users|groups|roles)(\/.*)?$/.exec(path)
  if (access) return `/settings/access/${access[1]}${access[2] ?? ''}${tail}`
  if (/^\/settings\/security\/?$/.test(path)) return `/settings/access/login${tail}`
  // Свой якорь заменяет прежний: OIDC теперь блок вкладки «Вход», а не отдельная страница.
  if (/^\/settings\/oidc\/?$/.test(path)) return `/settings/access/login${tail.split('#')[0]}#oidc`
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

  // Хвост — строка запроса и якорь: /vm/settings#zones ведёт к той же секции.
  const legacy = legacyPath(path, search + window.location.hash)
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

  // Первый сегмент пути — модуль. Корень и неизвестные пути ведут в первый
  // открытый пользователю модуль, а без модулей — в профиль: пустой экран
  // хуже любого выбора.
  const module = findModule(path.split('/')[1] ?? '')
  if (!module) {
    const home = firstReadableModule(me.access)
    return <Redirect to={home ? `/${home}` : '/settings/profile'} />
  }

  // Закрытый модуль по прямой ссылке — отказ в оболочке, а не 403 на каждом
  // запросе. У заглушек «в разработке» области прав нет — их видят все.
  if (module.status === 'available' && !atLeast(me.access, module.id as Area, 'read'))
    return (
      <AppShell>
        <Forbidden kind="module" />
      </AppShell>
    )

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
