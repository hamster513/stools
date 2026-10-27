import type { ReactNode } from 'react'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Redirect, useRouter } from '@/lib/router'
import { DrawerTabs } from '@/platform/tabs/DrawerTabs'
import { useScrollToAnchor } from '../useScrollToAnchor'
import { GroupEditor } from './GroupEditor'
import { GroupsPage } from './GroupsPage'
import { OidcPage } from './OidcPage'
import { RoleEditor } from './RoleEditor'
import { RolesPage } from './RolesPage'
import { SecurityPage } from './SecurityPage'
import { UsersPage } from './UsersPage'

const ROOT = '/settings/access'

const TABS = [
  { key: 'users', label: 'Пользователи' },
  { key: 'groups', label: 'Группы' },
  { key: 'roles', label: 'Роли' },
  { key: 'login', label: 'Вход' },
]

/** Вкладка «Вход»: пароли и сессии, ниже — OIDC. `#oidc` в адресе прокручивает ко второму блоку. */
function LoginTab() {
  useScrollToAnchor(true)
  return (
    <div className="h-full overflow-y-auto p-6">
      <SecurityPage />
      <div className="mt-8 border-t border-grid pt-6">
        <OidcPage />
      </div>
    </div>
  )
}

/**
 * Раздел «Доступ»: пользователи, группы, роли и вход под одними вкладками.
 * Вкладка — второй сегмент пути (`/settings/access/<вкладка>`), карточка группы
 * или роли — третий (`…/groups/new`, `…/roles/3`). Права проверяет SettingsShell.
 */
export function AccessPage() {
  const { path, navigate } = useRouter()
  const parts = path.split('/').filter(Boolean).slice(2) // после «settings/access»
  const [tab, id] = parts

  let content: ReactNode
  if (parts.length === 1 && tab === 'users') content = <UsersPage />
  else if (parts.length === 1 && tab === 'groups') content = <GroupsPage />
  else if (parts.length === 2 && tab === 'groups' && id) content = <GroupEditor />
  else if (parts.length === 1 && tab === 'roles') content = <RolesPage />
  else if (parts.length === 2 && tab === 'roles' && id) content = <RoleEditor />
  else if (parts.length === 1 && tab === 'login') content = <LoginTab />
  else return <Redirect to={`${ROOT}/users`} />

  return (
    <div className="flex h-full min-h-0 flex-col">
      <DrawerTabs tabs={TABS} current={tab} onSelect={(key) => navigate(`${ROOT}/${key}`)} label="Разделы доступа" />
      <div role="tabpanel" className="min-h-0 flex-1">
        {/* Ключ по вкладке: ошибка одной не должна переезжать в следующую; сами вкладки остаются на месте. */}
        <ErrorBoundary key={tab} resetLabel="Показать снова">
          {content}
        </ErrorBoundary>
      </div>
    </div>
  )
}
