import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { AssetsSidebar } from './AssetsSidebar'
import { AssetsPage } from './pages/AssetsPage'
import { GroupsPage } from './pages/GroupsPage'
import { JobsPage } from './pages/JobsPage'
import { NetworksPage } from './pages/NetworksPage'
import { OverviewPage } from './pages/OverviewPage'
import { UsersPage } from './pages/UsersPage'

/** Маршруты модуля Assets — всё под /assets. Реестр один на платформу, поэтому в адресе нет сервера или домена. */
export function AssetsModule() {
  const { path, navigate } = useRouter()

  let page: React.ReactNode
  if (path === '/assets') page = <OverviewPage />
  else if (path === '/assets/list') page = <AssetsPage />
  else if (path === '/assets/users') page = <UsersPage />
  else if (path === '/assets/groups') page = <GroupsPage />
  else if (path === '/assets/networks') page = <NetworksPage />
  else if (path === '/assets/jobs') page = <JobsPage />
  else return <Redirect to="/assets" />

  return (
    <AppShell sidebar={<AssetsSidebar />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/assets')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
