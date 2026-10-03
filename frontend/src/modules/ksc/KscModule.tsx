import { useServers } from '@/modules/ksc/api/queries'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { KscSidebar } from './KscSidebar'
import { OverviewPage } from './pages/OverviewPage'
import { HostsPage } from './pages/HostsPage'
import { FindingsPage } from './pages/FindingsPage'
import { PoliciesPage } from './pages/PoliciesPage'
import { PolicyPage } from './pages/PolicyPage'
import { ServerPage } from './pages/ServerPage'
import { SnapshotsPage } from './pages/SnapshotsPage'
import { SettingsPage } from './pages/SettingsPage'
import { JobsPage } from './pages/JobsPage'
import { ExclusionsPage } from './pages/ExclusionsPage'
import { NetRulesPage } from './pages/NetRulesPage'
import { ChangesPage } from './pages/ChangesPage'

/** Маршруты модуля KSC — всё под /ksc. Сервер — в адресе, как домен у AD. */
export function KscModule() {
  const { path, navigate } = useRouter()
  const servers = useServers()
  if (servers.isLoading) return <FullPageSpinner />
  const list = servers.data ?? []

  const policyMatch = matchPath('/ksc/servers/:id/policies/:policyId', path)
  const serverMatch = matchPath('/ksc/servers/:id', path) ?? matchPath('/ksc/servers/:id/:section', path)
  const serverId = policyMatch ? Number(policyMatch.id) : serverMatch ? Number(serverMatch.id) : null
  const section = serverMatch?.section ?? ''

  let page: React.ReactNode
  if (path === '/ksc') {
    return <Redirect to={list.length ? `/ksc/servers/${list[0].id}` : '/ksc/settings'} />
  } else if (path === '/ksc/settings') page = <SettingsPage />
  else if (path === '/ksc/jobs') page = <JobsPage />
  else if (policyMatch) page = <PolicyPage serverId={Number(policyMatch.id)} policyId={Number(policyMatch.policyId)} />
  else if (serverId !== null && section === '') page = <OverviewPage serverId={serverId} />
  else if (serverId !== null && section === 'hosts') page = <HostsPage serverId={serverId} />
  else if (serverId !== null && section === 'findings') page = <FindingsPage serverId={serverId} />
  else if (serverId !== null && section === 'policies') page = <PoliciesPage serverId={serverId} />
  else if (serverId !== null && section === 'exclusions') page = <ExclusionsPage serverId={serverId} />
  else if (serverId !== null && section === 'netrules') page = <NetRulesPage serverId={serverId} />
  else if (serverId !== null && section === 'changes') page = <ChangesPage serverId={serverId} />
  else if (serverId !== null && section === 'server') page = <ServerPage serverId={serverId} />
  else if (serverId !== null && section === 'snapshots') page = <SnapshotsPage serverId={serverId} />
  else return <Redirect to="/ksc" />

  return (
    <AppShell sidebar={<KscSidebar servers={list} serverId={serverId ?? list[0]?.id ?? null} />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/ksc')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
