import { useDomains } from '@/modules/ad/api/queries'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { AdSidebar } from './AdSidebar'
import { OverviewPage } from './pages/OverviewPage'
import { SummaryPage } from './pages/SummaryPage'
import { FindingsPage } from './pages/FindingsPage'
import { SnapshotsPage } from './pages/SnapshotsPage'
import { JobsPage } from './pages/JobsPage'

/** Маршруты модуля AD — всё под /ad. Домен — в адресе, как снапшот у SIEM. */
export function AdModule() {
  const { path, navigate } = useRouter()
  const domains = useDomains()
  if (domains.isLoading) return <FullPageSpinner />
  const list = domains.data ?? []

  const domainMatch = matchPath('/ad/domains/:id', path) ?? matchPath('/ad/domains/:id/:section', path)
  const domainId = domainMatch ? Number(domainMatch.id) : null
  const section = domainMatch?.section ?? ''

  let page: React.ReactNode
  if (path === '/ad') {
    return <Redirect to={list.length ? `/ad/domains/${list[0].id}` : '/settings/ad'} />
  } else if (path === '/ad/jobs') page = <JobsPage />
  else if (domainId !== null && section === '') page = <OverviewPage domainId={domainId} />
  else if (domainId !== null && section === 'summary') page = <SummaryPage domainId={domainId} />
  else if (domainId !== null && section === 'findings') page = <FindingsPage domainId={domainId} />
  else if (domainId !== null && section === 'snapshots') page = <SnapshotsPage domainId={domainId} />
  else return <Redirect to="/ad" />

  return (
    <AppShell sidebar={<AdSidebar domains={list} domainId={domainId ?? list[0]?.id ?? null} />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/ad')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
