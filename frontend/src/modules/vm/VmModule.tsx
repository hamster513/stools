import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { VmSidebar } from './VmSidebar'
import { OverviewPage } from './pages/OverviewPage'
import { VulnsPage } from './pages/VulnsPage'
import { JobsPage } from './pages/JobsPage'

/** Маршруты модуля VM — всё под /vm. Сессию платформа уже проверила. */
export function VmModule() {
  const { path, navigate } = useRouter()
  const section = path.split('/')[2] ?? ''

  let page: React.ReactNode
  if (section === '') page = <OverviewPage />
  else if (section === 'vulns') page = <VulnsPage />
  else if (section === 'jobs') page = <JobsPage />
  else return <Redirect to="/vm" />

  return (
    <AppShell sidebar={<VmSidebar />}>
      <ErrorBoundary key={section} resetLabel="Показать снова" onReset={() => navigate('/vm')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
