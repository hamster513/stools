import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { ToolboxSidebar } from './ToolboxSidebar'
import { AliasesPage } from './pages/AliasesPage'
import { NewJobForm } from './pages/NewJobForm'
import { ReversePage } from './pages/ReversePage'
import { ScrubJobPage } from './pages/ScrubJobPage'
import { ScrubJobsPage } from './pages/ScrubJobsPage'
import { SettingsPage } from './pages/SettingsPage'

/** Маршруты модуля ToolBox — всё под /toolbox. */
export function ToolboxModule() {
  const { path, navigate } = useRouter()
  const job = matchPath('/toolbox/scrub/:id', path)
  const jobId = job && /^\d+$/.test(job.id) ? Number(job.id) : null

  let page: React.ReactNode
  if (path === '/toolbox') page = <ScrubJobsPage />
  else if (path === '/toolbox/scrub/new') page = <NewJobForm />
  else if (jobId !== null) page = <ScrubJobPage id={jobId} />
  else if (path === '/toolbox/reverse') page = <ReversePage />
  else if (path === '/toolbox/aliases') page = <AliasesPage />
  else if (path === '/toolbox/settings') page = <SettingsPage />
  else return <Redirect to="/toolbox" />

  return (
    <AppShell sidebar={<ToolboxSidebar />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/toolbox')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
