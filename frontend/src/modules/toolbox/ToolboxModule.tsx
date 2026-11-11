import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { SectionHeader } from './components/SectionHeader'
import { sectionFor } from './nav'
import { ToolboxSidebar } from './ToolboxSidebar'
import { AliasesPage } from './pages/AliasesPage'
import { Base64Page } from './pages/Base64Page'
import { CronPage } from './pages/CronPage'
import { IpCalcPage } from './pages/IpCalcPage'
import { NewJobForm } from './pages/NewJobForm'
import { ReversePage } from './pages/ReversePage'
import { ScrubJobPage } from './pages/ScrubJobPage'
import { ScrubJobsPage } from './pages/ScrubJobsPage'
import { UnixTimePage } from './pages/UnixTimePage'

/** Маршруты модуля ToolBox — всё под /toolbox. Blindspot (очистка файлов) — на прежних адресах. */
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
  else if (path === '/toolbox/lookup') page = <Redirect to="/search" />
  else if (path === '/toolbox/base64') page = <Base64Page />
  else if (path === '/toolbox/ip') page = <IpCalcPage />
  else if (path === '/toolbox/linux') page = <UnixTimePage />
  else if (path === '/toolbox/linux/cron') page = <CronPage />
  else return <Redirect to="/toolbox" />
  const section = sectionFor(path)

  return (
    <AppShell sidebar={<ToolboxSidebar />}>
      <div className="flex h-full min-h-0 flex-col">
        {section && <SectionHeader section={section} path={path} />}
        <div className="min-h-0 flex-1">
          <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/toolbox')}>
            {page}
          </ErrorBoundary>
        </div>
      </div>
    </AppShell>
  )
}
