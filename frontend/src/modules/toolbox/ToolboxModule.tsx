import { Construction } from 'lucide-react'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { EmptyState } from '@/components/ui/EmptyState'
import { ToolboxSidebar } from './ToolboxSidebar'
import { NewJobForm } from './pages/NewJobForm'
import { ScrubJobPage } from './pages/ScrubJobPage'
import { ScrubJobsPage } from './pages/ScrubJobsPage'

const SOON: Record<string, string> = {
  '/toolbox/reverse': 'Обратный перевод',
  '/toolbox/aliases': 'Соответствия',
  '/toolbox/settings': 'Настройки',
}

/** Разделы, которых ещё нет: ссылки сайдбара ведут сюда, а не обратно в список. */
function SoonPage({ title }: { title: string }) {
  return (
    <div className="p-6">
      <h1 className="mb-4 text-base font-semibold text-text">{title}</h1>
      <EmptyState icon={Construction} title="Скоро" description="Раздел появится в следующей версии модуля." />
    </div>
  )
}

/** Маршруты модуля ToolBox — всё под /toolbox. */
export function ToolboxModule() {
  const { path, navigate } = useRouter()
  const job = matchPath('/toolbox/scrub/:id', path)
  const jobId = job && /^\d+$/.test(job.id) ? Number(job.id) : null

  let page: React.ReactNode
  if (path === '/toolbox') page = <ScrubJobsPage />
  else if (path === '/toolbox/scrub/new') page = <NewJobForm />
  else if (jobId !== null) page = <ScrubJobPage id={jobId} />
  else if (SOON[path]) page = <SoonPage title={SOON[path]} />
  else return <Redirect to="/toolbox" />

  return (
    <AppShell sidebar={<ToolboxSidebar />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/toolbox')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
