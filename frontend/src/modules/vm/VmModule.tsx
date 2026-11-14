import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { VmSidebar } from './VmSidebar'
import { OverviewPage } from './pages/OverviewPage'
import { VulnsPage } from './pages/VulnsPage'
import { ImagesPage } from './pages/ImagesPage'
import { ImagePage } from './pages/ImagePage'
import { JobsPage } from './pages/JobsPage'
import { CveSearchPage } from './pages/CveSearchPage'
import { TrendsPage } from './pages/TrendsPage'

/** Маршруты модуля VM — всё под /vm. Сессию платформа уже проверила. */
export function VmModule() {
  const { path, navigate } = useRouter()
  const [, , section = '', sub = ''] = path.split('/')

  let page: React.ReactNode
  if (section === '') page = <OverviewPage />
  else if (section === 'cve') page = <CveSearchPage />
  else if (section === 'vulns') page = <VulnsPage />
  else if (section === 'images' && sub === '') page = <ImagesPage />
  else if (section === 'images' && /^\d+$/.test(sub)) page = <ImagePage id={Number(sub)} />
  else if (section === 'jobs') page = <JobsPage />
  else if (section === 'trends') page = <TrendsPage />
  else return <Redirect to="/vm" />

  return (
    <AppShell sidebar={<VmSidebar />}>
      {/* Страница образа — своя граница: сбой карточки не держит ошибку на списке. */}
      <ErrorBoundary key={`${section}/${sub}`} resetLabel="Показать снова" onReset={() => navigate('/vm')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
