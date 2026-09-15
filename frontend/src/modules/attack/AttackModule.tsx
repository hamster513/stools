import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { AttackSidebar } from './AttackSidebar'
import { MatrixPage } from './pages/MatrixPage'
import { ChainsPage } from './pages/ChainsPage'
import { RuTtpPage } from './pages/RuTtpPage'
import { SettingsPage } from './pages/SettingsPage'
import { JobsPage } from './pages/JobsPage'

/** Маршруты модуля ATT&CK — всё под /attack. Снапшота у него нет: матрица показывает текущее состояние. */
export function AttackModule() {
  const { path, navigate } = useRouter()
  const section = matchPath('/attack/:section', path)?.section ?? (path === '/attack' ? 'matrix' : null)
  let page: React.ReactNode
  if (section === 'matrix') page = <MatrixPage />
  else if (section === 'chains') page = <ChainsPage />
  else if (section === 'ru') page = <RuTtpPage />
  else if (section === 'settings') page = <SettingsPage />
  else if (section === 'jobs') page = <JobsPage />
  else return <Redirect to="/attack" />
  return (
    <AppShell sidebar={<AttackSidebar />}>
      <ErrorBoundary key={path} resetLabel="Показать снова" onReset={() => navigate('/attack')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}
