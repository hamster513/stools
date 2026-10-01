import type { LucideIcon } from 'lucide-react'
import { Server } from 'lucide-react'
import { Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { EmptyState } from '@/components/ui/EmptyState'
import { AssetsSidebar } from './AssetsSidebar'
import { AssetsPage } from './pages/AssetsPage'
import { JobsPage } from './pages/JobsPage'
import { NetworksPage } from './pages/NetworksPage'
import { SettingsPage } from './pages/SettingsPage'

/** Раздел, у которого ещё нет данных: заголовок и подсказка, откуда они возьмутся. */
function EmptyPage({ title, icon, empty, description }: { title: string; icon: LucideIcon; empty: string; description: string }) {
  return (
    <div className="h-full overflow-y-auto p-6">
      <h1 className="mb-4 text-base font-semibold text-text">{title}</h1>
      <EmptyState icon={icon} title={empty} description={description} />
    </div>
  )
}

/** Маршруты модуля Assets — всё под /assets. Реестр один на платформу, поэтому в адресе нет сервера или домена. */
export function AssetsModule() {
  const { path, navigate } = useRouter()

  let page: React.ReactNode
  if (path === '/assets') {
    page = <EmptyPage title="Обзор" icon={Server} empty="Активов ещё нет" description="Активы появятся после синхронизации с модулями VM, антивируса и AD, скана сети или обновления DNS." />
  } else if (path === '/assets/list') page = <AssetsPage />
  else if (path === '/assets/networks') page = <NetworksPage />
  else if (path === '/assets/settings') page = <SettingsPage />
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
