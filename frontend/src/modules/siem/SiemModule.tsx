import { useSnapshots } from '@/modules/siem/api/queries'
import { matchPath, Redirect, useRouter } from '@/lib/router'
import { AppShell } from '@/components/layout/AppShell'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { FullPageSpinner } from '@/components/ui/Spinner'
import type { SnapshotListItem } from '@/modules/siem/api/types'
import { SiemSidebar } from './SiemSidebar'
import { HygienePage } from './pages/HygienePage'
import { OverviewPage } from './pages/OverviewPage'
import { RulesPage } from './pages/RulesPage'
import { ClonesPage } from './pages/ClonesPage'
import { ProfilePage } from './pages/ProfilePage'
import { AttackPage } from './pages/AttackPage'
import { SettingsPage } from './pages/SettingsPage'

const SECTIONS = new Set(['overview', 'rules', 'clones', 'attack', 'profile', 'hygiene'])

function latestOf(snapshots: SnapshotListItem[]): SnapshotListItem | null {
  return snapshots.length > 0 ? snapshots.reduce((a, b) => (b.id > a.id ? b : a)) : null
}

/** Маршруты модуля SIEM — всё под /siem. Сессию платформа уже проверила. */
export function SiemModule() {
  const { path, navigate } = useRouter()

  // Загрузки собраны в настройках. Прежний адрес /upload остаётся рабочим:
  // на него ведут закладки и ссылки в чужих инструкциях.
  if (path === '/siem/settings' || path === '/siem/upload') {
    return <SettingsRoute />
  }

  const match = matchPath('/siem/snapshots/:id/:section', path)
  if (match && SECTIONS.has(match.section)) {
    const snapshotId = Number(match.id)
    const section = match.section
    return (
      <AppShell sidebar={<SiemSidebar snapshotId={snapshotId} />}>
        {/* Ловушка внутри оболочки: ошибка раздела не должна уносить
            навигацию — иначе из пустого экрана некуда деться.
            Ключ по разделу сбрасывает состояние при переходе. */}
        <ErrorBoundary
          key={section}
          resetLabel="Показать снова"
          onReset={() => navigate(`/siem/snapshots/${snapshotId}/overview`)}
        >
          {section === 'hygiene' && <HygienePage snapshotId={snapshotId} />}
          {section === 'overview' && <OverviewPage snapshotId={snapshotId} />}
          {section === 'rules' && <RulesPage snapshotId={snapshotId} />}
          {section === 'clones' && <ClonesPage snapshotId={snapshotId} />}
          {section === 'attack' && <AttackPage snapshotId={snapshotId} />}
          {section === 'profile' && <ProfilePage snapshotId={snapshotId} />}
        </ErrorBoundary>
      </AppShell>
    )
  }

  return <SiemRootRedirect />
}

/**
 * Настройки не привязаны к снапшоту — адрес модели один на инсталляцию, —
 * но показываются в оболочке. Снапшот для сайдбара берётся последний,
 * только чтобы ссылки разделов вели куда-то осмысленно; без выгрузок
 * сайдбар остаётся с неактивными разделами — видно, что здесь будет.
 */
function SettingsRoute() {
  const { navigate } = useRouter()
  const { data: snapshots, isLoading } = useSnapshots()

  if (isLoading) return <FullPageSpinner />

  const latest = snapshots ? latestOf(snapshots) : null

  return (
    <AppShell sidebar={<SiemSidebar snapshotId={latest?.id ?? null} />}>
      <ErrorBoundary resetLabel="Показать снова" onReset={() => navigate('/siem/settings')}>
        <SettingsPage />
      </ErrorBoundary>
    </AppShell>
  )
}

/** `/siem` и неизвестные пути модуля ведут на актуальный снапшот или на загрузку. */
function SiemRootRedirect() {
  const { data: snapshots, isLoading } = useSnapshots()

  if (isLoading || !snapshots) return <FullPageSpinner />

  const latest = latestOf(snapshots)
  return <Redirect to={latest ? `/siem/snapshots/${latest.id}/rules` : '/siem/settings'} />
}
