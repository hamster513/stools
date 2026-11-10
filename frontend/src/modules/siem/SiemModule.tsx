import type { ReactNode } from 'react'
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
import { FindingPage } from './hunting/pages/FindingPage'
import { FindingsPage } from './hunting/pages/FindingsPage'
import { HuntPage } from './hunting/pages/HuntPage'
import { IntelSection } from './hunting/pages/settings/IntelSection'
import { LibraryPage } from './hunting/pages/LibraryPage'
import { DeepHuntPage } from './hunting/pages/DeepHuntPage'
import { DeepPage } from './hunting/pages/DeepPage'
import { RunsPage } from './hunting/pages/RunsPage'
import { SchedulerPage } from './hunting/pages/SchedulerPage'

const SECTIONS = new Set(['overview', 'rules', 'clones', 'attack', 'profile', 'hygiene'])

function latestOf(snapshots: SnapshotListItem[]): SnapshotListItem | null {
  return snapshots.length > 0 ? snapshots.reduce((a, b) => (b.id > a.id ? b : a), snapshots[0]) : null
}

/** Маршруты модуля SIEM — всё под /siem. Сессию платформа уже проверила. */
export function SiemModule() {
  const { path, navigate } = useRouter()

  // Threat Hunting не привязан к снапшоту правил.
  if (path === '/siem/hunting' || path.startsWith('/siem/hunting/')) {
    return <HuntingRoute />
  }

  // Ссылка на находку из «Моих находок» не знает снапшота: `?key=` открывается на актуальном.
  if (path === '/siem/hygiene') {
    return <HygieneRedirect />
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
 * Раздел Threat Hunting. Ссылки группы «SIEM Rules Analyzer» в сайдбаре ведут на последний
 * снапшот — он нужен только им: пока список снапшотов грузится, раздел уже открыт, а группа неактивна.
 */
function HuntingRoute() {
  const { path, search, navigate } = useRouter()
  const { data: snapshots } = useSnapshots()
  const latest = snapshots ? latestOf(snapshots) : null

  let section: string
  let page: ReactNode
  const finding = matchPath('/siem/hunting/findings/:id', path)
  const hunt = matchPath('/siem/hunting/library/:id', path)
  const deep = matchPath('/siem/hunting/deep/:id', path)
  const run = matchPath('/siem/hunting/runs/:id', path)
  if (path === '/siem/hunting') {
    // Фильтры страницы стартуют из адреса: смена строки запроса (ссылка «все находки ханта») открывает её заново.
    section = `findings${search}`
    page = <FindingsPage key={search} />
  } else if (finding) {
    section = `finding-${finding.id}`
    page = <FindingPage id={Number(finding.id)} />
  } else if (path === '/siem/hunting/materials') {
    section = path
    page = <div className="h-full overflow-y-auto p-6"><div className="max-w-4xl"><IntelSection /></div></div>
  } else if (path === '/siem/hunting/library') {
    section = path
    page = <LibraryPage />
  } else if (hunt) {
    section = path
    page = <HuntPage id={hunt.id === 'new' ? 'new' : Number(hunt.id)} />
  } else if (path === '/siem/hunting/deep') {
    // Адрес с `?from=<запрос>` открывает форму с подстановкой: смена строки запроса собирает страницу заново.
    section = `deep${search}`
    page = <DeepPage key={search} />
  } else if (deep) {
    section = path
    page = <DeepHuntPage id={Number(deep.id)} />
  } else if (path === '/siem/hunting/scheduler') {
    section = path
    page = <SchedulerPage />
  } else if (path === '/siem/hunting/runs') {
    // Список ночей переехал в планировщик (блок «История ночей»): старые закладки ведут туда.
    return <Redirect to="/siem/hunting/scheduler" />
  } else if (run) {
    section = path
    page = <RunsPage id={Number(run.id)} />
  } else {
    return <Redirect to="/siem/hunting" />
  }

  return (
    <AppShell sidebar={<SiemSidebar snapshotId={latest?.id ?? null} />}>
      <ErrorBoundary key={section} resetLabel="Показать снова" onReset={() => navigate('/siem/hunting')}>
        {page}
      </ErrorBoundary>
    </AppShell>
  )
}

/** `/siem/hygiene?key=…` — находки активного снапшота (последнего разобранного:
 *  статусы сверяются с ним) с той же строкой запроса. */
function HygieneRedirect() {
  const { search } = useRouter()
  const { data: snapshots, isLoading } = useSnapshots()

  if (isLoading || !snapshots) return <FullPageSpinner />

  const latest = latestOf(snapshots.filter((s) => s.parsed)) ?? latestOf(snapshots)
  return <Redirect to={latest ? `/siem/snapshots/${latest.id}/hygiene${search}` : '/settings/siem'} />
}

/** `/siem` и неизвестные пути модуля ведут на актуальный снапшот или на загрузку. */
function SiemRootRedirect() {
  const { data: snapshots, isLoading } = useSnapshots()

  if (isLoading || !snapshots) return <FullPageSpinner />

  const latest = latestOf(snapshots)
  return <Redirect to={latest ? `/siem/snapshots/${latest.id}/rules` : '/settings/siem'} />
}
