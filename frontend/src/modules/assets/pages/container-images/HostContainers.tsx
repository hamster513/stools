import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FilterX, Search } from 'lucide-react'
import { api, ApiRequestError, buildQuery } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { Link, useRouter, useSearchParams } from '@/lib/router'
import { FilterChips, FiltersButton, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { DrawerTabs } from '@/platform/tabs/DrawerTabs'
import { FacetRow, FacetSection } from '../AssetsPage'
import { SnapshotInfo } from './SnapshotInfo'
import { CONTAINER_STATES, when, type HostContainer, type HostContainerPage } from './types'

const CATALOG_PATH = { assets: '/assets/container-images', vm: '/vm/images' } as const
type CatalogArea = keyof typeof CATALOG_PATH
const VIEWS = [{ key: 'images', label: 'По образам' }, { key: 'hosts', label: 'По хостам' }]
const PAGE_SIZE = 50
const COLUMNS: ColumnDef[] = [
  { key: 'host', label: 'Хост / IP', width: 160 },
  { key: 'container', label: 'Контейнер / ID', width: 180 },
  { key: 'image', label: 'Образ / digest', width: 244, flex: true },
  { key: 'status', label: 'Состояние', width: 136 },
  { key: 'ports', label: 'Порты хоста → контейнера', width: 144 },
  { key: 'harbor', label: 'Совпадение в Harbor', width: 128 },
  { key: 'collected', label: 'Получено', width: 135 },
]
const FILTERS = [
  { key: 'running_only', label: 'Запущен' },
  { key: 'unmatched_only', label: 'Без подтверждённого совпадения в Harbor' },
] as const
const LINK = 'text-primary underline-offset-2 hover:underline focus-visible:underline'

export function ContainerImageViews({ area, children }: { area: CatalogArea; children: ReactNode }) {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const view = params.get('view') === 'hosts' ? 'hosts' : 'images'
  const path = CATALOG_PATH[area]
  return <div className="flex h-full min-h-0 flex-col">
    <header className="flex shrink-0 flex-wrap items-center gap-x-3 border-b border-grid bg-surface px-4">
      <h1 className="py-2 text-sm font-semibold text-text">Образы контейнеров</h1>
      <DrawerTabs label="Представление каталога" tabs={VIEWS} current={view} onSelect={(key) => {
        if (key !== view) navigate(key === 'hosts' ? `${path}?view=hosts` : path)
      }} />
    </header>
    {view === 'hosts' ? <HostContainers area={area} /> : children}
  </div>
}

function ImageCell({ row, assetsRead }: { row: HostContainer; assetsRead: boolean }) {
  const references = row.references.map((r) => [r.registry, r.repo].filter(Boolean).join('/') + (r.tag ? `:${r.tag}` : '')).filter(Boolean)
  const label = row.image_row_id === null ? 'Образ не определён' : references[0] || row.title || row.image_id || 'Образ не определён'
  return <td className="break-all px-2 py-2">
    {!assetsRead || row.image_row_id === null ? label : <Link className={LINK} to={`/assets/container-images?source=mp_vm&image=${row.image_row_id}`}>{label}</Link>}
    {references.filter((value) => value !== label).map((value, i) => <div className="font-mono" key={i}>{value}</div>)}
    {references.length > 0 && row.references_source === 'image' && <div title="Тег конкретного контейнера в этом снимке не сохранён." className="text-[11px] text-text-secondary">Имена из карточки образа</div>}
    {row.image_id && row.image_id !== label && <div className="select-all font-mono text-[11px] text-text-secondary">{row.image_id}</div>}
  </td>
}

function HostContainerTable({ items, area }: { items: HostContainer[]; area: CatalogArea }) {
  const cols = useColumnWidths(`${area}-host-containers-columns`, COLUMNS)
  const relatedArea = useCan(area === 'vm' ? 'assets' : 'vm')
  const assetsRead = area === 'assets' || relatedArea.read
  const vmRead = area === 'vm' || relatedArea.read
  return <div className="min-h-0 flex-1 overflow-auto">
    <table className="w-full text-left text-xs text-text" style={cols.tableStyle}>
      <caption className="sr-only">Контейнеры на хостах по снимку MaxPatrol VM</caption>
      <ColGroup cols={cols} />
      <thead className="sticky top-0 z-10 border-b border-grid bg-surface text-[11px] text-text-secondary">
        <tr><ResizableHeader cols={cols} className="px-2 py-2" /></tr>
      </thead>
      <tbody>{items.map((row, i) => {
        const c = row.container
        const hostname = row.hostname || row.ip || 'Хост не указан'
        const state = (c.status || '').toLowerCase()
        const status = Object.hasOwn(CONTAINER_STATES, state) ? CONTAINER_STATES[state] : ''
        const artifacts = (row.harbor_images ?? []).map((artifact) => {
          const { id, project, repository } = artifact
          const name = repository.startsWith(project + '/') ? repository : [project, repository].filter(Boolean).join('/')
          return <Link key={id} className={`block break-all ${LINK}`} title={vmRead ? 'Артефакт Harbor и его уязвимости в VM' : 'Карточка артефакта Harbor'}
            to={vmRead ? `/vm/images/${id}` : `/assets/container-images?source=harbor&image=${id}`}>{name} #{id}</Link>
        })
        return <tr key={`${row.hostname}|${row.ip}|${row.image_row_id}|${c.id || i}`} className="border-b border-grid align-top hover:bg-row-hover">
          <td className="break-all px-2 py-2">
            {!assetsRead || row.asset_id === null ? hostname : <Link to={`/assets/list?asset=${row.asset_id}`} className={LINK}>{hostname}</Link>}
            {row.ip && row.ip !== hostname && <div className="font-mono text-text-secondary">{row.ip}</div>}
          </td>
          <td className="break-all px-2 py-2"><div>{c.name || 'Без имени'}</div>{(!c.id || c.id !== c.name) && <div className="select-all font-mono text-[11px] text-text-secondary">{c.id || 'ID не указан'}</div>}</td>
          <ImageCell row={row} assetsRead={assetsRead} />
          <td className="break-words px-2 py-2">{status || c.status || 'Нет данных'}{status && <div className="font-mono text-[11px] text-text-secondary">{c.status}</div>}</td>
          <td className="break-words px-2 py-2 font-mono">{c.ports?.length ? c.ports.map((p, j) => <div key={j}>{p.host_ports || '—'} → {p.container_port || '—'}{p.protocol ? `/${p.protocol}` : ''}</div>) : '—'}</td>
          <td className="px-2 py-2">{row.harbor_matched ? <>Подтверждено
            {artifacts.length > 1 ? <details><summary className="cursor-pointer text-text-secondary">Артефакты ({artifacts.length})</summary>{artifacts}</details> : artifacts}
          </> : 'Не подтверждено'}</td>
          <td className="px-2 py-2 text-text-secondary"><time dateTime={row.collected_at}>{when(row.collected_at)}</time></td>
        </tr>
      })}</tbody>
    </table>
  </div>
}

function HostContainers({ area }: { area: CatalogArea }) {
  const params = useSearchParams()
  const { navigate } = useRouter()
  const path = CATALOG_PATH[area]
  const panel = useFiltersPanel(`${area}-host-containers`)
  const search = params.get('q') || ''
  const q = useDebouncedValue(search, 250)
  const assetId = params.get('asset_id') || undefined
  const requestedOffset = Number(params.get('offset'))
  const offset = Number.isSafeInteger(requestedOffset) && requestedOffset > 0 ? requestedOffset : 0
  const active = (key: string) => ['1', 'true'].includes(params.get(key) || '')
  const args = { q, asset_id: assetId, running_only: active('running_only'), unmatched_only: active('unmatched_only'), limit: PAGE_SIZE, offset }
  const query = useQuery<HostContainerPage, ApiRequestError>({
    queryKey: [`${area}-container-images-by-host`, args],
    queryFn: ({ signal }) => api.get(`/api${path}/by-host${buildQuery(args)}`, { signal }),
    refetchInterval: 60_000,
  })
  function update(key: string, value: string, replace = false) {
    const next = new URLSearchParams(params)
    next.delete('offset')
    if (value) next.set(key, value)
    else next.delete(key)
    navigate(`${path}?${next}`, { replace })
  }
  const data = query.data
  const assetLabel = data?.asset?.name ? `Актив: ${data.asset.name} (#${assetId})` : `Актив #${assetId}`
  const chips: FilterChip[] = FILTERS.filter(({ key }) => active(key)).map(({ key, label }) => ({ label, clear: () => update(key, '') }))
  if (assetId) chips.unshift({ label: assetLabel, clear: () => update('asset_id', '') })
  const hasSearchFilters = !!search || FILTERS.some(({ key }) => active(key))
  const total = data?.total ?? 0
  const previousOffset = Math.max(0, Math.min(offset - PAGE_SIZE, (Math.ceil(total / PAGE_SIZE) - 1) * PAGE_SIZE))
  return <div role="tabpanel" aria-label="По хостам" className="flex min-h-0 flex-1 flex-col">
    <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
      <FiltersButton open={panel.open} onToggle={panel.toggle} count={chips.length} />
      <div className="relative max-w-sm flex-1">
        <Search size={14} aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-secondary" />
        <input aria-label="Поиск контейнеров" placeholder="Хост, IP, контейнер, образ…" value={search} maxLength={200} onChange={(e) => update('q', e.target.value, true)} className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
      </div>
      {(assetId || hasSearchFilters) && <Button variant="ghost" className="text-xs" onClick={() => navigate(`${path}?view=hosts`)}><FilterX size={13} aria-hidden /> Сбросить</Button>}
      <span className="text-xs text-text-secondary">Контейнеров <span className="font-mono tabular-nums">{data ? total : '…'}</span></span>
      {!panel.open && <FilterChips chips={chips} />}
    </header>
    <div className="flex min-h-0 flex-1">
      {panel.open && <aside aria-label="Фильтры контейнеров" className="w-64 max-w-[50%] shrink-0 overflow-y-auto border-r border-grid bg-surface">
        <FacetSection title="Контейнеры">{FILTERS.map(({ key, label }) => <FacetRow key={key} active={active(key)} noCount count={undefined} onClick={() => update(key, active(key) ? '' : 'true')}><span className="block whitespace-normal">{label}</span></FacetRow>)}</FacetSection>
        {assetId && <FacetSection title="Выбранный актив"><FacetRow active noCount count={undefined} onClick={() => update('asset_id', '')}><span className="block break-words whitespace-normal">{assetLabel}</span></FacetRow></FacetSection>}
      </aside>}
      <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
        {data && <SnapshotInfo snapshot={data.mp_vm} />}
        {query.isPending && <FullPageSpinner />}
        {query.isError && <div className="p-4"><ErrorState message={query.error.message} onRetry={() => query.refetch()} /></div>}
        {data && data.items.length > 0 && <HostContainerTable key={offset} items={data.items} area={area} />}
        {data && !data.items.length && !query.isError && <div className="p-6"><EmptyState icon={FilterX}
          title={offset ? 'На странице нет контейнеров' : hasSearchFilters ? 'Ничего не найдено' : 'Контейнеров в снимке нет'}
          description={offset ? 'Вернитесь на предыдущую страницу.' : hasSearchFilters ? 'Ни один контейнер не подходит под выбранные условия.' : assetId ? 'Для выбранного актива в снимке MP VM нет контейнеров.' : 'Здесь появятся контейнеры, полученные при синхронизации MaxPatrol VM.'} /></div>}
        {data && (total > PAGE_SIZE || offset > 0) && <nav aria-label="Страницы контейнеров" className="mt-auto flex shrink-0 flex-wrap items-center gap-2 border-t border-grid bg-surface px-4 py-2 text-xs text-text-secondary">
          <span className="mr-auto font-mono tabular-nums">{data.items.length ? `${offset + 1}–${offset + data.items.length}` : '0'} из {total}</span>
          <Button className="text-xs" disabled={offset === 0} onClick={() => update('offset', previousOffset ? String(previousOffset) : '')}>Назад</Button>
          <Button className="text-xs" disabled={offset + PAGE_SIZE >= total} onClick={() => update('offset', String(offset + PAGE_SIZE))}>Далее</Button>
        </nav>}
      </div>
    </div>
  </div>
}
