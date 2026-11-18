import { LIST_QUERY_OPTIONS } from '@/api/listCache'
/** Хуки TanStack Query модуля Assets. */
import { useInfiniteQuery, useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import { FINDING_SUMMARY_KEY, FINDINGS_MINE_KEY } from '@/platform/findings/queries'
import type { FindingSummary } from '@/platform/findings/types'
import type {
  AdConnectionRef, AssetDetail, AssetPatch, AssetSettings, AssetsOverview, AssetsQuery, AssetsResponse, BulkPatch, DiscrepancyBulk, DnsIn, DnsServer, GroupDetail, GroupExpanded,
  GroupsQuery, GroupsResponse, Job, Network, NetworkIn, NetworkList, NetworksQuery,
  NetworkSchedule, PinnableField, Racktables, RacktablesIn, ScheduleIn, SyncStatus, UserDetail, UserPatch, UsersQuery, UsersResponse, Zone, ZoneIn,
  ZonePatch, ZoneRule, ZoneRuleIn, ZoneRulePreview,
} from './types'

export const ASSETS_PAGE_SIZE = 200

export function useJobs() {
  return useQuery<Job[], ApiRequestError>({
    queryKey: ['assets-jobs'],
    queryFn: () => api.get('/api/assets/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/assets/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
  })
}

export function useAssets(query: AssetsQuery) {
  return useInfiniteQuery<AssetsResponse, ApiRequestError>({
    ...LIST_QUERY_OPTIONS,
    queryKey: ['assets-list', query],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => api.get(`/api/assets/assets${buildQuery({ ...query, limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`, { signal }),
    getNextPageParam: nextPageOffset,
  })
}

export function useAsset(id: number | null) {
  return useQuery<AssetDetail, ApiRequestError>({
    queryKey: ['assets-asset', id],
    queryFn: () => api.get(`/api/assets/assets/${id}`),
    enabled: id !== null,
  })
}

/** После любого действия с активом меняются и карточка, и список (фасеты, число расхождений). */
function useAssetMutation<V>(fn: (vars: V) => Promise<AssetDetail>) {
  const qc = useQueryClient()
  return useMutation<AssetDetail, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: (detail) => {
      qc.setQueryData(['assets-asset', detail.id], detail)
      qc.invalidateQueries({ queryKey: ['assets-list'] })
      qc.invalidateQueries({ queryKey: ['assets-asset'] })
    },
  })
}

export function usePatchAsset(id: number) {
  return useAssetMutation<AssetPatch>((body) => api.patch(`/api/assets/assets/${id}`, body))
}

export function usePinField(id: number) {
  return useAssetMutation<{ field: PinnableField; pinned: boolean }>((body) => api.post(`/api/assets/assets/${id}/pin`, body))
}

export function useMergeAssets(id: number) {
  return useAssetMutation<number>((otherId) => api.post(`/api/assets/assets/${id}/merge`, { other_id: otherId }))
}

export function useDetachObservation() {
  return useAssetMutation<number>((observationId) => api.post(`/api/assets/observations/${observationId}/detach`))
}

export function useUsers(query: UsersQuery) {
  return useInfiniteQuery<UsersResponse, ApiRequestError>({
    queryKey: ['assets-users', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`/api/assets/users${buildQuery({ ...query, limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
  })
}

export function useUser(id: number | null) {
  return useQuery<UserDetail, ApiRequestError>({
    queryKey: ['assets-user', id],
    queryFn: () => api.get(`/api/assets/users/${id}`),
    enabled: id !== null,
  })
}

/** Ручные поля пользователя (заметка, теги): в списке их нет — обновляется только карточка, из ответа. */
export function usePatchUser(id: number) {
  const qc = useQueryClient()
  return useMutation<UserDetail, ApiRequestError, UserPatch>({
    mutationFn: (body) => api.patch(`/api/assets/users/${id}`, body),
    onSuccess: (detail) => qc.setQueryData(['assets-user', detail.id], detail),
  })
}

export function useGroups(query: GroupsQuery) {
  return useInfiniteQuery<GroupsResponse, ApiRequestError>({
    queryKey: ['assets-groups', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`/api/assets/groups${buildQuery({ ...query, limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
  })
}

export function useGroup(id: number | null) {
  return useQuery<GroupDetail, ApiRequestError>({
    queryKey: ['assets-group', id],
    queryFn: () => api.get(`/api/assets/groups/${id}`),
    enabled: id !== null,
  })
}

/** Полный состав группы постранично; запрашивается, только когда блок раскрыт (`enabled`). */
export function useGroupExpanded(id: number | null, enabled: boolean) {
  return useInfiniteQuery<GroupExpanded, ApiRequestError>({
    queryKey: ['assets-group-expanded', id],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`/api/assets/groups/${id}/expanded${buildQuery({ limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: id !== null && enabled,
  })
}

/** Удалённые карточки не перезапрашиваются (иначе 404 в консоли), а забываются; список и обзор — обновляются. */
function forgetDeleted(qc: ReturnType<typeof useQueryClient>, ids: number[]) {
  for (const id of ids) qc.removeQueries({ queryKey: ['assets-asset', id] })
  for (const key of ['assets-list', 'assets-overview']) qc.invalidateQueries({ queryKey: [key] })
}

export function useDeleteAsset() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/assets/assets/${id}`),
    onSuccess: (_void, id) => forgetDeleted(qc, [id]),
  })
}

export function useBulkDelete() {
  const qc = useQueryClient()
  return useMutation<{ deleted: number }, ApiRequestError, number[]>({
    mutationFn: (ids) => api.post('/api/assets/assets/bulk-delete', { ids }),
    onSuccess: (_result, ids) => forgetDeleted(qc, ids),
  })
}

/** Id всех активов под фильтрами списка — выбор «всех по фильтру», а не только загруженных строк. */
export function useAssetIds() {
  return useMutation<{ total: number; ids: number[] }, ApiRequestError, AssetsQuery>({
    mutationFn: (query) => api.get(`/api/assets/assets/ids${buildQuery({ ...query })}`),
  })
}

export function useBulkUpdate() {
  const qc = useQueryClient()
  return useMutation<{ updated: number }, ApiRequestError, BulkPatch>({
    mutationFn: (body) => api.post('/api/assets/assets/bulk', body),
    onSuccess: () => {
      for (const key of ['assets-list', 'assets-asset', 'assets-overview']) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

/** Статус расхождения у отмеченных активов; меняет списки, карточки, обзор и сводки статусов. */
export function useDiscrepancyBulk() {
  const qc = useQueryClient()
  return useMutation<{ changed: number }, ApiRequestError, DiscrepancyBulk>({
    mutationFn: (body) => api.post('/api/assets/assets/discrepancies/bulk', body),
    onSuccess: () => invalidateDiscrepancies(qc),
  })
}

/** После смены статуса расхождения: список, карточки, обзор, состояния находок, сводка и «Мои находки». */
export function invalidateDiscrepancies(qc: ReturnType<typeof useQueryClient>) {
  for (const key of ['assets-list', 'assets-asset', 'assets-overview', 'finding-state', FINDING_SUMMARY_KEY, FINDINGS_MINE_KEY]) {
    qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useStartSync() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/assets/sync'),
    onSuccess: () => {
      for (const key of ['assets-jobs', 'assets-sync-status', 'assets-overview']) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

export function useSyncStatus() {
  return useQuery<SyncStatus, ApiRequestError>({ queryKey: ['assets-sync-status'], queryFn: () => api.get('/api/assets/sync/status') })
}

export function useSyncSchedule() {
  return useQuery<NetworkSchedule | null, ApiRequestError>({ queryKey: ['assets-sync-schedule'], queryFn: () => api.get('/api/assets/sync/schedule') })
}

function useSyncScheduleMutation<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation<R, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-sync-schedule'] }),
  })
}

export function useSaveSyncSchedule() {
  return useSyncScheduleMutation<ScheduleIn, NetworkSchedule>((body) => api.put('/api/assets/sync/schedule', body))
}

export function useDeleteSyncSchedule() {
  return useSyncScheduleMutation<void, void>(() => api.del('/api/assets/sync/schedule'))
}

export function useOverview() {
  return useQuery<AssetsOverview, ApiRequestError>({ ...LIST_QUERY_OPTIONS, queryKey: ['assets-overview'], queryFn: ({ signal }) => api.get('/api/assets/overview', { signal }) })
}

/** Сводка статусов расхождений (`/api/findings/summary`, module `assets`): строка под плитками обзора. */
export function useDiscrepancySummary() {
  return useQuery<FindingSummary, ApiRequestError>({
    queryKey: [FINDING_SUMMARY_KEY, 'assets', 0],
    queryFn: () => api.get('/api/findings/summary?module=assets&scope_id=0'),
  })
}

export function useAssetSettings() {
  return useQuery<AssetSettings, ApiRequestError>({ queryKey: ['assets-settings'], queryFn: () => api.get('/api/assets/settings') })
}

/** Пороги меняют расхождения у всех активов: обновить и список, и карточку, и обзор. */
export function useSaveAssetSettings() {
  const qc = useQueryClient()
  return useMutation<AssetSettings, ApiRequestError, AssetSettings>({
    mutationFn: (body) => api.put('/api/assets/settings', body),
    onSuccess: (saved) => {
      qc.setQueryData(['assets-settings'], saved)
      for (const key of ['assets-list', 'assets-asset', 'assets-overview']) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

/**
 * Актив хоста другого модуля (ссылка «в Assets»): KSC — `server_id:host_id`, VM — `hostname|ip`.
 * 404 — хост не сопоставлен: это не ошибка, а «ссылки нет», поэтому без повторов.
 */
export function useAssetLookup(source: 'ksc' | 'vm', key: string | null) {
  return useQuery<{ asset_id: number }, ApiRequestError>({
    queryKey: ['assets-lookup', source, key],
    queryFn: () => api.get(`/api/assets/lookup${buildQuery({ source, key: key ?? '' })}`),
    enabled: key !== null,
    retry: false,
    staleTime: 60_000,
  })
}

/** Задача, за которой следит страница (синхронизация, запущенная кнопкой): опрос, пока идёт. */
export function useJob(id: number | null) {
  return useQuery<Job, ApiRequestError>({
    queryKey: ['assets-job', id],
    queryFn: () => api.get(`/api/assets/jobs/${id}`),
    enabled: id !== null,
    refetchInterval: (q) => (q.state.data?.status === 'running' || !q.state.data ? 1500 : false),
  })
}

/** Список сетей по страницам (сетей тысячи): поиск и фасеты — на сервере. */
export function useNetworkList(query: NetworksQuery) {
  return useInfiniteQuery<NetworkList, ApiRequestError>({
    queryKey: ['assets-networks', 'list', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`/api/assets/networks${buildQuery({ ...query, limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
  })
}

/** Сколько сетей показывает выбор сети: первые совпадения поиска, а не весь список. */
export const NETWORK_PICK_LIMIT = 50

/** Выбор сети: первые совпадения поиска (адрес, имя, тег, VLAN); пустой поиск — ничего не запрашивает. */
export function useNetworkSearch(q: string) {
  return useQuery<NetworkList, ApiRequestError>({
    queryKey: ['assets-networks', 'search', q],
    queryFn: () => api.get(`/api/assets/networks${buildQuery({ q, limit: NETWORK_PICK_LIMIT })}`),
    enabled: q !== '',
    placeholderData: (prev) => prev,
  })
}

/** Карточка сети: CIDR, группа и «почему», признаки, теги, объемлющие и вложенные. */
export function useNetwork(id: number | null) {
  return useQuery<Network, ApiRequestError>({ queryKey: ['assets-networks', id], queryFn: () => api.get(`/api/assets/networks/${id}`), enabled: id !== null })
}

/** Карточки нескольких сетей (подписи выбранных в фильтре) — тот же кэш, что у useNetwork. */
export function useNetworkCards(ids: number[]): Map<number, Network> {
  const results = useQueries({
    queries: ids.map((id) => ({ queryKey: ['assets-networks', id], queryFn: (): Promise<Network> => api.get(`/api/assets/networks/${id}`) })),
  })
  const out = new Map<number, Network>()
  for (const r of results) if (r.data) out.set(r.data.id, r.data)
  return out
}

/** Группа сети меняет расположение хостов: после правки сети, группы или правил обновить и сети, и активы. */
const NETWORK_KEYS = ['assets-networks', 'assets-zones', 'assets-zone-rules', 'assets-list', 'assets-asset']

/** Сеть изменилась — активы могли переехать в другую сеть: обновить и список, и карточку, и зоны (счётчик сетей). */
function useNetworkMutation<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation<R, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: () => {
      for (const key of NETWORK_KEYS) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

export function useSaveNetwork() {
  return useNetworkMutation<{ id?: number; body: NetworkIn }, Network>(({ id, body }) =>
    id === undefined ? api.post('/api/assets/networks', body) : api.put(`/api/assets/networks/${id}`, body),
  )
}

/** Удалённая карточка не перезапрашивается (иначе 404), а забывается. */
export function useDeleteNetwork() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/assets/networks/${id}`),
    onSuccess: (_void, id) => {
      qc.removeQueries({ queryKey: ['assets-networks', id] })
      for (const key of NETWORK_KEYS) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

export function useZones() {
  return useQuery<Zone[], ApiRequestError>({ queryKey: ['assets-zones'], queryFn: () => api.get('/api/assets/zones') })
}

export function useCreateZone() {
  return useNetworkMutation<ZoneIn, Zone>((body) => api.post('/api/assets/zones', body))
}

export function useDeleteZone() {
  return useNetworkMutation<string, void>((name) => api.del(`/api/assets/zones/${encodeURIComponent(name)}`))
}

/** Признаки и подписи группы сетей: меняют расположение у сетей и хостов. */
export function usePatchZone() {
  return useNetworkMutation<{ name: string; body: ZonePatch }, Zone>(({ name, body }) => api.patch(`/api/assets/zones/${encodeURIComponent(name)}`, body))
}

export function useZoneRules() {
  return useQuery<ZoneRule[], ApiRequestError>({ queryKey: ['assets-zone-rules'], queryFn: () => api.get('/api/assets/networks/zone-rules') })
}

/** Любая правка правил пересчитывает группы всех не ручных сетей. */
export function useSaveZoneRule() {
  return useNetworkMutation<{ id?: number; body: ZoneRuleIn }, ZoneRule>(({ id, body }) =>
    id === undefined ? api.post('/api/assets/networks/zone-rules', body) : api.put(`/api/assets/networks/zone-rules/${id}`, body),
  )
}

export function useDeleteZoneRule() {
  return useNetworkMutation<number, void>((id) => api.del(`/api/assets/networks/zone-rules/${id}`))
}

/** Новый порядок — id всех правил. */
export function useReorderZoneRules() {
  return useNetworkMutation<number[], ZoneRule[]>((ids) => api.put('/api/assets/networks/zone-rules/order', ids))
}

/** Проверка до сохранения: сколько не ручных сетей забрало бы правило на месте `position` (без него — в конце). */
export function usePreviewZoneRule() {
  return useMutation<ZoneRulePreview, ApiRequestError, { match: string; value: string; zone: string; position?: number }>({
    mutationFn: (body) => api.post('/api/assets/networks/zone-rules/preview', body),
  })
}

export function useApplyZoneRules() {
  return useNetworkMutation<void, { changed: number }>(() => api.post('/api/assets/networks/zone-rules/apply'))
}

export function useDnsServers() {
  return useQuery<DnsServer[], ApiRequestError>({ queryKey: ['assets-dns'], queryFn: () => api.get('/api/assets/dns') })
}

/** Подключения AD для режима «зоны AD»: тот же запрос, что у модуля AD. */
export function useAdConnections() {
  return useQuery<AdConnectionRef[], ApiRequestError>({ queryKey: ['ad-connections'], queryFn: () => api.get('/api/ad/connections') })
}

function useDnsMutation<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation<R, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-dns'] }),
  })
}

export function useSaveDns() {
  return useDnsMutation<{ id?: number; body: DnsIn }, DnsServer>(({ id, body }) =>
    id === undefined ? api.post('/api/assets/dns', body) : api.put(`/api/assets/dns/${id}`, body),
  )
}

export function useDeleteDns() {
  return useDnsMutation<number, void>((id) => api.del(`/api/assets/dns/${id}`))
}

/** Обновление через DNS сейчас; за задачей следит страница через `useJob`. */
export function useRunDns() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/assets/dns/${id}/run`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
  })
}

export function useRacktables() {
  return useQuery<Racktables[], ApiRequestError>({ queryKey: ['assets-racktables'], queryFn: () => api.get('/api/assets/racktables') })
}

function useRacktablesMutation<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation<R, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-racktables'] }),
  })
}

export function useSaveRacktables() {
  return useRacktablesMutation<{ id?: number; body: RacktablesIn }, Racktables>(({ id, body }) =>
    id === undefined ? api.post('/api/assets/racktables', body) : api.put(`/api/assets/racktables/${id}`, body),
  )
}

export function useDeleteRacktables() {
  return useRacktablesMutation<number, void>((id) => api.del(`/api/assets/racktables/${id}`))
}

/** `getAPIVersion` сохранёнными учётными данными — проверка адреса и пароля. */
export function useCheckRacktables() {
  return useMutation<{ version: string }, ApiRequestError, number>({ mutationFn: (id) => api.post(`/api/assets/racktables/${id}/check`) })
}

/** Проход по RackTables сейчас; за задачей следит страница через `useJob`. */
export function useRunRacktables() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/assets/racktables/${id}/run`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
  })
}

export function useSaveRacktablesSchedule(rtId: number) {
  return useRacktablesMutation<ScheduleIn, NetworkSchedule>((body) => api.put(`/api/assets/racktables/${rtId}/schedule`, body))
}

export function useDeleteRacktablesSchedule(rtId: number) {
  return useRacktablesMutation<void, void>(() => api.del(`/api/assets/racktables/${rtId}/schedule`))
}

export function useSaveDnsSchedule(dnsId: number) {
  return useDnsMutation<ScheduleIn, NetworkSchedule>((body) => api.put(`/api/assets/dns/${dnsId}/schedule`, body))
}

export function useDeleteDnsSchedule(dnsId: number) {
  return useDnsMutation<void, void>(() => api.del(`/api/assets/dns/${dnsId}/schedule`))
}
