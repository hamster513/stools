/** Хуки TanStack Query модуля Assets. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import type {
  AdConnectionRef, AssetDetail, AssetPatch, AssetSettings, AssetsOverview, AssetsQuery, AssetsResponse, BulkPatch, DnsIn, DnsServer, Job, Network, NetworkIn,
  NetworkSchedule, PinnableField, ScanStarted, ScheduleIn, SyncStatus, Zone, ZoneIn,
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
    queryKey: ['assets-list', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`/api/assets/assets${buildQuery({ ...query, limit: ASSETS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
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
  return useQuery<AssetsOverview, ApiRequestError>({ queryKey: ['assets-overview'], queryFn: () => api.get('/api/assets/overview') })
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

export function useNetworks() {
  return useQuery<Network[], ApiRequestError>({ queryKey: ['assets-networks'], queryFn: () => api.get('/api/assets/networks') })
}

/** Сеть изменилась — активы могли переехать в другую сеть: обновить и список, и карточку, и зоны (счётчик сетей). */
function useNetworkMutation<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation<R, ApiRequestError, V>({
    mutationFn: fn,
    onSuccess: () => {
      for (const key of ['assets-networks', 'assets-zones', 'assets-list', 'assets-asset']) qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

export function useSaveNetwork() {
  return useNetworkMutation<{ id?: number; body: NetworkIn }, Network>(({ id, body }) =>
    id === undefined ? api.post('/api/assets/networks', body) : api.put(`/api/assets/networks/${id}`, body),
  )
}

export function useDeleteNetwork() {
  return useNetworkMutation<number, void>((id) => api.del(`/api/assets/networks/${id}`))
}

/** Скан сети сейчас; за задачей следит страница через `useJob`. */
export function useStartScan() {
  const qc = useQueryClient()
  return useMutation<ScanStarted, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/assets/networks/${id}/scan`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
  })
}

export function useSaveSchedule(networkId: number) {
  return useNetworkMutation<ScheduleIn, NetworkSchedule>((body) => api.put(`/api/assets/networks/${networkId}/schedule`, body))
}

export function useDeleteSchedule(networkId: number) {
  return useNetworkMutation<void, void>(() => api.del(`/api/assets/networks/${networkId}/schedule`))
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

export function useSaveDnsSchedule(dnsId: number) {
  return useDnsMutation<ScheduleIn, NetworkSchedule>((body) => api.put(`/api/assets/dns/${dnsId}/schedule`, body))
}

export function useDeleteDnsSchedule(dnsId: number) {
  return useDnsMutation<void, void>(() => api.del(`/api/assets/dns/${dnsId}/schedule`))
}
