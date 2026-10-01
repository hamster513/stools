/** Хуки TanStack Query модуля Assets. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import type { AssetDetail, AssetPatch, AssetsQuery, AssetsResponse, Job, Network, NetworkIn, PinnableField, Zone, ZoneIn } from './types'

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

export function useStartSync() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/assets/sync'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
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

export function useZones() {
  return useQuery<Zone[], ApiRequestError>({ queryKey: ['assets-zones'], queryFn: () => api.get('/api/assets/zones') })
}

export function useCreateZone() {
  return useNetworkMutation<ZoneIn, Zone>((body) => api.post('/api/assets/zones', body))
}

export function useDeleteZone() {
  return useNetworkMutation<string, void>((name) => api.del(`/api/assets/zones/${encodeURIComponent(name)}`))
}
