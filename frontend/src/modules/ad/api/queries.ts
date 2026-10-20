/** Хуки TanStack Query модуля AD. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import { makeConnectionScheduleHooks } from '@/platform/collector/queries'
import type {
  AdConfig,
  CaData,
  Connection,
  ConnectionIn,
  DcLink,
  Domain,
  FindingDetail,
  FindingsQuery,
  FindingsResponse,
  Job,
  Overview,
  SettingsView,
  Snapshot,
  Summary,
} from './types'

export const FINDINGS_PAGE_SIZE = 200

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  for (const key of ['ad-domains', 'ad-snapshots', 'ad-overview', 'ad-findings', 'ad-finding', 'ad-connections', 'ad-jobs', 'ad-ca-data']) {
    qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useDomains() {
  return useQuery<Domain[], ApiRequestError>({ queryKey: ['ad-domains'], queryFn: () => api.get('/api/ad/domains') })
}

export function useOverview(domainId: number | undefined) {
  return useQuery<Overview, ApiRequestError>({
    queryKey: ['ad-overview', domainId],
    queryFn: () => api.get(`/api/ad/domains/${domainId}/overview`),
    enabled: domainId !== undefined,
  })
}

export function useSnapshots(domainId: number | undefined) {
  return useQuery<Snapshot[], ApiRequestError>({
    queryKey: ['ad-snapshots', domainId],
    queryFn: () => api.get(`/api/ad/snapshots${buildQuery({ domain_id: domainId })}`),
  })
}

export function useSnapshot(snapshotId: number | undefined) {
  return useQuery<Snapshot, ApiRequestError>({
    queryKey: ['ad-snapshots', 'one', snapshotId],
    queryFn: () => api.get(`/api/ad/snapshots/${snapshotId}`),
    enabled: snapshotId !== undefined,
  })
}

/** Сводка снапшота. 409 — сводка не посчитана (снапшот прежней версии анализатора): повтор не поможет, нужен пересчёт. */
export function useSummary(snapshotId: number | undefined) {
  return useQuery<Summary, ApiRequestError>({
    queryKey: ['ad-snapshots', 'summary', snapshotId],
    queryFn: () => api.get(`/api/ad/snapshots/${snapshotId}/summary`),
    enabled: !!snapshotId,
    retry: (count, err) => err.status !== 409 && count < 1,
  })
}

/** Контроллеры сводки, связанные с Assets, VM и антивирусом; читаются при показе. */
export function useDcLinks(domainId: number | undefined) {
  return useQuery<DcLink[], ApiRequestError>({
    queryKey: ['ad-snapshots', 'dc-links', domainId],
    queryFn: () => api.get(`/api/ad/domains/${domainId}/dc-links`),
    enabled: !!domainId,
  })
}

export function useFindings(snapshotId: number | undefined, query: Omit<FindingsQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<FindingsResponse, ApiRequestError>({
    queryKey: ['ad-findings', snapshotId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ad/snapshots/${snapshotId}/findings${buildQuery({ ...query, limit: FINDINGS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useFindingDetail(snapshotId: number | undefined, key: string | undefined) {
  return useQuery<FindingDetail, ApiRequestError>({
    queryKey: ['ad-finding', snapshotId, key],
    queryFn: () => api.get(`/api/ad/snapshots/${snapshotId}/findings/${key}`),
    enabled: snapshotId !== undefined && key !== undefined,
  })
}

/** После смены статусов находок: списки, карточки и обзор модуля читают их заново. */
export function useFindingsChanged() {
  const qc = useQueryClient()
  return () => {
    for (const key of ['ad-findings', 'ad-finding', 'ad-overview']) qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useUploadExport() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/ad/snapshots/file', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-jobs'] }),
  })
}

export function useReanalyze() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ad/snapshots/${id}/reanalyze`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-jobs'] }),
  })
}

export function useDeleteSnapshot() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/ad/snapshots/${id}`),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useCaData(domainId: number | undefined) {
  return useQuery<CaData[], ApiRequestError>({
    queryKey: ['ad-ca-data', domainId],
    queryFn: () => api.get(`/api/ad/domains/${domainId}/ca-data`),
    enabled: domainId !== undefined,
  })
}

/** 202 — пересчёт последнего снапшота запущен; 204 (undefined) — снапшотов домена нет. */
export function useDeleteCaData() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number } | undefined, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/ad/ca-data/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ad-ca-data'] })
      qc.invalidateQueries({ queryKey: ['ad-jobs'] })
    },
  })
}

export function useAdSettings() {
  return useQuery<SettingsView, ApiRequestError>({ queryKey: ['ad-settings'], queryFn: () => api.get('/api/ad/settings') })
}

export function useSaveAdSettings() {
  const qc = useQueryClient()
  return useMutation<{ config: AdConfig }, ApiRequestError, AdConfig>({
    mutationFn: (cfg) => api.put('/api/ad/settings', cfg),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-settings'] }),
  })
}

export function useConnections() {
  return useQuery<Connection[], ApiRequestError>({ queryKey: ['ad-connections'], queryFn: () => api.get('/api/ad/connections') })
}

export function useSaveConnection() {
  const qc = useQueryClient()
  return useMutation<Connection, ApiRequestError, { id?: number; body: ConnectionIn }>({
    mutationFn: ({ id, body }) => (id ? api.put(`/api/ad/connections/${id}`, body) : api.post('/api/ad/connections', body)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-connections'] }),
  })
}

export function useDeleteConnection() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/ad/connections/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-connections'] }),
  })
}

export function useTestConnection() {
  return useMutation<{ ok: boolean; message: string }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ad/connections/${id}/test`),
  })
}

export function useCollect() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ad/connections/${id}/collect`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-jobs'] }),
  })
}

/** Расписание сбора подключения; после изменений список подключений (с его `schedule`) читается заново. */
export const {
  useSchedule: useConnectionSchedule,
  useSaveSchedule: useSaveConnectionSchedule,
  useDeleteSchedule: useDeleteConnectionSchedule,
} = makeConnectionScheduleHooks('/api/ad', 'ad-connections')

export function useJobs() {
  return useQuery<Job[], ApiRequestError>({
    queryKey: ['ad-jobs'],
    queryFn: () => api.get('/api/ad/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useJob(jobId: number | undefined) {
  const qc = useQueryClient()
  return useQuery<Job, ApiRequestError>({
    queryKey: ['ad-job', jobId],
    queryFn: async () => {
      const job = await api.get<Job>(`/api/ad/jobs/${jobId}`)
      if (job.status !== 'running') invalidateAll(qc)
      return job
    },
    enabled: jobId !== undefined,
    refetchInterval: (q) => (q.state.data?.status === 'running' || !q.state.data ? 1000 : false),
    refetchIntervalInBackground: true,
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ad/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-jobs'] }),
  })
}
