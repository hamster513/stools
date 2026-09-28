/** Хуки TanStack Query модуля KSC. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import type {
  Connection,
  ConnectionIn,
  FindingDetail,
  FindingsQuery,
  FindingsResponse,
  HostDetail,
  HostsQuery,
  HostsResponse,
  Job,
  KscConfig,
  Overview,
  PoliciesResponse,
  PolicyContents,
  Server,
  ServerData,
  SettingsView,
  Snapshot,
} from './types'

export const FINDINGS_PAGE_SIZE = 200
export const HOSTS_PAGE_SIZE = 200

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  for (const key of ['ksc-servers', 'ksc-snapshots', 'ksc-overview', 'ksc-hosts', 'ksc-host', 'ksc-findings', 'ksc-finding', 'ksc-policies', 'ksc-policy-contents', 'ksc-server', 'ksc-connections', 'ksc-jobs']) {
    qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useServers() {
  return useQuery<Server[], ApiRequestError>({ queryKey: ['ksc-servers'], queryFn: () => api.get('/api/ksc/servers') })
}

export function useOverview(serverId: number | undefined) {
  return useQuery<Overview, ApiRequestError>({
    queryKey: ['ksc-overview', serverId],
    queryFn: () => api.get(`/api/ksc/servers/${serverId}/overview`),
    enabled: serverId !== undefined,
  })
}

export function useSnapshots(serverId: number | undefined) {
  return useQuery<Snapshot[], ApiRequestError>({
    queryKey: ['ksc-snapshots', serverId],
    queryFn: () => api.get(`/api/ksc/snapshots${buildQuery({ server_id: serverId })}`),
  })
}

export function useSnapshot(snapshotId: number | undefined) {
  return useQuery<Snapshot, ApiRequestError>({
    queryKey: ['ksc-snapshots', 'one', snapshotId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}`),
    enabled: snapshotId !== undefined,
  })
}

export function useHosts(snapshotId: number | undefined, query: Omit<HostsQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<HostsResponse, ApiRequestError>({
    queryKey: ['ksc-hosts', snapshotId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ksc/snapshots/${snapshotId}/hosts${buildQuery({ ...query, limit: HOSTS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useHostDetail(snapshotId: number | undefined, hostId: string | undefined) {
  return useQuery<HostDetail, ApiRequestError>({
    queryKey: ['ksc-host', snapshotId, hostId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/hosts/${hostId}`),
    enabled: snapshotId !== undefined && hostId !== undefined,
  })
}

export function useFindings(snapshotId: number | undefined, query: Omit<FindingsQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<FindingsResponse, ApiRequestError>({
    queryKey: ['ksc-findings', snapshotId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ksc/snapshots/${snapshotId}/findings${buildQuery({ ...query, limit: FINDINGS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useFindingDetail(snapshotId: number | undefined, key: string | undefined) {
  return useQuery<FindingDetail, ApiRequestError>({
    queryKey: ['ksc-finding', snapshotId, key],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/findings/${key}`),
    enabled: snapshotId !== undefined && key !== undefined,
  })
}

export function useSetVerdict() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, { key: string; server_id: number; reason: string }>({
    mutationFn: ({ key, ...body }) => api.put(`/api/ksc/verdicts/${key}`, body),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useDropVerdict() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, { key: string; server_id: number }>({
    mutationFn: ({ key, server_id }) => api.del(`/api/ksc/verdicts/${key}?server_id=${server_id}`),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useUploadExport() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/ksc/snapshots/file', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-jobs'] }),
  })
}

export function useReanalyze() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ksc/snapshots/${id}/reanalyze`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-jobs'] }),
  })
}

export function useDeleteSnapshot() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/ksc/snapshots/${id}`),
    onSuccess: () => invalidateAll(qc),
  })
}

export function usePolicies(snapshotId: number | undefined) {
  return useQuery<PoliciesResponse, ApiRequestError>({
    queryKey: ['ksc-policies', snapshotId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies`),
    enabled: snapshotId !== undefined,
  })
}

export function usePolicyContents(snapshotId: number | undefined, policyId: number | undefined) {
  return useQuery<PolicyContents, ApiRequestError>({
    queryKey: ['ksc-policy-contents', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}/contents`),
    enabled: snapshotId !== undefined && policyId !== undefined,
  })
}

export function useServer(snapshotId: number | undefined) {
  return useQuery<ServerData, ApiRequestError>({
    queryKey: ['ksc-server', snapshotId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/server`),
    enabled: snapshotId !== undefined,
  })
}

export function useConnections() {
  return useQuery<Connection[], ApiRequestError>({ queryKey: ['ksc-connections'], queryFn: () => api.get('/api/ksc/connections') })
}

export function useSaveConnection() {
  const qc = useQueryClient()
  return useMutation<Connection, ApiRequestError, { id?: number; body: ConnectionIn }>({
    mutationFn: ({ id, body }) => (id ? api.put(`/api/ksc/connections/${id}`, body) : api.post('/api/ksc/connections', body)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-connections'] }),
  })
}

export function useDeleteConnection() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/ksc/connections/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-connections'] }),
  })
}

export function useTestConnection() {
  return useMutation<{ ok: boolean; message: string }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ksc/connections/${id}/test`),
  })
}

export function useCollect() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/ksc/connections/${id}/collect`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-jobs'] }),
  })
}

export function useKscSettings() {
  return useQuery<SettingsView, ApiRequestError>({ queryKey: ['ksc-settings'], queryFn: () => api.get('/api/ksc/settings') })
}

export function useSaveKscSettings() {
  const qc = useQueryClient()
  return useMutation<{ config: KscConfig }, ApiRequestError, KscConfig>({
    mutationFn: (cfg) => api.put('/api/ksc/settings', cfg),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-settings'] }),
  })
}

export function useJobs() {
  return useQuery<Job[], ApiRequestError>({
    queryKey: ['ksc-jobs'],
    queryFn: () => api.get('/api/ksc/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useJob(jobId: number | undefined) {
  const qc = useQueryClient()
  return useQuery<Job, ApiRequestError>({
    queryKey: ['ksc-job', jobId],
    queryFn: async () => {
      const job = await api.get<Job>(`/api/ksc/jobs/${jobId}`)
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
    mutationFn: (id) => api.post(`/api/ksc/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ksc-jobs'] }),
  })
}
