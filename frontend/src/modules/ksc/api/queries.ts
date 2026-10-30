import { netRulesSearch } from './netRulesQuery'
/** Хуки TanStack Query модуля KSC. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import { makeConnectionScheduleHooks } from '@/platform/collector/queries'
import type {
  ChangesQuery,
  ChangesResponse,
  Connection,
  ConnectionIn,
  ExclusionDetail,
  ExclusionsQuery,
  ExclusionsResponse,
  FindingDetail,
  FindingsQuery,
  FindingsResponse,
  HostDetail,
  HostProfiles,
  HostsQuery,
  HostsResponse,
  Job,
  KscConfig,
  NetRuleDetail,
  NetRuleSection,
  NetRulesQuery,
  NetRulesResponse,
  Overview,
  PoliciesResponse,
  PolicyCard,
  PolicyContents,
  PolicyGradeFindings,
  PolicyListQuery,
  PolicyListResponse,
  PolicyProfiles,
  PolicyScope,
  PolicySettings,
  Server,
  ServerData,
  SettingsView,
  Snapshot,
  TasksQuery,
  TasksResponse,
} from './types'

export const FINDINGS_PAGE_SIZE = 200
export const HOSTS_PAGE_SIZE = 200
export const OBJECTS_PAGE_SIZE = 200

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  for (const key of ['ksc-servers', 'ksc-snapshots', 'ksc-overview', 'ksc-hosts', 'ksc-host', 'ksc-host-profiles', 'ksc-findings', 'ksc-finding', 'ksc-policies', 'ksc-policy-contents', 'ksc-policy-list', 'ksc-policy',
    'ksc-policy-scope', 'ksc-policy-settings', 'ksc-policy-findings', 'ksc-policy-profiles', 'ksc-tasks', 'ksc-server', 'ksc-connections', 'ksc-jobs',
    'ksc-exclusions', 'ksc-net-rules', 'ksc-net-rule-sections', 'ksc-net-rule-summary', 'ksc-changes', 'ksc']) {
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

/** Политики хоста с профилями и их активацией на нём по тегам, и что включает каждый тег. */
export function useHostProfiles(snapshotId: number | undefined, hostId: string | undefined) {
  return useQuery<HostProfiles, ApiRequestError>({
    queryKey: ['ksc-host-profiles', snapshotId, hostId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/hosts/${hostId}/profiles`),
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

/** После смены статусов находок: списки, карточки, обзор модуля и оценки политик читают их заново. */
export function useFindingsChanged() {
  const qc = useQueryClient()
  return () => {
    for (const key of ['ksc-findings', 'ksc-finding', 'ksc-overview', 'ksc-hosts', 'ksc-host', 'ksc-policy-list', 'ksc-policy', 'ksc-policy-findings']) {
      qc.invalidateQueries({ queryKey: [key] })
    }
  }
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

export function usePolicyList(snapshotId: number | undefined, query: PolicyListQuery) {
  return useQuery<PolicyListResponse, ApiRequestError>({
    queryKey: ['ksc-policy-list', snapshotId, query],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policy-list${buildQuery({ ...query })}`),
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function usePolicy(snapshotId: number | undefined, policyId: number | undefined) {
  return useQuery<PolicyCard, ApiRequestError>({
    queryKey: ['ksc-policy', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}`),
    enabled: snapshotId !== undefined && policyId !== undefined,
  })
}

/** Находки оценки политики: считаемые первыми, затем по серьёзности. */
export function usePolicyFindings(snapshotId: number | undefined, policyId: number | undefined) {
  return useQuery<PolicyGradeFindings, ApiRequestError>({
    queryKey: ['ksc-policy-findings', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}/findings`),
    enabled: snapshotId !== undefined && policyId !== undefined,
  })
}

/** Настройки политики по компонентам защиты; `enabled=false` — не запрашивать (содержимое не собрано). */
export function usePolicySettings(snapshotId: number | undefined, policyId: number | undefined, enabled = true) {
  return useQuery<PolicySettings, ApiRequestError>({
    queryKey: ['ksc-policy-settings', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}/settings`),
    enabled: enabled && snapshotId !== undefined && policyId !== undefined,
  })
}

export function usePolicyScope(snapshotId: number | undefined, policyId: number | undefined) {
  return useQuery<PolicyScope, ApiRequestError>({
    queryKey: ['ksc-policy-scope', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}/scope`),
    enabled: snapshotId !== undefined && policyId !== undefined,
  })
}

export function usePolicyProfiles(snapshotId: number | undefined, policyId: number | undefined) {
  return useQuery<PolicyProfiles, ApiRequestError>({
    queryKey: ['ksc-policy-profiles', snapshotId, policyId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/policies/${policyId}/profiles`),
    enabled: snapshotId !== undefined && policyId !== undefined,
  })
}

export function useTasks(snapshotId: number | undefined, query: TasksQuery) {
  return useQuery<TasksResponse, ApiRequestError>({
    queryKey: ['ksc-tasks', snapshotId, query],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/tasks${buildQuery({ ...query })}`),
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useExclusions(snapshotId: number | undefined, query: Omit<ExclusionsQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<ExclusionsResponse, ApiRequestError>({
    queryKey: ['ksc-exclusions', snapshotId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ksc/snapshots/${snapshotId}/exclusions${buildQuery({ ...query, limit: OBJECTS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useNetRules(snapshotId: number | undefined, query: Omit<NetRulesQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<NetRulesResponse, ApiRequestError>({
    queryKey: ['ksc-net-rules', snapshotId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ksc/snapshots/${snapshotId}/net-rules${netRulesSearch({ ...query, limit: OBJECTS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    enabled: snapshotId !== undefined,
    placeholderData: (prev) => prev,
  })
}

export function useNetRuleSections(snapshotId: number | undefined, query: NetRulesQuery) {
  return useQuery<NetRuleSection[], ApiRequestError>({
    queryKey: ['ksc-net-rule-sections', snapshotId, query],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/net-rules/sections${netRulesSearch(query)}`),
    enabled: snapshotId !== undefined,
  })
}

export function useNetRuleSummary(snapshotId: number | undefined, query: NetRulesQuery) {
  return useQuery<NetRulesResponse, ApiRequestError>({
    queryKey: ['ksc-net-rule-summary', snapshotId, query],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/net-rules${netRulesSearch({ ...query, limit: 1, offset: 0 })}`),
    enabled: snapshotId !== undefined,
  })
}

/** Карточка исключения; `rowId === null` — панель закрыта, запроса нет. */
export function useExclusionDetail(snapshotId: number | undefined, rowId: number | null) {
  return useQuery<ExclusionDetail, ApiRequestError>({
    queryKey: ['ksc', 'exclusion', snapshotId, rowId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/exclusions/${rowId}`),
    enabled: snapshotId !== undefined && rowId !== null,
  })
}

/** Карточка сетевого правила; `rowId === null` — панель закрыта, запроса нет. */
export function useNetRuleDetail(snapshotId: number | undefined, rowId: number | null) {
  return useQuery<NetRuleDetail, ApiRequestError>({
    queryKey: ['ksc', 'net-rule', snapshotId, rowId],
    queryFn: () => api.get(`/api/ksc/snapshots/${snapshotId}/net-rules/${rowId}`),
    enabled: snapshotId !== undefined && rowId !== null,
  })
}

/** Журнал изменений сервера по всем снапшотам; `facets` и `snapshots` — со страницы offset=0. */
export function useChanges(serverId: number, query: Omit<ChangesQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<ChangesResponse, ApiRequestError>({
    queryKey: ['ksc-changes', serverId, query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/ksc/servers/${serverId}/changes${buildQuery({ ...query, limit: OBJECTS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
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

/** Расписание сбора подключения; после изменений список подключений (с его `schedule`) читается заново. */
export const {
  useSchedule: useConnectionSchedule,
  useSaveSchedule: useSaveConnectionSchedule,
  useDeleteSchedule: useDeleteConnectionSchedule,
} = makeConnectionScheduleHooks('/api/ksc', 'ksc-connections')

export function useKscSettings() {
  return useQuery<SettingsView, ApiRequestError>({ queryKey: ['ksc-settings'], queryFn: () => api.get('/api/ksc/settings') })
}

export function useSaveKscSettings() {
  const qc = useQueryClient()
  return useMutation<{ config: KscConfig }, ApiRequestError, KscConfig>({
    mutationFn: (cfg) => api.put('/api/ksc/settings', cfg),
    onSuccess: () => {
      for (const key of ['ksc-settings', 'ksc-net-rules', 'ksc-net-rule-summary', 'ksc-net-rule-sections']) qc.invalidateQueries({ queryKey: [key] })
    },
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
