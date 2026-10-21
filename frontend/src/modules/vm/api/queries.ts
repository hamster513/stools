/** Хуки TanStack Query модуля VM. Ключи запросов держим здесь же. */
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { FINDING_SUMMARY_KEY, FINDINGS_MINE_KEY } from '@/platform/findings/queries'
import type {
  HostDetail,
  ImportState,
  Job,
  Overview,
  RefState,
  RiskCard,
  SettingsUpdate,
  SettingsView,
  VulnsQuery,
  VulnsResponse,
  Zone,
} from './types'

export const VULNS_PAGE_SIZE = 200

function invalidateData(qc: ReturnType<typeof useQueryClient>) {
  // Импорт и массовая смена меняют и статусы пар: устаревают карточки состояний.
  for (const key of ['vm-vulns', 'vm-overview', 'vm-zones', 'vm-import', 'vm-refs', 'vm-card', 'vm-host', 'finding-state', FINDING_SUMMARY_KEY, FINDINGS_MINE_KEY]) {
    qc.invalidateQueries({ queryKey: [key] })
  }
}

export function useVulns(query: Omit<VulnsQuery, 'limit' | 'offset'>) {
  return useInfiniteQuery<VulnsResponse, ApiRequestError>({
    queryKey: ['vm-vulns', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(`/api/vm/vulns${buildQuery({ ...query, limit: VULNS_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: (last, pages) => {
      // Число пар — только у первой страницы: следующие его не пересчитывают.
      const loaded = pages.reduce((sum, page) => sum + page.items.length, 0)
      return last.items.length > 0 && loaded < (pages[0].total ?? 0) ? loaded : undefined
    },
    placeholderData: (prev) => prev,
  })
}

export function useRiskCard(hostId: number | undefined, cveId: string | undefined) {
  return useQuery<RiskCard, ApiRequestError>({
    queryKey: ['vm-card', hostId, cveId],
    queryFn: () => api.get(`/api/vm/vulns/${hostId}/${encodeURIComponent(cveId ?? '')}`),
    enabled: hostId !== undefined && cveId !== undefined,
  })
}

export function useHost(hostId: number | undefined) {
  return useQuery<HostDetail, ApiRequestError>({
    queryKey: ['vm-host', hostId],
    queryFn: () => api.get(`/api/vm/hosts/${hostId}`),
    enabled: hostId !== undefined,
  })
}

export function useOverview() {
  return useQuery<Overview, ApiRequestError>({ queryKey: ['vm-overview'], queryFn: () => api.get('/api/vm/overview') })
}

export function useZones() {
  return useQuery<Zone[], ApiRequestError>({ queryKey: ['vm-zones'], queryFn: () => api.get('/api/vm/zones') })
}

export function useSaveZones() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, { name: string; internet_access: boolean; confidential_data: boolean }[]>({
    mutationFn: (zones) => api.put('/api/vm/zones', zones),
    onSuccess: () => invalidateData(qc),
  })
}

export function useVmSettings() {
  return useQuery<SettingsView, ApiRequestError>({ queryKey: ['vm-settings'], queryFn: () => api.get('/api/vm/settings') })
}

export function useSaveVmSettings() {
  const qc = useQueryClient()
  return useMutation<SettingsView, ApiRequestError, SettingsUpdate>({
    mutationFn: (body) => api.put('/api/vm/settings', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-settings'] }),
  })
}

export function useTestVm() {
  return useMutation<{ ok: boolean; message: string }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/vm/settings/test-vm'),
  })
}

export function useImportState() {
  return useQuery<ImportState, ApiRequestError>({
    queryKey: ['vm-import'],
    queryFn: () => api.get('/api/vm/import'),
    refetchInterval: (q) => (q.state.data?.active ? 2000 : false),
  })
}

export function useStartVmImport() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/vm/import/vm'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-import'] }),
  })
}

export function useUploadImport() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/vm/import/file', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-import'] }),
  })
}

export function useRefs() {
  return useQuery<RefState[], ApiRequestError>({
    queryKey: ['vm-refs'],
    queryFn: () => api.get('/api/vm/refs'),
    refetchInterval: (q) => (q.state.data?.some((r) => r.active_job_id !== null) ? 2000 : false),
  })
}

export function useDownloadRef() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, { name: string; years?: number[] }>({
    mutationFn: ({ name, years }) => api.post(`/api/vm/refs/${name}/download`, years ? { years } : {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-refs'] }),
  })
}

export function useUploadRef() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, { name: string; files: File[] }>({
    mutationFn: ({ name, files }) => {
      const form = new FormData()
      for (const f of files) form.append('files', f)
      return api.postForm(`/api/vm/refs/${name}/upload`, form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-refs'] }),
  })
}

/** Архив справочников от скрипта download-references: одна задача на все ленты. */
export function useUploadBundle() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.append('file', file)
      return api.postForm('/api/vm/refs/bundle/upload', form)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vm-refs'] })
      qc.invalidateQueries({ queryKey: ['vm-jobs'] })
    },
  })
}

export function useRecalculate() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post('/api/vm/recalculate'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-jobs'] }),
  })
}

export function useJobs() {
  return useQuery<Job[], ApiRequestError>({
    queryKey: ['vm-jobs'],
    queryFn: () => api.get('/api/vm/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useJob(jobId: number | undefined) {
  const qc = useQueryClient()
  return useQuery<Job, ApiRequestError>({
    queryKey: ['vm-job', jobId],
    queryFn: async () => {
      const job = await api.get<Job>(`/api/vm/jobs/${jobId}`)
      // Задача завершилась — данные на экранах уже другие.
      if (job.status !== 'running') invalidateData(qc)
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
    mutationFn: (id) => api.post(`/api/vm/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vm-jobs'] }),
  })
}
