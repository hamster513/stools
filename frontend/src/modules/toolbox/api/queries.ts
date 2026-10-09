/** Хуки TanStack Query модуля ToolBox: задания очистки файлов, соответствия, настройки. */
import { useEffect, useRef } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import { nextPageOffset } from '@/platform/collector/paging'
import type {
  AliasesQuery, AliasesResponse, Download, FindingsPatch, FindingsQuery, FindingsResponse, JobInfo, ReverseResult, ScrubJob, ToolboxSettings,
} from './types'

const BASE = '/api/toolbox/scrub'
const ALIASES = '/api/toolbox/aliases'
export const FINDINGS_PAGE_SIZE = 200
export const ALIASES_PAGE_SIZE = 100

export function useScrubJobs() {
  return useQuery<ScrubJob[], ApiRequestError>({
    queryKey: ['toolbox-jobs'],
    queryFn: () => api.get(`${BASE}/jobs?limit=50`),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

/**
 * Задание по номеру; пока идёт — опрос раз в 1,5 с. Когда ход кончился, сведения и находки
 * перечитываются: скан дописал находки и счётчики, применение — имя результата и замены.
 */
export function useScrubJob(id: number) {
  const qc = useQueryClient()
  const job = useQuery<ScrubJob, ApiRequestError>({
    queryKey: ['toolbox-job', id],
    queryFn: () => api.get(`${BASE}/jobs/${id}`),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 1500 : false),
  })
  // По отметке, а не по одному статусу: короткое применение успевает пройти между опросами,
  // и «готово» скана сменяется «готово» применения, минуя «идёт».
  const d = job.data
  const stamp = d ? `${d.kind}:${d.status}:${d.finished_at ?? ''}` : undefined
  const prev = useRef(stamp)
  useEffect(() => {
    if (prev.current !== undefined && stamp !== undefined && stamp !== prev.current && !stamp.includes(':running:')) {
      qc.invalidateQueries({ queryKey: ['toolbox-info', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-findings', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-jobs'] })
    }
    prev.current = stamp
  }, [qc, id, stamp])
  return job
}

export function useJobInfo(id: number) {
  return useQuery<JobInfo, ApiRequestError>({
    queryKey: ['toolbox-info', id],
    queryFn: () => api.get(`${BASE}/jobs/${id}/info`),
  })
}

export function useCreateJob() {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, FormData>({
    mutationFn: (form) => api.postForm(`${BASE}/jobs`, form),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['toolbox-jobs'] }),
  })
}

export function useFindings(id: number, query: FindingsQuery, enabled = true) {
  return useQuery<FindingsResponse, ApiRequestError>({
    queryKey: ['toolbox-findings', id, query],
    queryFn: () => api.get(`${BASE}/jobs/${id}/findings${buildQuery({ limit: FINDINGS_PAGE_SIZE, ...query })}`),
    placeholderData: (prev) => prev,
    enabled,
  })
}

export function useUpdateFindings(id: number) {
  const qc = useQueryClient()
  return useMutation<{ added: number }, ApiRequestError, FindingsPatch>({
    mutationFn: (body) => api.patch(`${BASE}/jobs/${id}/findings`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['toolbox-findings', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-info', id] })
    },
  })
}

/** Применение идёт той же строкой задания: после 202 карточка снова опрашивает ход. */
export function useApply(id: number) {
  const qc = useQueryClient()
  return useMutation<{ job_id: number }, ApiRequestError, void>({
    mutationFn: () => api.post(`${BASE}/jobs/${id}/apply`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['toolbox-job', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-jobs'] })
    },
  })
}

/** Удаляет файлы и находки задания; строка и счётчики в stats остаются, в сведениях — `files_deleted`. */
export function useDeleteJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`${BASE}/jobs/${id}`),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['toolbox-info', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-jobs'] })
    },
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.post(`${BASE}/jobs/${id}/cancel`),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['toolbox-job', id] })
      qc.invalidateQueries({ queryKey: ['toolbox-jobs'] })
    },
  })
}

export function downloadUrl(id: number, which: Download): string {
  return `${BASE}/jobs/${id}/${which}`
}

/** Обратный перевод — действие, а не данные: результат с настоящими значениями держит сама мутация, поэтому страница сбрасывает её при уходе (`reset`), а `gcTime: 0` убирает запись из кэша. */
export function useReverse() {
  return useMutation<ReverseResult, ApiRequestError, string>({
    mutationFn: (text) => api.post(`${BASE}/reverse`, { text }),
    // Без наблюдателя запись с результатом сразу уходит из кэша мутаций (по умолчанию живёт 5 минут).
    gcTime: 0,
  })
}

/** `enabled` — аудитору запрос не уходит вовсе: сервер всё равно ответил бы 403. */
export function useAliases(query: AliasesQuery, enabled = true) {
  return useInfiniteQuery<AliasesResponse, ApiRequestError>({
    queryKey: ['toolbox-aliases', query],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get(`${ALIASES}${buildQuery({ ...query, limit: ALIASES_PAGE_SIZE, offset: pageParam as number })}`),
    getNextPageParam: nextPageOffset,
    placeholderData: (prev) => prev,
    enabled,
  })
}

export function useForgetAlias() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`${ALIASES}/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['toolbox-aliases'] }),
  })
}

export function aliasesExportUrl(): string {
  return `${ALIASES}/export.csv`
}

export function useToolboxSettings(enabled = true) {
  return useQuery<ToolboxSettings, ApiRequestError>({
    queryKey: ['toolbox-settings'],
    queryFn: () => api.get('/api/toolbox/settings'),
    // Форма держит несохранённые правки; фоновое перечитывание не должно их сбрасывать.
    refetchOnWindowFocus: false,
    enabled,
  })
}

export function useSaveToolboxSettings() {
  const qc = useQueryClient()
  return useMutation<ToolboxSettings, ApiRequestError, ToolboxSettings>({
    mutationFn: (body) => api.put('/api/toolbox/settings', body),
    onSuccess: (data) => qc.setQueryData(['toolbox-settings'], data),
  })
}
