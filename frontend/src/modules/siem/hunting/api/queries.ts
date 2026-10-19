/**
 * Хуки TanStack Query раздела Threat Hunting поверх api-клиента (/api/siem/hunting).
 * Ключи держим здесь же: все под префиксом `th`, чтобы инвалидация не расползалась по страницам.
 * Статусы, исполнителей, сроки и комментарии находок меняет платформа (`/api/findings/*`,
 * модуль `siem_th`) — после её мутации страница сама сбрасывает `TH_FINDINGS_KEY`.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiRequestError, buildQuery } from '@/api/client'
import {
  DEEP_ACTIVE,
  type CheckQueryIn,
  type CheckQueryOut,
  type DeepCreate,
  type DeepDetail,
  type DeepSaveIn,
  type DeepView,
  type EventsPage,
  type HuntIn,
  type HuntListItem,
  type HuntsFilters,
  type HuntView,
  type ImportApplyIn,
  type ImportPreview,
  type ImportResult,
  type RerunOut,
  type RunDetail,
  type RunView,
  type ThFindingList,
  type ThFindingsFilters,
  type ThFindingView,
  type ThJob,
  type ThSettings,
  type ThSettingsView,
} from './types'

const BASE = '/api/siem/hunting'

export const TH_HUNTS_KEY = ['th', 'hunts'] as const
export const TH_FINDINGS_KEY = ['th', 'findings'] as const
export const TH_RUNS_KEY = ['th', 'runs'] as const
export const TH_DEEP_KEY = ['th', 'deep'] as const
export const TH_JOBS_KEY = ['th', 'jobs'] as const

/** Размер страницы таблицы событий находки; предел сервера — 1000. */
export const EVENTS_PAGE_SIZE = 100

/** Опрос идущих задач раздела: ночной прогон и большой хант меняются без участия человека. */
const POLL_MS = 5000

// --- Библиотека ------------------------------------------------------------

export function useHunts(filters: HuntsFilters = {}) {
  return useQuery<HuntListItem[], ApiRequestError>({
    queryKey: [...TH_HUNTS_KEY, 'list', filters],
    queryFn: () => api.get(`${BASE}/hunts${buildQuery({ ...filters })}`),
    placeholderData: keepPreviousData,
  })
}

export function useHunt(id: number | undefined) {
  return useQuery<HuntView, ApiRequestError>({
    queryKey: [...TH_HUNTS_KEY, 'one', id],
    queryFn: () => api.get(`${BASE}/hunts/${id}`),
    enabled: id !== undefined,
  })
}

/** Ответом хант приходит целиком: кладём его в кэш карточки, список обновится запросом. */
function useHuntCache() {
  const qc = useQueryClient()
  return (hunt: HuntView) => {
    qc.setQueryData([...TH_HUNTS_KEY, 'one', hunt.id], hunt)
    qc.invalidateQueries({ queryKey: [...TH_HUNTS_KEY, 'list'] })
  }
}

/** Без `id` — создание (POST), с `id` — правка (PUT); код при правке не меняется. */
export function useSaveHunt() {
  const cache = useHuntCache()
  return useMutation<HuntView, ApiRequestError, { id?: number; body: HuntIn }>({
    mutationFn: ({ id, body }) => (id === undefined ? api.post(`${BASE}/hunts`, body) : api.put(`${BASE}/hunts/${id}`, body)),
    onSuccess: cache,
  })
}

export function useDeleteHunt() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`${BASE}/hunts/${id}`),
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: [...TH_HUNTS_KEY, 'one', id] })
      qc.invalidateQueries({ queryKey: TH_HUNTS_KEY })
    },
  })
}

export function useToggleHunt() {
  const cache = useHuntCache()
  return useMutation<HuntView, ApiRequestError, { id: number; enabled: boolean }>({
    mutationFn: ({ id, enabled }) => api.post(`${BASE}/hunts/${id}/enabled`, { enabled }),
    onSuccess: cache,
  })
}

/** `queryPk` — `QueryView.id`, не `query_id`. */
export function useToggleQuery() {
  const cache = useHuntCache()
  return useMutation<HuntView, ApiRequestError, { queryPk: number; enabled: boolean }>({
    mutationFn: ({ queryPk, enabled }) => api.post(`${BASE}/queries/${queryPk}/enabled`, { enabled }),
    onSuccess: cache,
  })
}

/** Принимает ли MaxPatrol запрос: результат не сохраняется, кэш не меняется. */
export function useCheckQuery() {
  return useMutation<CheckQueryOut, ApiRequestError, CheckQueryIn>({
    mutationFn: (body) => api.post(`${BASE}/queries/check`, body),
  })
}

export function useImportPreview() {
  return useMutation<ImportPreview, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm(`${BASE}/library/import/preview`, form)
    },
  })
}

export function useImportApply() {
  const qc = useQueryClient()
  return useMutation<ImportResult, ApiRequestError, ImportApplyIn>({
    mutationFn: ({ file, replace }) => {
      const form = new FormData()
      form.set('file', file)
      form.set('replace', replace.join(','))
      return api.postForm(`${BASE}/library/import`, form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: TH_HUNTS_KEY }),
  })
}

/** Адрес выгрузки библиотеки в YAML для ссылки «Скачать». */
export const LIBRARY_EXPORT_URL = `${BASE}/library/export`

// --- Настройки -------------------------------------------------------------

export function useThSettings() {
  return useQuery<ThSettingsView, ApiRequestError>({
    queryKey: ['th', 'settings'],
    queryFn: () => api.get(`${BASE}/settings`),
  })
}

export function useSaveThSettings() {
  const qc = useQueryClient()
  return useMutation<ThSettingsView, ApiRequestError, ThSettings>({
    mutationFn: (body) => api.put(`${BASE}/settings`, body),
    onSuccess: (view) => qc.setQueryData(['th', 'settings'], view),
  })
}

// --- Находки ---------------------------------------------------------------

/** Параметры списка находок; те же уходят в выгрузку: exportHref(TH_FINDINGS_PATH + '/export', thFindingsParams(f)). */
export function thFindingsParams(f: Omit<ThFindingsFilters, 'limit' | 'offset'>) {
  return {
    status: f.status,
    hunt: f.hunt,
    date_from: f.date_from,
    date_to: f.date_to,
    limit_hit: f.limit_hit,
    sort: f.sort,
    order: f.order,
  }
}

export const TH_FINDINGS_PATH = `${BASE}/findings`

export function useThFindings(filters: ThFindingsFilters = {}) {
  const { limit, offset, ...rest } = filters
  return useQuery<ThFindingList, ApiRequestError>({
    queryKey: [...TH_FINDINGS_KEY, 'list', filters],
    queryFn: () => api.get(`${TH_FINDINGS_PATH}${buildQuery({ ...thFindingsParams(rest), limit, offset })}`),
    placeholderData: keepPreviousData,
  })
}

export function useThFinding(id: number | undefined) {
  return useQuery<ThFindingView, ApiRequestError>({
    queryKey: [...TH_FINDINGS_KEY, 'one', id],
    queryFn: () => api.get(`${TH_FINDINGS_PATH}/${id}`),
    enabled: id !== undefined,
  })
}

/** Страница событий (с нуля, по `EVENTS_PAGE_SIZE` строк); при листании прежняя страница остаётся на экране. */
export function useThEvents(id: number | undefined, page: number) {
  return useQuery<EventsPage, ApiRequestError>({
    queryKey: [...TH_FINDINGS_KEY, 'events', id, page],
    queryFn: () => api.get(`${TH_FINDINGS_PATH}/${id}/events${buildQuery({ limit: EVENTS_PAGE_SIZE, offset: page * EVENTS_PAGE_SIZE })}`),
    enabled: id !== undefined,
    placeholderData: keepPreviousData,
  })
}

/** Адрес выгрузки всех событий находки (CSV или XLSX) для ExportButton. */
export function thEventsExportHref(id: number): (fmt: 'csv' | 'xlsx') => string {
  return (fmt) => `${TH_FINDINGS_PATH}/${id}/events/export${buildQuery({ format: fmt })}`
}

// --- Ночные прогоны --------------------------------------------------------

export function useRuns() {
  return useQuery<RunView[], ApiRequestError>({
    queryKey: [...TH_RUNS_KEY, 'list'],
    queryFn: () => api.get(`${BASE}/runs`),
    refetchInterval: (query) => (query.state.data?.some((r) => r.status === 'running' || r.status === 'queued') ? POLL_MS : false),
  })
}

export function useRun(id: number | undefined) {
  return useQuery<RunDetail, ApiRequestError>({
    queryKey: [...TH_RUNS_KEY, 'one', id],
    queryFn: () => api.get(`${BASE}/runs/${id}`),
    enabled: id !== undefined,
    refetchInterval: (query) => (query.state.data && (query.state.data.status === 'running' || query.state.data.status === 'queued') ? POLL_MS : false),
  })
}

/** «Повторить за дату»: 409, если прогон этой даты уже идёт или ждёт. */
export function useRerun() {
  const qc = useQueryClient()
  return useMutation<RerunOut, ApiRequestError, number>({
    mutationFn: (runId) => api.post(`${BASE}/runs/${runId}/rerun`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TH_RUNS_KEY })
      qc.invalidateQueries({ queryKey: TH_JOBS_KEY })
    },
  })
}

/** Отмена ждущего или идущего прогона; 409, если он уже завершён. */
export function useCancelRun() {
  const qc = useQueryClient()
  return useMutation<RunView, ApiRequestError, number>({
    mutationFn: (runId) => api.post(`${BASE}/runs/${runId}/cancel`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TH_RUNS_KEY })
      qc.invalidateQueries({ queryKey: TH_JOBS_KEY })
    },
  })
}

// --- Большие ханты ---------------------------------------------------------

export function useDeepHunts() {
  return useQuery<DeepView[], ApiRequestError>({
    queryKey: [...TH_DEEP_KEY, 'list'],
    queryFn: () => api.get(`${BASE}/deep`),
    refetchInterval: (query) => (query.state.data?.some((d) => DEEP_ACTIVE.includes(d.status)) ? POLL_MS : false),
  })
}

export function useDeepHunt(id: number | undefined) {
  return useQuery<DeepDetail, ApiRequestError>({
    queryKey: [...TH_DEEP_KEY, 'one', id],
    queryFn: () => api.get(`${BASE}/deep/${id}`),
    enabled: id !== undefined,
    refetchInterval: (query) => (query.state.data && DEEP_ACTIVE.includes(query.state.data.status) ? POLL_MS : false),
  })
}

function useDeepRefresh() {
  const qc = useQueryClient()
  return () => {
    qc.invalidateQueries({ queryKey: TH_DEEP_KEY })
    qc.invalidateQueries({ queryKey: TH_JOBS_KEY })
    // Хант копит одну находку: она появляется после первого окна с событиями.
    qc.invalidateQueries({ queryKey: TH_FINDINGS_KEY })
  }
}

export function useCreateDeep() {
  const refresh = useDeepRefresh()
  return useMutation<DeepView, ApiRequestError, DeepCreate>({
    mutationFn: (body) => api.post(`${BASE}/deep`, body),
    onSuccess: refresh,
  })
}

/** 409, если хант уже завершён. Собранное до отмены остаётся в находке с пометкой «неполная». */
export function useCancelDeep() {
  const refresh = useDeepRefresh()
  return useMutation<DeepView, ApiRequestError, number>({
    mutationFn: (id) => api.post(`${BASE}/deep/${id}/cancel`),
    onSuccess: refresh,
  })
}

/** Новый хант с тем же запросом и периодом; прежний остаётся как был. */
export function useRerunDeep() {
  const refresh = useDeepRefresh()
  return useMutation<DeepView, ApiRequestError, number>({
    mutationFn: (id) => api.post(`${BASE}/deep/${id}/rerun`),
    onSuccess: refresh,
  })
}

/** Свой запрос — в библиотеку выключенным хантом; запрос из библиотеки там уже есть (409). */
export function useSaveDeepToLibrary() {
  const qc = useQueryClient()
  return useMutation<HuntView, ApiRequestError, { id: number } & DeepSaveIn>({
    mutationFn: ({ id, ...body }) => api.post(`${BASE}/deep/${id}/save-to-library`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TH_HUNTS_KEY })
      qc.invalidateQueries({ queryKey: TH_DEEP_KEY })
    },
  })
}

// --- Задачи ----------------------------------------------------------------

/** Задачи раздела: идущие сверху, затем завершённые. Отмены нет — отменяют прогон или большой хант. */
export function useThJobs() {
  return useQuery<ThJob[], ApiRequestError>({
    queryKey: [...TH_JOBS_KEY, 'list'],
    queryFn: () => api.get(`${BASE}/jobs`),
    refetchInterval: (query) => (query.state.data?.some((j) => j.status === 'running') ? POLL_MS : false),
  })
}
