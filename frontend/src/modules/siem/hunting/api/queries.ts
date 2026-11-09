/**
 * Хуки TanStack Query раздела Threat Hunting поверх api-клиента (/api/siem/hunting).
 * Ключи держим здесь же: все под префиксом `th`, чтобы инвалидация не расползалась по страницам.
 * Статусы, исполнителей, сроки и комментарии находок меняет платформа (`/api/findings/*`,
 * модуль `siem_th`) — после её мутации страница сама сбрасывает `TH_FINDINGS_KEY`.
 */
import { keepPreviousData, useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
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
  type ExpectedNights,
  type HuntIn,
  type HuntListItem,
  type HuntsFilters,
  type HuntView,
  type ImportApplyIn,
  type ImportPreview,
  type ImportResult,
  type OrderIn,
  type RerunDateIn,
  type RerunOut,
  type RunDetail,
  type RunView,
  type SchedulerIn,
  type SchedulerOut,
  type ThFindingList,
  type ThFindingsFilters,
  type ThFindingView,
  type ThJob,
  type CatalogQuery,
  type FilterCatalog,
  type SavedFilter,
  type ThSettings,
  type ThSettingsView,
} from './types'

const BASE = '/api/siem/hunting'

export const TH_HUNTS_KEY = ['th', 'hunts'] as const
export const TH_FINDINGS_KEY = ['th', 'findings'] as const
export const TH_RUNS_KEY = ['th', 'runs'] as const
export const TH_DEEP_KEY = ['th', 'deep'] as const
export const TH_JOBS_KEY = ['th', 'jobs'] as const
export const TH_SCHEDULER_KEY = ['th', 'scheduler'] as const
export const TH_SETTINGS_KEY = ['th', 'settings'] as const

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

/**
 * Хант запроса с номером `queryPk` (`QueryView.id`) для подстановки в форму большого ханта. Ссылка «в большой хант»
 * несёт и номер ханта (`huntId`): тогда читается одна его карточка. Без него (старая закладка) остаётся поиск:
 * ханты читаются по одному в общий кэш карточек. `enabled = false` (аудитору форма не нужна) не запрашивает ничего.
 * `failed` — запросы не удались: «не загрузился» не то же, что «запроса нет».
 */
export function useHuntOfQuery(queryPk: number | undefined, huntId: number | undefined, enabled = true) {
  const wanted = enabled && queryPk !== undefined
  const direct = wanted && huntId !== undefined
  const card = useHunt(direct ? huntId : undefined)
  const list = useQuery<HuntListItem[], ApiRequestError>({
    queryKey: [...TH_HUNTS_KEY, 'list', {}],
    queryFn: () => api.get(`${BASE}/hunts${buildQuery({})}`),
    enabled: wanted && !direct,
  })
  const ids = wanted && !direct ? (list.data ?? []).map((h) => h.id) : []
  const one = useQueries({
    queries: ids.map((id) => ({
      queryKey: [...TH_HUNTS_KEY, 'one', id],
      queryFn: (): Promise<HuntView> => api.get(`${BASE}/hunts/${id}`),
    })),
  })
  if (!wanted) return { hunt: null, loading: false, failed: false }
  if (direct) {
    const hunt = card.data?.queries.some((q) => q.id === queryPk) ? card.data : null
    return { hunt, loading: card.isLoading, failed: card.isError }
  }
  const hunt = one.map((q) => q.data).find((h) => h?.queries.some((q) => q.id === queryPk)) ?? null
  return {
    hunt,
    loading: !hunt && (list.isLoading || one.some((q) => q.isLoading)),
    failed: !hunt && (list.isError || one.some((q) => q.isError)),
  }
}

/** Ответом хант приходит целиком: кладём его в кэш карточки, список обновится запросом. */
function useHuntCache() {
  const qc = useQueryClient()
  return (hunt: HuntView) => {
    qc.setQueryData([...TH_HUNTS_KEY, 'one', hunt.id], hunt)
    qc.invalidateQueries({ queryKey: [...TH_HUNTS_KEY, 'list'] })
    // Очередь планировщика показывает те же ханты: галочка «в очереди» встаёт сразу, остальное — запросом.
    qc.setQueryData<SchedulerOut>(TH_SCHEDULER_KEY, (old) => old && { ...old, hunts: old.hunts.map((h) => (h.id === hunt.id ? { ...h, enabled: hunt.enabled } : h)) })
    qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY })
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
      // Удалённый хант уходит и из очереди планировщика.
      qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY })
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

/** Проверка запроса: события за выбранное окно разобранной таблицей; результат не сохраняется, кэш не меняется. */
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
    // Загрузка добавляет и заменяет ханты — очередь планировщика меняется вместе с библиотекой.
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: TH_HUNTS_KEY })
      qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY })
    },
  })
}

/** Адрес выгрузки библиотеки в YAML для ссылки «Скачать». */
export const LIBRARY_EXPORT_URL = `${BASE}/library/export`

// --- Настройки -------------------------------------------------------------

export function useThSettings() {
  return useQuery<ThSettingsView, ApiRequestError>({
    queryKey: TH_SETTINGS_KEY,
    queryFn: () => api.get(`${BASE}/settings`),
  })
}

export function useSaveThSettings() {
  const qc = useQueryClient()
  return useMutation<ThSettingsView, ApiRequestError, ThSettings>({
    mutationFn: (body) => api.put(`${BASE}/settings`, body),
    onSuccess: (view) => {
      qc.setQueryData(TH_SETTINGS_KEY, view)
      // Расписание живёт в тех же настройках: планировщик перечитает его.
      qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY })
    },
  })
}

// --- Планировщик -----------------------------------------------------------

export function useScheduler() {
  return useQuery<SchedulerOut, ApiRequestError>({
    queryKey: TH_SCHEDULER_KEY,
    queryFn: () => api.get(`${BASE}/scheduler`),
  })
}

/** Расписание: ответ — весь планировщик; настройки раздела держат то же время и паузу, их кэш сбрасывается. */
export function useSaveScheduler() {
  const qc = useQueryClient()
  return useMutation<SchedulerOut, ApiRequestError, SchedulerIn>({
    mutationFn: (body) => api.put(`${BASE}/scheduler`, body),
    onSuccess: (out) => {
      qc.setQueryData(TH_SCHEDULER_KEY, out)
      qc.invalidateQueries({ queryKey: TH_SETTINGS_KEY })
    },
  })
}

/** Порядок очереди: полный список id; 422 «набор хантов не совпадает», если ханты успели смениться. */
export function useSaveQueueOrder() {
  const qc = useQueryClient()
  return useMutation<SchedulerOut, ApiRequestError, OrderIn>({
    mutationFn: (body) => api.put(`${BASE}/scheduler/order`, body),
    onSuccess: (out) => {
      qc.setQueryData(TH_SCHEDULER_KEY, out)
      // Библиотека показывает ханты в порядке очереди.
      qc.invalidateQueries({ queryKey: [...TH_HUNTS_KEY, 'list'] })
    },
    // Отказ (чаще всего ханты сменились в другой вкладке) — экран перечитывает очередь, а не держит устаревшую.
    onError: () => qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY }),
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

/** Диапазон ожидаемых ночей: даты без прогона в нём — пропущенные ночи. */
export function useExpectedNights() {
  return useQuery<ExpectedNights, ApiRequestError>({
    queryKey: [...TH_RUNS_KEY, 'expected'],
    queryFn: () => api.get(`${BASE}/runs/expected`),
  })
}

/** «Запустить за дату» для пропущенной ночи: 409, если прогон даты идёт или ждёт; 422 — ночь ещё не наступила. */
export function useRerunDate() {
  const qc = useQueryClient()
  return useMutation<RerunOut, ApiRequestError, RerunDateIn>({
    mutationFn: (body) => api.post(`${BASE}/runs/rerun-date`, body),
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
      // Новый хант из большого ханта встаёт в конец очереди планировщика.
      qc.invalidateQueries({ queryKey: TH_SCHEDULER_KEY })
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

export function useFilterFolders(enabled: boolean) {
  return useQuery<{ id: string; name: string }[], ApiRequestError>({
    queryKey: ['th', 'filter-folders'],
    queryFn: () => api.get(`${BASE}/filters/folders`),
    enabled, retry: false, staleTime: 0,
  })
}

export function usePublishFilter() {
  const qc = useQueryClient()
  return useMutation<SavedFilter, ApiRequestError, { kind: 'query' | 'deep'; id: number }>({
    mutationFn: ({ kind, id }) => api.post(`${BASE}/filters/${kind}/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['th'] }),
  })
}

export function useFilterCatalog(enabled = true) {
  return useQuery<FilterCatalog, ApiRequestError>({
    queryKey: ['th', 'filter-catalog'],
    queryFn: () => api.get(`${BASE}/filters/catalog`),
    enabled, retry: false, staleTime: 0,
  })
}

export function useReadFilter() {
  return useMutation<CatalogQuery, ApiRequestError, string>({
    mutationFn: id => api.get(`${BASE}/filters/catalog/${encodeURIComponent(id)}`),
  })
}

export function useRefreshFilters() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.get(`${BASE}/filters/catalog`),
    onSettled: () => qc.invalidateQueries({queryKey: ['th']}),
  })
}
