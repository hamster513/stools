/**
 * Хуки TanStack Query поверх api-клиента. Ключи запросов держим здесь же,
 * чтобы инвалидация не расползалась по компонентам.
 */
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryOptions,
} from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import type {
  ApplyReferenceRequest,
  ApplyReferenceResult,
  AttackConfirmRequest,
  ReferenceCompare,
  ReferenceImportResult,
  AttackCoverage,
  AttackGroupsQuery,
  AttackGroupsResponse,
  AttackGroupDetail,
  AttackRunResponse,
  CloneCompare,
  CloneEntry,
  CreateSnapshotResponse,
  DivergencesQuery,
  DivergencesResponse,
  FindingDetail,
  FindingsListResponse,
  FindingsQuery,
  InstallationProfile,
  JobStatusResponse,
  ProfileFieldsResponse,
  ProfilePreview,
  ProfileSuggestResponse,
  RuleDetail,
  RulesListResponse,
  RulesQuery,
  Settings,
  SnapshotListItem,
  TableListsResponse,
  TableReadersResponse,
  TableValuesResponse,
  SnapshotSummary,
  UpdateProfileRequest,
  UpdateSettingsRequest,
} from './types'

// --- Снапшоты -----------------------------------------------------------

export function useSnapshots() {
  return useQuery<SnapshotListItem[], ApiRequestError>({
    queryKey: ['snapshots'],
    queryFn: () => api.get('/api/siem/snapshots'),
  })
}

export function useSnapshotSummary(id: number | undefined) {
  return useQuery<SnapshotSummary, ApiRequestError>({
    queryKey: ['snapshot', id],
    queryFn: () => api.get(`/api/siem/snapshots/${id}`),
    enabled: id !== undefined,
  })
}

export function useUploadSnapshot() {
  const qc = useQueryClient()
  return useMutation<CreateSnapshotResponse, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm('/api/siem/snapshots', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['snapshots'] }),
  })
}

export function useJobStatus(jobId: number | undefined, opts?: { enabled?: boolean }) {
  return useQuery<JobStatusResponse, ApiRequestError>({
    queryKey: ['job', jobId],
    queryFn: () => api.get(`/api/siem/jobs/${jobId}`),
    enabled: jobId !== undefined && (opts?.enabled ?? true),
    // Контракт требует опроса раз в секунду, пока задание выполняется —
    // независимо от того, свёрнута ли вкладка в фоне.
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 1000 : false),
    refetchIntervalInBackground: true,
  })
}

// --- Находки --------------------------------------------------------------

/** Размер страницы. Предел сервера — 1000 (см. docs/api-contract.md);
 *  берём заметно меньше, чтобы первая отрисовка не ждала всю выгрузку. */
export const FINDINGS_PAGE_SIZE = 300

/**
 * Находки страницами. Выгрузка заведомо больше одной страницы — на
 * эталонной 1093 находки, — поэтому «загрузить всё разом» не работает
 * ни при каком разумном пределе, и рассчитывать на это нельзя.
 *
 * Фасеты приходят с сервера в каждой странице и посчитаны по всему
 * снапшоту. Считать их по загруженным строкам нельзя: счётчики менялись
 * бы по мере прокрутки, и это выглядело бы как поломка.
 */
export function useFindings(query: Omit<FindingsQuery, 'limit' | 'offset'>, options?: { enabled?: boolean }) {
  return useInfiniteQuery<FindingsListResponse, ApiRequestError>({
    queryKey: ['findings', query],
    enabled: options?.enabled ?? true,
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get(
        `/api/siem/findings${buildQuery({
          ...query,
          limit: FINDINGS_PAGE_SIZE,
          offset: pageParam as number,
        })}`,
      ),
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((sum, page) => sum + page.items.length, 0)
      return loaded < last.total ? loaded : undefined
    },
    placeholderData: (prev) => prev,
  })
}

export function useFindingDetail(
  id: number | undefined,
  options?: Pick<UseQueryOptions<FindingDetail, ApiRequestError>, 'enabled'>,
) {
  return useQuery<FindingDetail, ApiRequestError>({
    queryKey: ['finding-detail', id],
    queryFn: () => api.get(`/api/siem/findings/${id}/detail`),
    enabled: id !== undefined && (options?.enabled ?? true),
  })
}

// --- Расхождения ------------------------------------------------------

export function useDivergences(query: DivergencesQuery) {
  const qs = buildQuery({ ...query })
  return useQuery<DivergencesResponse, ApiRequestError>({
    queryKey: ['divergences', query],
    queryFn: () => api.get(`/api/siem/divergences${qs}`),
    placeholderData: (prev) => prev,
  })
}

// --- Клоны ------------------------------------------------------------

export function useClones(snapshotId: number | undefined) {
  return useQuery<CloneEntry[], ApiRequestError>({
    queryKey: ['clones', snapshotId],
    queryFn: () => api.get(`/api/siem/clones${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: snapshotId !== undefined,
  })
}

export function useCloneCompare(snapshotId: number, ruleA: string | null, ruleB: string | null) {
  return useQuery<CloneCompare, ApiRequestError>({
    queryKey: ['clone-compare', snapshotId, ruleA, ruleB],
    queryFn: () =>
      api.get(`/api/siem/clones/compare${buildQuery({ snapshot_id: snapshotId, rule_a: ruleA ?? undefined, rule_b: ruleB ?? undefined })}`),
    enabled: ruleA !== null && ruleB !== null,
  })
}

// --- Правила --------------------------------------------------------------

export function useRules(query: RulesQuery) {
  const qs = buildQuery({ ...query })
  return useQuery<RulesListResponse, ApiRequestError>({
    queryKey: ['rules', query],
    queryFn: () => api.get(`/api/siem/rules${qs}`),
    placeholderData: (prev) => prev,
  })
}

export function useRuleDetail(uuid: string | undefined, snapshotId: number | undefined) {
  return useQuery<RuleDetail, ApiRequestError>({
    queryKey: ['rule-detail', uuid, snapshotId],
    queryFn: () => api.get(`/api/siem/rules/${uuid}${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: uuid !== undefined && snapshotId !== undefined,
  })
}

// --- Профиль ------------------------------------------------------------

export function useProfile(snapshotId: number | undefined) {
  return useQuery<InstallationProfile, ApiRequestError>({
    queryKey: ['profile', snapshotId],
    queryFn: () => api.get(`/api/siem/profile${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: snapshotId !== undefined,
  })
}

export function useProfileSuggest(snapshotId: number | undefined) {
  return useQuery<ProfileSuggestResponse, ApiRequestError>({
    queryKey: ['profile-suggest', snapshotId],
    queryFn: () => api.get(`/api/siem/profile/suggest${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: snapshotId !== undefined,
  })
}

export function useUpdateProfile() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, UpdateProfileRequest>({
    mutationFn: (body) => api.put('/api/siem/profile', body),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['profile', vars.snapshot_id] })
      qc.invalidateQueries({ queryKey: ['snapshot', vars.snapshot_id] })
    },
  })
}

// --- Настройки ------------------------------------------------------------

export function useSettings() {
  return useQuery<Settings, ApiRequestError>({
    queryKey: ['settings'],
    queryFn: () => api.get('/api/siem/settings'),
  })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, UpdateSettingsRequest>({
    mutationFn: (body) => api.put('/api/siem/settings', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })
}

// --- Разметка ATT&CK --------------------------------------------------------

export function useAttackCoverage(snapshotId: number | undefined) {
  return useQuery<AttackCoverage, ApiRequestError>({
    queryKey: ['attack-coverage', snapshotId],
    queryFn: () => api.get(`/api/siem/attack/coverage${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: snapshotId !== undefined,
  })
}

/**
 * Группы разметки. Пагинации у ручки нет намеренно: групп десятки, а не
 * тысячи — это единица разметки, а не правило.
 */
export function useAttackGroups(query: AttackGroupsQuery) {
  return useQuery<AttackGroupsResponse, ApiRequestError>({
    queryKey: ['attack-groups', query],
    queryFn: () => api.get(`/api/siem/attack/groups${buildQuery({ ...query })}`),
    enabled: query.snapshot_id !== undefined,
    placeholderData: (prev) => prev,
  })
}

/** Всё о группе: её правила с маркировкой и её разметка. */
export function useAttackGroupDetail(group: string | undefined, snapshotId: number) {
  return useQuery<AttackGroupDetail, ApiRequestError>({
    queryKey: ['attack-group', group, snapshotId],
    queryFn: () =>
      api.get(`/api/siem/attack/group${buildQuery({ snapshot_id: snapshotId, group })}`),
    enabled: group !== undefined,
  })
}

export function useRunAttack() {
  return useMutation<AttackRunResponse, ApiRequestError, { snapshot_id: number }>({
    mutationFn: (body) => api.post('/api/siem/attack/run', body),
  })
}

export function useConfirmAttackGroup() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, AttackConfirmRequest>({
    mutationFn: (body) => api.post('/api/siem/attack/confirm', body),
    onSuccess: (_data, vars) => {
      // Ключ группы включает фильтр status — точного совпадения не будет,
      // инвалидируем по префиксу все запросы групп разметки.
      qc.invalidateQueries({ queryKey: ['attack-groups'] })
      qc.invalidateQueries({ queryKey: ['attack-coverage', vars.snapshot_id] })
      // Платформенная матрица и цепочки собираются по слоям всех модулей
      // и снапшота в ключе не знают: разметка SIEM меняет их содержимое.
      qc.invalidateQueries({ queryKey: ['attack-matrix'] })
      qc.invalidateQueries({ queryKey: ['attack-chains'] })
      qc.invalidateQueries({ queryKey: ['rules'] })
      // Карточка правила показывает разметку своей группы и лежит под
      // отдельным ключом: без этого человек правит разметку и видит
      // на экране прежнюю — то есть решает, что правка не сохранилась.
      qc.invalidateQueries({ queryKey: ['rule-detail'] })
      // То же и с карточкой техники: уточнение подтехник делается прямо
      // в ней, и без сброса человек уточнил бы разметку, а «0 из 5
      // закрыто» осталось бы на экране.
      qc.invalidateQueries({ queryKey: ['attack-technique'] })
    },
  })
}

export function useProfileFields(snapshotId: number) {
  return useQuery<ProfileFieldsResponse, ApiRequestError>({
    queryKey: ['profile-fields', snapshotId],
    queryFn: () => api.get(`/api/siem/profile/fields${buildQuery({ snapshot_id: snapshotId })}`),
  })
}

/**
 * Что даст профиль, если его сохранить. Одно поле на эталонной выгрузке
 * добавляет до семидесяти замечаний — принимать такое вслепую не стоит.
 */
export function usePreviewProfile() {
  return useMutation<ProfilePreview, ApiRequestError, UpdateProfileRequest>({
    mutationFn: (body) => api.post('/api/siem/profile/preview', body),
  })
}

// --- Табличные списки -------------------------------------------------------

export function useTableLists(snapshotId: number) {
  return useQuery<TableListsResponse, ApiRequestError>({
    queryKey: ['tables', snapshotId],
    queryFn: () => api.get(`/api/siem/tables${buildQuery({ snapshot_id: snapshotId })}`),
  })
}

/**
 * Состав списка. Запрашивается только когда человек его раскрыл:
 * содержимое списков — инвентарь внутренней инфраструктуры, и грузить
 * его «на всякий случай» не следует.
 */
export function useTableValues(name: string | undefined, snapshotId: number) {
  return useQuery<TableValuesResponse, ApiRequestError>({
    queryKey: ['table-values', name, snapshotId],
    queryFn: () =>
      api.get(`/api/siem/tables/values${buildQuery({ name, snapshot_id: snapshotId, limit: 50 })}`),
    enabled: name !== undefined,
  })
}

export function useTableReaders(name: string | undefined, snapshotId: number) {
  return useQuery<TableReadersResponse, ApiRequestError>({
    queryKey: ['table-readers', name, snapshotId],
    queryFn: () =>
      api.get(`/api/siem/tables/readers${buildQuery({ name, snapshot_id: snapshotId })}`),
    enabled: name !== undefined,
  })
}

export function attackLayerUrl(snapshotId: number): string {
  return `/api/siem/attack/layer/${snapshotId}`
}

/** Сверка нашей разметки с эталонной таблицей. */
export function useReferenceCompare(snapshotId: number | undefined) {
  return useQuery<ReferenceCompare, ApiRequestError>({
    queryKey: ['attack-reference', snapshotId],
    queryFn: () =>
      api.get(`/api/siem/attack/reference/compare${buildQuery({ snapshot_id: snapshotId })}`),
    enabled: snapshotId !== undefined,
  })
}

/** Загрузка эталона. Своей разметки не касается — сравнивать иначе не с чем. */
export function useUploadReference(snapshotId: number) {
  const qc = useQueryClient()
  return useMutation<ReferenceImportResult, ApiRequestError, File>({
    mutationFn: (file) => {
      const form = new FormData()
      form.set('file', file)
      return api.postForm(
        `/api/siem/attack/reference${buildQuery({ snapshot_id: snapshotId })}`,
        form,
      )
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-reference'] }),
  })
}

export function useDropReference() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, void>({
    mutationFn: () => api.del('/api/siem/attack/reference'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-reference'] }),
  })
}

/** Принять эталон как разметку. Явное решение человека, а не побочное
 *  действие загрузки файла: иначе сверять станет не с чем. */
export function useApplyReference() {
  const qc = useQueryClient()
  return useMutation<ApplyReferenceResult, ApiRequestError, ApplyReferenceRequest>({
    mutationFn: (body) => api.post('/api/siem/attack/reference/apply', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['attack-reference'] })
      qc.invalidateQueries({ queryKey: ['attack-coverage'] })
      qc.invalidateQueries({ queryKey: ['attack-groups'] })
      qc.invalidateQueries({ queryKey: ['attack-matrix'] })
      qc.invalidateQueries({ queryKey: ['attack-technique'] })
      // Цепочки считают закрытые шаги по той же разметке: принятый эталон
      // меняет их ровно так же, как матрицу.
      qc.invalidateQueries({ queryKey: ['attack-chains'] })
      qc.invalidateQueries({ queryKey: ['rules'] })
      qc.invalidateQueries({ queryKey: ['rule-detail'] })
    },
  })
}
