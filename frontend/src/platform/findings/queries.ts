/** Хуки TanStack Query статусов находок. Списки модулей обновляет их `onChanged`/`onDone`. */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import type {
  BulkChangeRequest,
  DirectoryUser,
  FindingChange,
  FindingRef,
  FindingSettings,
  FindingState,
  FindingStatus,
  MyFinding,
  MyFindingsCount,
} from './types'

export function useFindingState(ref: FindingRef | undefined) {
  return useQuery<FindingState, ApiRequestError>({
    queryKey: ['finding-state', ref?.module, ref?.scope_id, ref?.key],
    queryFn: () => api.get(`/api/findings/state${buildQuery({ module: ref?.module, scope_id: ref?.scope_id, key: ref?.key })}`),
    enabled: ref !== undefined,
  })
}

/** Ключи запросов сводки области и «Моих находок»: смена статуса делает их устаревшими. */
export const FINDING_SUMMARY_KEY = 'finding-summary'
export const FINDINGS_MINE_KEY = 'findings-mine'

function invalidateDerived(qc: ReturnType<typeof useQueryClient>) {
  for (const key of [FINDING_SUMMARY_KEY, FINDINGS_MINE_KEY]) qc.invalidateQueries({ queryKey: [key] })
}

export function useChangeFinding() {
  const qc = useQueryClient()
  // title и severity — для «Моих находок» до ближайшей сверки с данными модуля.
  return useMutation<FindingState, ApiRequestError, FindingRef & FindingChange & { title?: string; severity?: string }>({
    mutationFn: (body) => api.put('/api/findings/state', body),
    onSuccess: (state) => {
      qc.setQueryData(['finding-state', state.module, state.scope_id, state.key], state)
      invalidateDerived(qc)
    },
  })
}

/** По ключам — сразу `{changed}`; по фильтру у модуля с фоновой задачей — `{job_id}` (202). */
export type BulkChangeResult = { changed: number } | { job_id: number }

export function useBulkChange() {
  const qc = useQueryClient()
  return useMutation<BulkChangeResult, ApiRequestError, BulkChangeRequest>({
    mutationFn: (body) => api.post('/api/findings/bulk', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['finding-state'] })
      invalidateDerived(qc)
    },
  })
}

/** Кому можно назначить находку модуля — у кого в нём «аналитик» и выше. Спросить может
 *  только тот, кто сам назначает: без права записи запрос не идёт (сервер ответил бы 403). */
export function useUsersDirectory(module: string, enabled = true) {
  return useQuery<DirectoryUser[], ApiRequestError>({
    queryKey: ['users-directory', module],
    queryFn: () => api.get(`/api/users/directory${buildQuery({ module })}`),
    staleTime: 5 * 60_000,
    enabled,
  })
}

export function useFindingSettings() {
  return useQuery<FindingSettings, ApiRequestError>({
    queryKey: ['finding-settings'],
    queryFn: () => api.get('/api/settings/findings'),
  })
}

export function useSaveFindingSettings() {
  const qc = useQueryClient()
  return useMutation<FindingSettings, ApiRequestError, FindingSettings>({
    mutationFn: (body) => api.put('/api/settings/findings', body),
    onSuccess: (saved) => {
      qc.setQueryData(['finding-settings'], saved)
      // Подсчёты модулей зависят от `counted`: обзоры и списки перечитываются.
      qc.invalidateQueries()
    },
  })
}

/** Параметры «Моих находок» — те же у списка и у выгрузки; статусы и модули — повторением ключа. */
export function myFindingsParams(filters: { status?: FindingStatus[]; module?: string[] }) {
  return { status: filters.status, module: filters.module }
}

/** «Мои находки»; без статусов сервер отдаёт открытые. */
export function useMyFindings(filters: { status?: FindingStatus[]; module?: string[] }) {
  const params = myFindingsParams(filters)
  return useQuery<MyFinding[], ApiRequestError>({
    queryKey: [FINDINGS_MINE_KEY, 'list', params],
    queryFn: () => api.get(`/api/findings/mine${buildQuery(params)}`),
  })
}

/** Значок меню; ключ под FINDINGS_MINE_KEY — смена статуса его обновляет. */
export function useMyFindingsCount(enabled: boolean) {
  return useQuery<MyFindingsCount, ApiRequestError>({
    queryKey: [FINDINGS_MINE_KEY, 'count'],
    queryFn: () => api.get('/api/findings/mine/count'),
    enabled,
    refetchInterval: 5 * 60_000,
  })
}
