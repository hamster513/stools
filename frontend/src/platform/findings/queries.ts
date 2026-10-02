/** Хуки TanStack Query статусов находок. Списки модулей обновляет их `onChanged`/`onDone`. */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, ApiRequestError } from '@/api/client'
import type { BulkChangeRequest, DirectoryUser, FindingChange, FindingRef, FindingSettings, FindingState } from './types'

export function useFindingState(ref: FindingRef | undefined) {
  return useQuery<FindingState, ApiRequestError>({
    queryKey: ['finding-state', ref?.module, ref?.scope_id, ref?.key],
    queryFn: () => api.get(`/api/findings/state${buildQuery({ module: ref?.module, scope_id: ref?.scope_id, key: ref?.key })}`),
    enabled: ref !== undefined,
  })
}

export function useChangeFinding() {
  const qc = useQueryClient()
  // title и severity — для «Моих находок» до ближайшей сверки с данными модуля.
  return useMutation<FindingState, ApiRequestError, FindingRef & FindingChange & { title?: string; severity?: string }>({
    mutationFn: (body) => api.put('/api/findings/state', body),
    onSuccess: (state) => qc.setQueryData(['finding-state', state.module, state.scope_id, state.key], state),
  })
}

export function useBulkChange() {
  const qc = useQueryClient()
  return useMutation<{ changed: number }, ApiRequestError, BulkChangeRequest>({
    mutationFn: (body) => api.post('/api/findings/bulk', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['finding-state'] }),
  })
}

export function useUsersDirectory() {
  return useQuery<DirectoryUser[], ApiRequestError>({
    queryKey: ['users-directory'],
    queryFn: () => api.get('/api/users/directory'),
    staleTime: 5 * 60_000,
  })
}

export function useFindingSettings() {
  return useQuery<FindingSettings, ApiRequestError>({
    queryKey: ['finding-settings'],
    queryFn: () => api.get('/api/settings/findings'),
  })
}
