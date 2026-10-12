/** Хуки TanStack Query, общие для модулей-сборщиков (KSC, AD). */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiRequestError } from '@/api/client'
import type { ScheduleIn, ScheduleView } from './types'

/**
 * Хуки расписания сбора по подключению: `GET/PUT/DELETE {prefix}/connections/{id}/schedule`.
 * После изменения обновляется список подключений (`listKey`) — поле `schedule` лежит в нём.
 */
export function makeConnectionScheduleHooks(prefix: '/api/ksc' | '/api/ad', listKey: string) {
  const url = (id: number) => `${prefix}/connections/${id}/schedule`

  function useScheduleMutation<V, R>(fn: (vars: V) => Promise<R>) {
    const qc = useQueryClient()
    return useMutation<R, ApiRequestError, V>({
      mutationFn: fn,
      onSuccess: () => qc.invalidateQueries({ queryKey: [listKey] }),
    })
  }

  function useSchedule(id: number) {
    return useQuery<ScheduleView | null, ApiRequestError>({ queryKey: [listKey, 'schedule', id], queryFn: () => api.get(url(id)) })
  }

  function useSaveSchedule(id: number) {
    return useScheduleMutation<ScheduleIn, ScheduleView>((body) => api.put(url(id), body))
  }

  function useDeleteSchedule(id: number) {
    return useScheduleMutation<void, void>(() => api.del(url(id)))
  }

  return { useSchedule, useSaveSchedule, useDeleteSchedule }
}
