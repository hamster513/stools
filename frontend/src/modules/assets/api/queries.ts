/** Хуки TanStack Query модуля Assets. */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiRequestError } from '@/api/client'
import type { Job } from './types'

export function useJobs() {
  return useQuery<Job[], ApiRequestError>({
    queryKey: ['assets-jobs'],
    queryFn: () => api.get('/api/assets/jobs?limit=50'),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === 'running') ? 1500 : 10000),
    refetchIntervalInBackground: true,
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.post(`/api/assets/jobs/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets-jobs'] }),
  })
}
