/**
 * Роли и группы доступа: что разрешено (роль — матрица «область × уровень»)
 * и кому (группа даёт роль своим участникам). Ключи держим здесь же, рядом с
 * мутациями: правка роли меняет счётчики групп и права самого пользователя,
 * поэтому инвалидация общая.
 */
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { api, type ApiRequestError } from '@/api/client'
import type { Access } from '@/platform/access/types'

export interface RoleRow {
  id: number
  name: string
  description: string
  builtin: boolean
  levels: Access
  /** Сколько групп получают эту роль. */
  groups: number
}

export interface RoleInput {
  name: string
  description: string
  levels: Access
}

// --- Роли -------------------------------------------------------------

export function useRoles() {
  return useQuery<RoleRow[], ApiRequestError>({
    queryKey: ['roles'],
    queryFn: () => api.get('/api/settings/roles'),
  })
}

/** Отдельной ручки на одну роль нет: берём из списка, он невелик. */
export function useRole(id: number | null) {
  const q = useRoles()
  return { ...q, data: q.data?.find((r) => r.id === id) }
}

/** Права пользователей считаются из ролей их групп: после правки ролей и групп они устаревают. */
function invalidateAccess(qc: QueryClient) {
  return Promise.all(
    [['roles'], ['groups'], ['settings-users'], ['me']].map((queryKey) => qc.invalidateQueries({ queryKey })),
  )
}

export function useCreateRole() {
  const qc = useQueryClient()
  return useMutation<RoleRow, ApiRequestError, RoleInput>({
    mutationFn: (body) => api.post('/api/settings/roles', body),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function useUpdateRole() {
  const qc = useQueryClient()
  return useMutation<RoleRow, ApiRequestError, { id: number; body: RoleInput }>({
    mutationFn: ({ id, body }) => api.put(`/api/settings/roles/${id}`, body),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function useDeleteRole() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/settings/roles/${id}`),
    onSuccess: () => invalidateAccess(qc),
  })
}
