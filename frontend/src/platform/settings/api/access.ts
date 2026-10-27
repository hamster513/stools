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

export interface GroupRow {
  id: number
  name: string
  /** local — участников ведёт администратор; oidc — состав приходит из провайдера при входе. */
  source: 'local' | 'oidc'
  external_name: string | null
  role_id: number
  role_name: string
  members: number
}

export interface GroupInput {
  name: string
  source: 'local' | 'oidc'
  external_name?: string | null
  role_id: number
}

export interface MemberRow {
  user_id: number
  login: string
  display_name: string | null
  auth_source: 'local' | 'oidc'
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
export function invalidateAccess(qc: QueryClient) {
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

// --- Группы -----------------------------------------------------------

export function useGroups() {
  return useQuery<GroupRow[], ApiRequestError>({
    queryKey: ['groups'],
    queryFn: () => api.get('/api/settings/groups'),
  })
}

/** Как и у роли: отдельной ручки нет, группа берётся из списка. */
export function useGroup(id: number | null) {
  const q = useGroups()
  return { ...q, data: q.data?.find((g) => g.id === id) }
}

export function useCreateGroup() {
  const qc = useQueryClient()
  return useMutation<GroupRow, ApiRequestError, GroupInput>({
    mutationFn: (body) => api.post('/api/settings/groups', body),
    onSuccess: () => invalidateAccess(qc),
  })
}

/** Источник группы после создания не меняется — в теле его нет. */
export function useUpdateGroup() {
  const qc = useQueryClient()
  return useMutation<GroupRow, ApiRequestError, { id: number; body: Omit<GroupInput, 'source'> }>({
    mutationFn: ({ id, body }) => api.put(`/api/settings/groups/${id}`, body),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function useDeleteGroup() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/settings/groups/${id}`),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function useGroupMembers(id: number | null) {
  return useQuery<MemberRow[], ApiRequestError>({
    queryKey: ['groups', id, 'members'],
    queryFn: () => api.get(`/api/settings/groups/${id}/members`),
    enabled: id !== null,
  })
}

/** Состав local-группы задаётся целиком: список id всех участников после правки. */
export function useSetGroupMembers(id: number) {
  const qc = useQueryClient()
  return useMutation<MemberRow[], ApiRequestError, number[]>({
    mutationFn: (userIds) => api.put(`/api/settings/groups/${id}/members`, { user_ids: userIds }),
    onSuccess: () => invalidateAccess(qc),
  })
}
