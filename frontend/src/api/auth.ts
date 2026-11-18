/**
 * Вход, выход, «кто я» — платформенная часть API STools. Хуки модулей
 * живут в своих каталогах (modules/<id>/api), здесь только то, что нужно
 * оболочке до выбора модуля.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { Theme } from '@/lib/theme'
import type { Access } from '@/platform/access/types'
import { api, ApiRequestError } from './client.ts'

export interface LoginRequest {
  login: string
  password: string
}

/** Откуда учётка: пароль в STools или провайдер входа. У второй пароля
 *  нет — сменить его на своём профиле невозможно. */
export type AuthSource = 'local' | 'oidc'

/** Группа, через которую пользователь получил права. */
export interface MeGroup {
  id: number
  name: string
  source: 'local' | 'oidc'
}

export interface MeResponse {
  login: string
  display_name: string | null
  theme: Theme
  auth_source: AuthSource
  /** Итоговый уровень в каждой области — сервер свёл роли всех групп. */
  access: Access
  groups: MeGroup[]
}

export async function fetchMe(options?: { signal?: AbortSignal }): Promise<MeResponse | null> {
  try {
    return await api.get<MeResponse>('/api/auth/me', options)
  } catch (error) {
    // 401 — отсутствие сессии, а не ошибка загрузки. При ошибке фонового
    // запроса React Query сохраняет прежнего пользователя в data.
    if (error instanceof ApiRequestError && error.status === 401) return null
    throw error
  }
}

export function useMe() {
  return useQuery<MeResponse | null, ApiRequestError>({
    queryKey: ['me'],
    queryFn: ({ signal }) => fetchMe({ signal }),
    retry: false,
  })
}

export interface OidcStatus {
  enabled: boolean
  display_name: string
}

/** Показывать ли на странице входа кнопку провайдера. Ручка публичная —
 *  сессии там ещё нет; без повторов: вход по паролю работает и тогда,
 *  когда про провайдера ничего не известно. */
export function useOidcStatus() {
  return useQuery<OidcStatus, ApiRequestError>({
    queryKey: ['oidc-status'],
    queryFn: () => api.get('/api/auth/oidc/status'),
    retry: false,
  })
}

export function useLogin() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, LoginRequest>({
    mutationFn: (body) => api.post('/api/auth/login', body),
    onSuccess: async () => {
      await qc.cancelQueries({ queryKey: ['me'] })
      qc.setQueryData(['me'], null)
      return qc.invalidateQueries({ queryKey: ['me'] })
    },
  })
}

/** Смена собственного пароля: текущий подтверждает, что за клавиатурой хозяин учётки. */
export function useChangePassword() {
  return useMutation<void, ApiRequestError, { current: string; new: string }>({
    mutationFn: (body) => api.post('/api/auth/password', body),
  })
}

/** Незаданное поле не трогают: PATCH темы не должен стирать имя, и наоборот. */
export function usePatchMe() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, { display_name?: string | null; theme?: Theme }>({
    mutationFn: (body) => api.patch('/api/auth/me', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError>({
    mutationFn: () => api.post('/api/auth/logout'),
    onSuccess: async () => {
      await qc.cancelQueries({ queryKey: ['me'] })
      qc.setQueryData(['me'], null)
    },
  })
}
