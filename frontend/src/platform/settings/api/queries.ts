/**
 * Хуки TanStack Query для общих настроек: пользователи, безопасность,
 * журнал действий. Ключи держим здесь же, рядом с мутациями, чтобы
 * инвалидация не расползалась по экранам.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, buildQuery, type ApiRequestError } from '@/api/client'
import { invalidateAccess } from './access'
import type {
  AuditFilters,
  AuditResponse,
  CreateUserRequest,
  LlmSettings,
  OidcSettings,
  OidcSettingsInput,
  OidcTestResult,
  PatchUserRequest,
  SecuritySettings,
  TestLlmRequest,
  TestLlmResponse,
  UserRow,
} from './types'

// --- Пользователи -----------------------------------------------------
// Правка пользователя меняет счётчики групп и, если это сам вызывающий, его права (`me`, рейка).

export function useUsers() {
  return useQuery<UserRow[], ApiRequestError>({
    queryKey: ['settings-users'],
    queryFn: () => api.get('/api/settings/users'),
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation<UserRow, ApiRequestError, CreateUserRequest>({
    mutationFn: (body) => api.post('/api/settings/users', body),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function usePatchUser() {
  const qc = useQueryClient()
  return useMutation<UserRow, ApiRequestError, { id: number; patch: PatchUserRequest }>({
    mutationFn: ({ id, patch }) => api.patch(`/api/settings/users/${id}`, patch),
    onSuccess: () => invalidateAccess(qc),
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, number>({
    mutationFn: (id) => api.del(`/api/settings/users/${id}`),
    onSuccess: () => invalidateAccess(qc),
  })
}

/** Сброс пароля администратором: текущий пароль не спрашивается — его
 *  как раз и забыли. Список не меняется, инвалидировать нечего. */
export function useSetUserPassword() {
  return useMutation<void, ApiRequestError, { id: number; password: string }>({
    mutationFn: ({ id, password }) => api.post(`/api/settings/users/${id}/password`, { password }),
  })
}

// --- Безопасность -----------------------------------------------------

export function useSecurity() {
  return useQuery<SecuritySettings, ApiRequestError>({
    queryKey: ['settings-security'],
    queryFn: () => api.get('/api/settings/security'),
  })
}

export function useSaveSecurity() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, Partial<SecuritySettings>>({
    mutationFn: (body) => api.put('/api/settings/security', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings-security'] }),
  })
}

// --- Модель -----------------------------------------------------------

/** Настройки модели общие для платформы: её адрес нужен и разметке SIEM,
 *  и переводу техник ATT&CK. Поэтому ключ здесь, а не в модуле. */
export function useLlm() {
  return useQuery<LlmSettings, ApiRequestError>({
    queryKey: ['settings-llm'],
    queryFn: () => api.get('/api/settings/llm'),
  })
}

export function useLlmModels(
  baseUrl: string,
  provider: NonNullable<LlmSettings['provider']> = 'ollama',
  options: { enabled?: boolean; apiKey?: string; credentialVersion?: string } = {},
) {
  return useQuery<{ models: string[]; embedding_models?: string[] }, ApiRequestError>({
    // Only a revision identifier belongs in the cache key, never the API key.
    queryKey: ['settings-llm-models', provider, provider === 'ollama' ? baseUrl : '', options.credentialVersion ?? ''],
    queryFn: () => api.post('/api/settings/llm/models', {
      base_url: baseUrl, provider, ...(provider === 'deepseek' ? { api_key: options.apiKey } : {}),
    }),
    enabled: options.enabled ?? (provider === 'openrouter' || (provider === 'ollama' && !!baseUrl)),
    retry: false,
    staleTime: 60_000,
  })
}

export function useSaveLlm() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, LlmSettings>({
    mutationFn: (body) => api.put('/api/settings/llm', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings-llm'] }),
  })
}

/** Проверка доступности модели до сохранения — настройка, о неработоспособности
 *  которой узнают через час на фоновой задаче, плохая настройка. */
export function useTestLlm() {
  return useMutation<TestLlmResponse, ApiRequestError, TestLlmRequest>({
    mutationFn: (body) => api.post('/api/settings/llm/test', body),
  })
}

// --- Вход по OIDC -----------------------------------------------------

export function useOidcSettings() {
  return useQuery<OidcSettings, ApiRequestError>({
    queryKey: ['settings-oidc'],
    queryFn: () => api.get('/api/settings/oidc'),
  })
}

export function useSaveOidc() {
  const qc = useQueryClient()
  return useMutation<void, ApiRequestError, OidcSettingsInput>({
    mutationFn: (body) => api.put('/api/settings/oidc', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings-oidc'] }),
  })
}

/** Проверка провайдера по адресу из формы, а не по сохранённому: настройка,
 *  о неработоспособности которой узнают на чужом входе, плохая настройка. */
export function useTestOidc() {
  return useMutation<OidcTestResult, ApiRequestError, { issuer_url: string }>({
    mutationFn: (body) => api.post('/api/settings/oidc/test', body),
  })
}

// --- Журнал действий --------------------------------------------------

/** Отбор без страницы. `denied_only=false` не отправляем: пустой фильтр
 *  в адресе выгрузки читается человеком, а лишний параметр — нет. */
function selection(filters: AuditFilters) {
  return {
    user_id: filters.user_id,
    since: filters.since,
    until: filters.until,
    denied_only: filters.denied_only ? true : undefined,
  }
}

export function useAudit(filters: AuditFilters) {
  return useQuery<AuditResponse, ApiRequestError>({
    queryKey: ['settings-audit', filters],
    queryFn: () =>
      api.get(
        `/api/settings/audit${buildQuery({
          ...selection(filters),
          page: filters.page,
          page_size: filters.page_size,
        })}`,
      ),
    // Без этого таблица пустеет на время запроса и мигает на каждом шаге
    // пагинации.
    placeholderData: (prev) => prev,
  })
}

/** Ссылка на выгрузку: те же фильтры, но без страницы — выгружается всё
 *  отобранное, а не видимый кусок. */
export function auditExportUrl(filters: AuditFilters, format: 'csv' | 'xlsx'): string {
  return `/api/settings/audit/export${buildQuery({ format, ...selection(filters) })}`
}
