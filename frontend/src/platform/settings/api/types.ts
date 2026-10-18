import type { AuthSource, Role } from '@/api/auth'

/** Названия ролей для показа человеку: в API роль — код, на экране — слово. */
export const ROLE_TITLES: Record<Role, string> = {
  admin: 'администратор',
  analyst: 'аналитик',
  auditor: 'аудитор',
}

/** Минимальная длина пароля — та же, что проверяет сервер. */
export const MIN_PASSWORD = 8

export interface UserRow {
  id: number
  login: string
  display_name: string | null
  role: Role
  is_active: boolean
  last_login_at: string | null
  created_at: string
  auth_source: AuthSource
}

export interface CreateUserRequest {
  login: string
  display_name: string | null
  role: Role
  password: string
}

/** Любое поле можно опустить: PATCH меняет только присланное. */
export interface PatchUserRequest {
  display_name?: string | null
  role?: Role
  is_active?: boolean
}

export interface SecuritySettings {
  session_ttl_hours: number
  idle_timeout_minutes: number
  audit_retention_days: number
}

/** Настройки модели. Пустой адрес — рабочее состояние, а не ошибка:
 *  без модели работает всё, кроме предложений по разметке и перевода. */
export interface LlmSettings {
  base_url: string
  model: string
  embed_model: string
  think: boolean
  timeout: number
  enabled: boolean
}

export interface TestLlmRequest {
  base_url: string
  model: string
  timeout?: number
}

export interface TestLlmResponse {
  ok: boolean
  latency_ms: number | null
  error: string | null
}

/** Группа провайдера и роль, которую она даёт в STools. */
export interface GroupRole {
  group: string
  role: Role
}

/** Настройки входа через провайдера. Секрет наружу не отдаётся: в ответе
 *  на его месте маска, а `has_secret` говорит, задан ли он на самом деле. */
export interface OidcSettings {
  enabled: boolean
  display_name: string
  public_url: string
  issuer_url: string
  client_id: string
  client_secret: string
  has_secret: boolean
  redirect_uri: string
  scopes: string
  groups_claim: string
  login_claim: string
  name_claim: string
  group_roles: GroupRole[]
}

/** То же, но на запись: маску и собранный адрес возврата сервер не ждёт. */
export type OidcSettingsInput = Omit<OidcSettings, 'has_secret' | 'redirect_uri'>

export interface OidcTestResult {
  ok: boolean
  issuer: string | null
  endpoints: {
    authorization: string
    token: string
    jwks: string
    userinfo: string | null
  } | null
  keys: number
  error: string | null
}

export interface AuditItem {
  id: number
  at: string
  user_id: number | null
  login: string
  role: Role | null
  method: string
  path: string
  status: number
  ip: string | null
  summary: string | null
}

export interface AuditFilters {
  /** Пользователи — повторением ключа (buildQuery): «ИЛИ». */
  user_id?: number[]
  /** ISO-строка: поле ввода даёт местное время, в API уходит UTC. */
  since?: string
  until?: string
  denied_only?: boolean
  page: number
  page_size: number
}

export interface AuditResponse {
  total: number
  items: AuditItem[]
}
