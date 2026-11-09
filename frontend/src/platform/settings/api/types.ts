import type { AuthSource, MeGroup } from '@/api/auth'
import type { Access } from '@/platform/access/types'

/** Минимальная длина пароля — та же, что проверяет сервер. */
export const MIN_PASSWORD = 8

export interface UserRow {
  id: number
  login: string
  display_name: string | null
  /** Группы учётки: local ведёт администратор, oidc приходят из провайдера при входе. */
  groups: MeGroup[]
  /** Итоговые права: сервер свёл роли всех групп, побеждает старший уровень. */
  access: Access
  is_active: boolean
  last_login_at: string | null
  created_at: string
  auth_source: AuthSource
}

export interface CreateUserRequest {
  login: string
  display_name: string | null
  /** Только локальные группы. */
  group_ids: number[]
  password: string
}

/** Любое поле можно опустить: PATCH меняет только присланное. */
export interface PatchUserRequest {
  display_name?: string | null
  /** Полный список локальных групп; oidc-группы не трогаются. */
  group_ids?: number[]
  is_active?: boolean
}

export interface SecuritySettings {
  session_ttl_hours: number
  idle_timeout_minutes: number
  audit_retention_days: number
}

/** Настройки модели. Пустой адрес — рабочее состояние, а не ошибка:
 *  без модели работает всё, кроме предложений по разметке и перевода. */
export type LlmProvider = 'ollama' | 'openrouter' | 'deepseek'
export type LlmTaskId = 'attack_embeddings' | 'attack_markup' | 'attack_translation' | 'threat_analysis' | 'vulnerability_assistant'
export interface LlmTaskAssignment {
  provider: LlmProvider
  model: string
  enabled: boolean
  timeout: number
  think: boolean
  local_only: boolean
}
export interface LlmTaskInfo {
  title: string
  description: string
  kind: 'embedding' | 'completion'
  data_class: 'public' | 'redacted' | 'internal'
  providers: LlmProvider[]
}

export interface LlmSettings {
  tasks?: Record<LlmTaskId, LlmTaskAssignment>
  task_catalog?: Record<LlmTaskId, LlmTaskInfo>
  key_updates?: Partial<Record<'openrouter' | 'deepseek', string | undefined>>
  provider?: "ollama" | "openrouter" | "deepseek"
  has_api_key?: boolean
  api_keys?: Record<string, boolean>
  api_key?: string
  base_url: string
  model: string
  embed_model: string
  think: boolean
  timeout: number
  enabled: boolean
}

export interface TestLlmRequest {
  task?: LlmTaskId
  assignment?: LlmTaskAssignment
  think?: boolean
  provider?: "ollama" | "openrouter" | "deepseek"
  api_key?: string
  base_url: string
  model?: string
  timeout?: number
}

export interface TestLlmResponse {
  ok: boolean
  latency_ms: number | null
  error: string | null
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
  /** Названия групп пользователя на момент действия. */
  role: string | null
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
