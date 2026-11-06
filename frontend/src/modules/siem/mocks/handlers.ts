/**
 * Обработчики MSW, реализующие контракт docs/api-contract.md поверх
 * фикстур из ./data. Бэкенда ещё нет — это единственная среда разработки.
 *
 * Переключение на настоящий API: удалить вызов startMockWorker() из
 * src/main.tsx (или выставить VITE_USE_MOCKS=false в .env) — все запросы
 * тогда пойдут на реальный бэкенд по относительным путям /api/*.
 */
import { delay, http, HttpResponse } from 'msw'
import type {
  DeploymentSetsResponse,
  DivergencesResponse,
  FindingsListResponse,
  GraphResponse,
  InstallationProfile,
  JobStatusResponse,
  KbConnectionUpdate,
  KbConnectionView,
  KbTestResponse,
  ProfileSuggestResponse,
  RulesListResponse,
  Settings,
  SnapshotListItem,
  SnapshotSummary,
  CloneCompare,
  DiffLine,
} from '@/modules/siem/api/types'
import type { MeGroup, MeResponse } from '@/api/auth'
import { AREAS, type Access, type Level } from '@/platform/access/types'
import { readStoredTheme } from '@/lib/theme'
import {
  affectedRulesFor,
  ATTACK_GROUPS,
  attackCoverage,
  ruleAttack,
  ruleAttention,
  BUILTIN_ACCOUNTS,
  CLONES,
  DIVERGENCES,
  FIELD_ROLES,
  FINDINGS,
  findingStatus,
  LLM_SETTINGS,
  NAME_SCHEME_SUGGESTION,
  RULES,
  ruleDetail,
  SETTINGS,
  TABLE_RANKING,
} from './data'
import { FIELDS, TECHNIQUE_CATALOG } from './fixtures'

const KB_CONNECTION: KbConnectionView = { host: 'mp.demo.local', kb_port: 8091, verify_tls: false, api_token_set: true, configured: true }

let referenceLoaded: string | null = null
let sessionActive = false
let displayName: string | null = 'Аналитик'

/**
 * Права текущего пользователя в макете. Читаются на каждый запрос, а не
 * при загрузке модуля: так экраны проверяются под тремя наборами прав
 * правкой localStorage и перезагрузкой, без пересборки.
 *
 *   localStorage.setItem('stools-mock-role', 'auditor')
 *
 * admin — всё на уровне «администратор»; analyst — модули «аналитик»,
 * платформа закрыта; auditor — модули «аудитор», платформа закрыта.
 */
function currentAccess(): { access: Access; groups: MeGroup[] } {
  const stored = window.localStorage.getItem('stools-mock-role') ?? 'admin'
  const matrix = (module: Level, platform: Level) =>
    Object.fromEntries(AREAS.map((a) => [a, a === 'platform' || a === 'irp' ? platform : module])) as Access
  if (stored === 'analyst')
    return { access: matrix('write', 'deny'), groups: [{ id: 2, name: 'Аналитики', source: 'local' }] }
  if (stored === 'auditor')
    return { access: matrix('read', 'deny'), groups: [{ id: 3, name: 'Аудиторы', source: 'local' }] }
  return { access: matrix('admin', 'admin'), groups: [{ id: 1, name: 'Администраторы', source: 'local' }] }
}

/** Имя из профиля: его меняет обработчик PATCH /api/auth/me платформенного мока. */
export function setMockDisplayName(value: string | null): void {
  displayName = value
}

/** Ответ «сессии нет» или null, если вход выполнен. Обработчики других
 *  модулей проверяют сессию тем же способом: мок, отвечающий данными
 *  до входа, показывал бы экран, которого в продукте не бывает. */
export const noSession = () =>
  sessionActive
    ? null
    : HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })

const CURRENT_ID = 2
const PREVIOUS_ID = 1

const SNAPSHOTS: SnapshotListItem[] = [
  {
    id: CURRENT_ID,
    created_at: '2026-08-24T09:12:00Z',
    filename: 'knowledgebase_2026_08_24.zip',
    rule_count: RULES.length,
    finding_count: FINDINGS.length,
    kb_version: '30.0.6825',
    parsed: true,
    source_type: 'api',
    kb_host: 'mp.demo.local',
    kb_database: 'Default',
  },
  {
    id: PREVIOUS_ID,
    created_at: '2026-08-10T08:03:00Z',
    filename: 'knowledgebase_2026_08_10.zip',
    rule_count: RULES.length,
    finding_count: 1108,
    kb_version: '30.0.6702',
    parsed: true,
    source_type: 'upload',
    kb_host: null,
    kb_database: null,
  },
]

let profileConfirmed = false
const currentProfile: InstallationProfile = {
  tables: {
    scoping: TABLE_RANKING.filter((t) => t.is_scoping).map((t) => t.name),
    watched: [],
  },
  builtin_accounts: BUILTIN_ACCOUNTS,
  field_roles: FIELD_ROLES,
  name_scheme: NAME_SCHEME_SUGGESTION,
  confirmed_by: null,
  confirmed_at: null,
}

function count<T extends string>(items: readonly T[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const v of items) out[v] = (out[v] ?? 0) + 1
  return out
}

function buildSummary(id: number): SnapshotSummary {
  if (id === PREVIOUS_ID) {
    return {
      id: PREVIOUS_ID,
      created_at: '2026-08-10T08:03:00Z',
      filename: 'knowledgebase_2026_08_10.zip',
      source_type: 'upload',
      kb_host: null,
      kb_database: null,
      rule_count: RULES.length,
      group_count: 44,
      rules_without_code: 0,
      unsupported_count: 3,
      edge_count: 40,
      scoped_count: 60,
      finding_count: 1108,
      findings_by_kind: { '1': 495, '2': 376, '3': 34, '4': 20, '5': 183 },
      findings_by_polarity: { negation: 143, assertion: 965 },
      findings_by_object_type: { correlation: 1073, filter: 27, enrichment: 8 },
      objects_with_findings: 87,
      in_table_count: 495,
      divergence_count: 495,
      clone_count: 15,
      rules_without_msgid: 40,
      name_scheme_coverage: '187/187',
      profile_confirmed: false,
      authors: { DEMO: 172, acme: 9, SOC: 5, IOC: 1 },
      table_ranking: TABLE_RANKING,
      delta: null,
    }
  }

  const kindFacets = count(FINDINGS.map((f) => f.kind))
  const polarityFacets = count(FINDINGS.map((f) => f.polarity))
  const objectTypeFacets = count(FINDINGS.map((f) => f.object_type))
  const objectsWithFindings = new Set(FINDINGS.map((f) => f.object_uuid)).size

  return {
    id: CURRENT_ID,
    created_at: '2026-08-24T09:12:00Z',
    filename: 'knowledgebase_2026_08_24.zip',
    source_type: 'api',
    kb_host: 'mp.demo.local',
    kb_database: 'Default',
    rule_count: RULES.length,
    group_count: 44,
    rules_without_code: 0,
    unsupported_count: RULES.filter((r) => r.parse_status === 'unsupported').length,
    edge_count: 40,
    scoped_count: RULES.filter((r) => r.scoped).length,
    finding_count: FINDINGS.length,
    findings_by_kind: kindFacets as SnapshotSummary['findings_by_kind'],
    findings_by_polarity: polarityFacets as SnapshotSummary['findings_by_polarity'],
    findings_by_object_type: objectTypeFacets as SnapshotSummary['findings_by_object_type'],
    objects_with_findings: objectsWithFindings,
    in_table_count: FINDINGS.filter((f) => f.in_table).length,
    divergence_count: DIVERGENCES.length,
    clone_count: CLONES.length,
    rules_without_msgid: RULES.filter((r) => r.msgid_count === 0).length,
    name_scheme_coverage: '187/187',
    profile_confirmed: profileConfirmed,
    authors: { DEMO: 172, acme: 9, SOC: 5, IOC: 1 },
    table_ranking: TABLE_RANKING,
    delta: { finding_count: FINDINGS.length - 1108, rule_count: 0 },
  }
}

// --- Задания загрузки -----------------------------------------------------

interface MockJob {
  id: number
  startedAt: number
  failReason: string | null
}

const JOBS = new Map<number, MockJob>()
let jobSeq = 1

const STAGE_DURATION_MS = 1400

function jobStatus(job: MockJob): JobStatusResponse {
  if (job.failReason) {
    return { id: job.id, stage: 'parsing', status: 'failed', progress: 0, error: job.failReason, snapshot_id: null }
  }
  const elapsed = Date.now() - job.startedAt
  const stages: { stage: JobStatusResponse['stage']; from: number; to: number }[] = [
    { stage: 'pending', from: 0, to: 5 },
    { stage: 'parsing', from: 5, to: 55 },
    { stage: 'analyzing', from: 55, to: 85 },
    { stage: 'persisting', from: 85, to: 99 },
  ]
  const totalDuration = STAGE_DURATION_MS * 4
  if (elapsed >= totalDuration) {
    return { id: job.id, stage: 'done', status: 'done', progress: 100, error: null, snapshot_id: CURRENT_ID }
  }
  const stageIndex = Math.min(3, Math.floor(elapsed / STAGE_DURATION_MS))
  const stageElapsed = elapsed - stageIndex * STAGE_DURATION_MS
  const { stage, from, to } = stages[stageIndex]
  const progress = Math.round(from + (to - from) * (stageElapsed / STAGE_DURATION_MS))
  return { id: job.id, stage, status: 'running', progress, error: null, snapshot_id: CURRENT_ID }
}

// --- Хеш файла для дедупликации --------------------------------------------

const knownHashes = new Map<string, number>()

async function hashFile(file: File): Promise<string> {
  const buf = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

const DEMO_SET_IDS = ['set-install', 'set-windows', 'set-linux']
/** Имена наборов для карточки правила: сервер отдаёт там названия, а не идентификаторы KB. */
const DEMO_SET_NAMES: Record<string, string> = { 'set-install': 'install', 'set-windows': 'Windows', 'set-linux': 'Linux' }

/** Инвентарь KB для мока: снапшот CURRENT_ID «собран по API», остальные — из файла. */
function kbFields(uuid: string): { installed: boolean | null; folder_path: string | null; deployment_sets: string[] } {
  const n = parseInt(uuid.slice(-2), 16)
  return {
    installed: n % 5 !== 0,
    folder_path: n % 3 === 0 ? 'PT/Windows' : n % 3 === 1 ? 'PT/Linux' : 'Local/Drafts',
    deployment_sets: n % 5 !== 0 ? [DEMO_SET_IDS[0], DEMO_SET_IDS[1 + (n % 2)]] : [],
  }
}

/** Разметка есть только у снапшота по API; у снапшота из файла — пусто, как отдаёт сервер. */
function kbFieldsFor(uuid: string, snapshotId: number): ReturnType<typeof kbFields> {
  return snapshotId === CURRENT_ID ? kbFields(uuid) : { installed: null, folder_path: null, deployment_sets: [] }
}

export const handlers = [
  // --- Аутентификация -------------------------------------------------
  http.post('/api/auth/login', async ({ request }) => {
    await delay(300)
    const body = (await request.json()) as { login?: string; password?: string }
    if (!body.login || !body.password || body.password.length < 4) {
      return HttpResponse.json({ detail: 'Неверный логин или пароль' }, { status: 401 })
    }
    sessionActive = true
    return new HttpResponse(null, { status: 204 })
  }),

  http.post('/api/auth/logout', async () => {
    sessionActive = false
    return new HttpResponse(null, { status: 204 })
  }),

  http.get('/api/auth/me', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json<MeResponse>({
      login: 'analyst',
      display_name: displayName,
      ...currentAccess(),
      // Профиля за моком нет, поэтому «сервер» помнит тему там же, где её
      // держит сам интерфейс, — иначе выбор сбрасывался бы на перезагрузке.
      theme: readStoredTheme() ?? 'dark',
      auth_source: 'local',
    })
  }),

  /**
   * Состояние входа через провайдера. Ручка публичная — сессия не нужна.
   * Кнопка на странице входа включается правкой localStorage: обе стороны
   * (с провайдером и без) должны проверяться без пересборки.
   *
   *   localStorage.setItem('stools-mock-oidc', '1')
   */
  http.get('/api/auth/oidc/status', () =>
    HttpResponse.json({
      enabled: window.localStorage.getItem('stools-mock-oidc') === '1',
      display_name: 'Avanpost',
    }),
  ),

  // --- Снапшоты ---------------------------------------------------------
  http.get('/api/siem/snapshots', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(SNAPSHOTS)
  }),

  http.get('/api/siem/snapshots/:id', ({ params }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const id = Number(params.id)
    if (id !== CURRENT_ID && id !== PREVIOUS_ID) {
      return HttpResponse.json({ detail: 'Снапшот не найден' }, { status: 404 })
    }
    return HttpResponse.json(buildSummary(id))
  }),

  http.post('/api/siem/snapshots', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const form = await request.formData()
    const file = form.get('file')
    if (!(file instanceof File)) {
      return HttpResponse.json({ detail: 'Файл не найден в запросе' }, { status: 422 })
    }
    if (!file.name.toLowerCase().endsWith('.zip')) {
      return HttpResponse.json({ detail: 'Ожидался zip-архив выгрузки базы знаний' }, { status: 422 })
    }
    const hash = await hashFile(file)
    const existing = knownHashes.get(hash)
    const jobId = jobSeq++
    if (existing !== undefined) {
      JOBS.set(jobId, { id: jobId, startedAt: Date.now() - STAGE_DURATION_MS * 5, failReason: null })
      return HttpResponse.json({ job_id: jobId, snapshot_id: existing, duplicate: true })
    }
    knownHashes.set(hash, CURRENT_ID)
    const failReason = file.size === 0 ? 'Архив пуст' : null
    JOBS.set(jobId, { id: jobId, startedAt: Date.now(), failReason })
    return HttpResponse.json({ job_id: jobId, snapshot_id: CURRENT_ID })
  }),

  http.get('/api/siem/jobs/:id', ({ params }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const job = JOBS.get(Number(params.id))
    if (!job) return HttpResponse.json({ detail: 'Задание не найдено' }, { status: 404 })
    return HttpResponse.json(jobStatus(job))
  }),

  // --- Находки ------------------------------------------------------------
  http.get('/api/siem/findings', ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const url = new URL(request.url)
    const p = url.searchParams

    type Filters = {
      kind?: string[]
      polarity?: string[]
      object_type?: string[]
      in_table?: string
      status?: string
      field?: string[]
      shape?: string[]
      object_uuid?: string
      key?: string
      q?: string
    }
    // Перечислимые фасеты, как на сервере, — повторением ключа (`kind=1&kind=2`), «ИЛИ» внутри фасета.
    const many = (key: string) => { const v = p.getAll(key); return v.length ? v : undefined }
    // Без статуса — открытые, как на сервере; `all` — все; статус понимает и старую запись через запятую.
    const rawStatuses = p.getAll('status').flatMap((s) => s.split(','))
    const statuses = rawStatuses[0] === 'all' ? null : rawStatuses.length ? rawStatuses : ['new', 'in_work', 'fixed', 'reopened']
    const filters: Filters = {
      kind: many('kind'),
      polarity: many('polarity'),
      object_type: many('object_type'),
      in_table: p.get('in_table') ?? undefined,
      status: p.get('status') ?? undefined,
      field: many('field'),
      shape: many('shape'),
      object_uuid: p.get('object_uuid') ?? undefined,
      key: p.get('key') ?? undefined,
      q: p.get('q') ?? undefined,
    }

    const oneOf = (picked: string[] | undefined, value: string) => picked === undefined || picked.includes(value)

    function applies(f: (typeof FINDINGS)[number], except: keyof Filters | null): boolean {
      if (filters.kind && except !== 'kind' && !oneOf(filters.kind, f.kind)) return false
      if (filters.polarity && except !== 'polarity' && !oneOf(filters.polarity, f.polarity)) return false
      if (filters.object_type && except !== 'object_type' && !oneOf(filters.object_type, f.object_type)) return false
      if (filters.in_table && except !== 'in_table' && String(f.in_table) !== filters.in_table) return false
      if (statuses && except !== 'status' && !statuses.includes(findingStatus(f.id))) return false
      if (filters.key && f.key !== filters.key) return false
      if (filters.field && except !== 'field' && !oneOf(filters.field, f.field)) return false
      if (filters.shape && except !== 'shape' && !oneOf(filters.shape, f.shape ?? 'plain')) return false
      if (filters.object_uuid && except !== 'object_uuid' && f.object_uuid !== filters.object_uuid)
        return false
      if (filters.q && except !== 'q') {
        const needle = filters.q.toLowerCase()
        const haystack = `${f.object_name} ${f.field} ${f.table_name ?? ''}`.toLowerCase()
        if (!haystack.includes(needle)) return false
      }
      return true
    }

    const withStatus = FINDINGS.map((f) => ({ ...f, status: findingStatus(f.id) }))
    const filtered = withStatus.filter((f) => applies(f, null))

    const sort = p.get('sort') ?? 'id'
    const order = p.get('order') === 'desc' ? -1 : 1
    const sorted = [...filtered].sort((a, b) => {
      const av = String(a[sort as keyof typeof a] ?? '')
      const bv = String(b[sort as keyof typeof b] ?? '')
      return av < bv ? -order : av > bv ? order : 0
    })

    // Предел тот же, что у сервера: мок, отдающий всё разом, скрыл бы
    // ошибку «клиент рассчитывает получить выгрузку одной страницей».
    const limit = Number(p.get('limit') ?? 100)
    if (limit > 1000) {
      return HttpResponse.json(
        { detail: 'limit не может превышать 1000' },
        { status: 422 },
      )
    }
    const offset = Number(p.get('offset') ?? 0)
    const page = sorted.slice(offset, offset + limit)

    function facetCounts<K extends Filters[keyof Filters] extends string | undefined ? string : never>(
      key: keyof Filters,
      extractor: (f: (typeof withStatus)[number]) => string,
    ): Record<string, number> {
      const pool = withStatus.filter((f) => applies(f, key))
      return count(pool.map(extractor)) as Record<K, number>
    }

    const response: FindingsListResponse = {
      total: filtered.length,
      items: page,
      facets: {
        kind: facetCounts('kind', (f) => f.kind),
        polarity: facetCounts('polarity', (f) => f.polarity),
        object_type: facetCounts('object_type', (f) => f.object_type),
        field: facetCounts('field', (f) => f.field),
        in_table: facetCounts('in_table', (f) => String(f.in_table)) as { true?: number; false?: number },
        shape: facetCounts('shape', (f) => f.shape ?? 'plain'),
        status: facetCounts('status', (f) => findingStatus(f.id)),
        assignee: { none: withStatus.filter((f) => applies(f, null)).length },
        flags: { overdue: 0, risk_expiring: 0 },
      },
      is_latest: Number(p.get('snapshot_id')) === CURRENT_ID,
      statuses_as_of: 'today',
      status_keys_broken: false,
    }
    return HttpResponse.json(response)
  }),

  http.get('/api/siem/findings/:id/detail', ({ params }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const id = Number(params.id)
    const finding = FINDINGS.find((f) => f.id === id)
    if (!finding) return HttpResponse.json({ detail: 'Находка не найдена' }, { status: 404 })
    const sampleValues: Record<string, string> = {
      '1': 'wks-fin-0231.corp.local',
      '2': '10.44.12.0/24',
      '3': 'svc_backup, svc_monitor, svc_report',
      '4': 'S-1-5-21-3623811015-3361044348-30300820-1013',
      '5': 'C:\\Windows\\Temp\\payload.exe',
    }
    return HttpResponse.json({
      value: finding.has_value ? sampleValues[finding.kind] : '',
      body_excerpt: `... ${finding.polarity === 'negation' ? '!=' : '=='} ${finding.field} ...`,
      table_name: finding.table_name,
      affected_rules: affectedRulesFor(finding.object_name),
    })
  }),

  // --- Расхождения ------------------------------------------------------
  http.get('/api/siem/divergences', ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const p = new URL(request.url).searchParams
    // Предел тот же, что у сервера: мок, отдающий всё разом, скрыл бы
    // ошибку «клиент рассчитывает получить выгрузку одной страницей».
    const limit = Number(p.get('limit') ?? 100)
    if (limit > 1000) {
      return HttpResponse.json(
        { detail: 'limit не может превышать 1000' },
        { status: 422 },
      )
    }
    const offset = Number(p.get('offset') ?? 0)
    const response: DivergencesResponse = {
      total: DIVERGENCES.length,
      items: DIVERGENCES.slice(offset, offset + limit),
    }
    return HttpResponse.json(response)
  }),

  // --- Правила --------------------------------------------------------------
  http.get('/api/siem/rules', ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const p = new URL(request.url).searchParams
    const author = p.get('author')
    const category = p.get('category')
    const group = p.get('group')
    const q = p.get('q')?.toLowerCase()

    const filtered = RULES.filter((r) => {
      if (author && r.author !== author) return false
      if (category && r.category !== category) return false
      if (group && r.group !== group) return false
      if (q && !r.name.toLowerCase().includes(q)) return false
      return true
    })

    const limit = Number(p.get('limit') ?? 200)
    const offset = Number(p.get('offset') ?? 0)
    const response: RulesListResponse = {
      total: filtered.length,
      // Разметка наследуется от группы — так же, как её отдаёт сервер.
      items: filtered.slice(offset, offset + limit).map((r) => {
        const attention = ruleAttention(r.uuid)
        return {
          ...r,
          open_finding_count: attention.open,
          max_severity: attention.worst,
          attack: ruleAttack(r.name),
          ...kbFieldsFor(r.uuid, Number(p.get('snapshot_id'))),
        }
      }),
    }
    return HttpResponse.json(response)
  }),

  http.get('/api/siem/rules/:uuid', ({ params, request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const detail = ruleDetail(String(params.uuid))
    if (!detail) return HttpResponse.json({ detail: 'Правило не найдено' }, { status: 404 })
    const kb = kbFieldsFor(String(params.uuid), Number(new URL(request.url).searchParams.get('snapshot_id')))
    return HttpResponse.json({ ...detail, ...kb, deployment_sets: kb.deployment_sets.map((id) => DEMO_SET_NAMES[id] ?? id) })
  }),


  // --- Разметка ATT&CK ---------------------------------------------------
  http.get('/api/siem/attack/coverage', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(attackCoverage())
  }),

  http.get('/api/siem/attack/groups', ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const wanted = new URL(request.url).searchParams.get('status')
    const items = wanted ? ATTACK_GROUPS.filter((g) => g.status === wanted) : ATTACK_GROUPS
    return HttpResponse.json({ total: items.length, items })
  }),

  http.post('/api/siem/attack/run', async () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    if (!LLM_SETTINGS.base_url.trim()) {
      return HttpResponse.json(
        { detail: 'адрес модели не задан — задайте его в настройках' },
        { status: 409 },
      )
    }
    const jobId = jobSeq++
    JOBS.set(jobId, { id: jobId, startedAt: Date.now(), failReason: null })
    return HttpResponse.json({ job_id: jobId }, { status: 202 })
  }),

  http.post('/api/siem/attack/confirm', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as {
      group?: string
      rule_uuid?: string
      techniques: string[]
    }
    // Разметка ведётся по правилу; в моке правило представлено своей
    // группой — важно, что контракт «либо правило, либо группа» соблюдён.
    if (!body.group === !body.rule_uuid) {
      return HttpResponse.json(
        { detail: 'подтверждать нужно либо правило, либо группу' },
        { status: 422 },
      )
    }
    const group = body.group
      ? ATTACK_GROUPS.find((g) => g.group === body.group)
      : ATTACK_GROUPS.find(() => RULES.some((r) => r.uuid === body.rule_uuid))
    if (group) {
      group.status = 'confirmed'
      group.reviewed_by = 'mock'
      group.reviewed_at = new Date().toISOString()
      // Не только убрать лишнее, но и добавить выбранное: иначе мок
      // молча теряет уточнение подтехниками, и экран показывает,
      // будто правка не сработала, хотя в продукте она работает.
      const kept = group.techniques.filter((t) => body.techniques.includes(t.technique_id))
      const added = body.techniques
        .filter((id) => !kept.some((t) => t.technique_id === id))
        .map((id) => {
          const known = TECHNIQUE_CATALOG.find((t) => t.technique_id === id)
          return {
            technique_id: id,
            name: id,
            name_ru: known?.name_ru ?? id,
            tactics: known?.tactics ?? [],
            confidence: 'высокая' as const,
            evidence: 'выбрано человеком',
            source: 'manual' as const,
          }
        })
      group.techniques = [...kept, ...added]
    }
    return new HttpResponse(null, { status: 204 })
  }),

  // Эталон живёт в памяти мока: экран сверки иначе не проверить,
  // а непроверяемый экран рано или поздно оказывается сломанным.
  http.post('/api/siem/attack/reference', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const form = await request.formData()
    const file = form.get('file')
    const name = file instanceof File ? file.name : 'mapping.xlsx'
    referenceLoaded = name
    return HttpResponse.json({
      source: name,
      rows: 126,
      rows_without_techniques: 0,
      matched_rules: RULES.length - 4,
      matched_by: { code: 124 },
      unmatched_keys: ['JC-HC-001-020', 'JC-NSA-006-801'],
      rules_without_reference: 4,
      migrated_techniques: 12,
      unknown_techniques: [],
      columns: { key: 'ID Условия', techniques: 'MITREID', note: 'Описание' },
    })
  }),

  http.delete('/api/siem/attack/reference', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    referenceLoaded = null
    return new HttpResponse(null, { status: 204 })
  }),

  http.post('/api/siem/attack/reference/apply', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as { rule_uuid?: string; verdicts?: string[] }
    const n = body.rule_uuid ? 1 : body.verdicts?.length ? 12 : 24
    return HttpResponse.json({ applied: n, skipped_empty: 0, considered: n })
  }),

  http.get('/api/siem/attack/reference/compare', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    if (!referenceLoaded) {
      return HttpResponse.json({
        loaded: false,
        source: null,
        imported_at: null,
        imported_by: null,
        compared: 0,
        counts: {},
        items: [],
        unmatched: [],
        rules_without_reference: 0,
      })
    }
    const verdicts = [
      'different',
      'partial',
      'same',
      'reference_finer',
      'no_markup',
      'reference_coarser',
    ] as const
    const items = RULES.slice(0, 24).map((rule, index) => {
      const attack = ruleAttack(rule.name)
      const verdict = verdicts[index % verdicts.length]
      const ours = attack.techniques.map((t) => t.technique_id)
      const theirs =
        verdict === 'same'
          ? ours
          : verdict === 'reference_finer'
            ? ours.map((t) => `${t}.001`)
            : ['T1558.003']
      return {
        uuid: rule.uuid,
        name: rule.name,
        source_key: `JC-${rule.category}-${rule.group}-${String(index).padStart(3, '0')}`,
        verdict,
        ours: verdict === 'no_markup' ? [] : ours,
        theirs,
        original: index % 5 === 0 ? ['T1562.001'] : theirs,
        note: 'Строка из таблицы аналитика',
        status: attack.status,
        inherited: index % 3 !== 0,
      }
    })
    const counts: Record<string, number> = {}
    for (const i of items) counts[i.verdict] = (counts[i.verdict] ?? 0) + 1
    return HttpResponse.json({
      loaded: true,
      source: referenceLoaded,
      imported_at: new Date().toISOString(),
      imported_by: 'analyst',
      compared: items.length,
      counts,
      items,
      unmatched: [{ source_key: 'JC-HC-001-020', theirs: ['T1078'] }],
      rules_without_reference: RULES.length - items.length,
    })
  }),

  // --- Настройки ---------------------------------------------------------
  http.get('/api/siem/settings', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(SETTINGS)
  }),

  http.put('/api/siem/settings', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as Settings
    SETTINGS.attack = { ...body.attack, attack_version: SETTINGS.attack.attack_version }
    return new HttpResponse(null, { status: 204 })
  }),

  // --- База знаний по API ---------------------------------------------------
  http.get('/api/siem/mp', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(KB_CONNECTION)
  }),

  http.put('/api/siem/mp', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as KbConnectionUpdate
    KB_CONNECTION.host = body.host
    KB_CONNECTION.kb_port = body.kb_port
    KB_CONNECTION.verify_tls = body.verify_tls
    if (body.api_token) KB_CONNECTION.api_token_set = true
    KB_CONNECTION.configured = Boolean(KB_CONNECTION.host && KB_CONNECTION.api_token_set)
    return HttpResponse.json(KB_CONNECTION)
  }),

  http.post('/api/siem/mp/test', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    if (!KB_CONNECTION.configured) return HttpResponse.json({ detail: 'подключение не настроено' }, { status: 400 })
    const response: KbTestResponse = { ok: true, message: 'база знаний 27.1.1234 отвечает, БД контента: Default', version: '27.1.1234', database: 'Default', events_ok: true, events_message: 'события отвечают, за минуту: 1' }
    return HttpResponse.json(response)
  }),

  http.post('/api/siem/mp/collect', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    if (!KB_CONNECTION.configured) return HttpResponse.json({ detail: 'подключение не настроено' }, { status: 400 })
    const jobId = jobSeq++
    JOBS.set(jobId, { id: jobId, startedAt: Date.now(), failReason: null })
    return HttpResponse.json({ job_id: jobId }, { status: 202 })
  }),

  http.get('/api/siem/snapshots/:id/deployment-sets', ({ params }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    if (Number(params.id) !== CURRENT_ID) {
      return HttpResponse.json({ available: false, sets: [], objects_total: 0, installed: 0, kb_not_exported: [] })
    }
    const installed = RULES.filter((r) => kbFields(r.uuid).installed).length
    const response: DeploymentSetsResponse = {
      available: true,
      objects_total: RULES.length + 2,
      installed,
      kb_not_exported: ['DEMO_HC_002_099_Draft', 'DEMO_AC_020_050_Draft'],
      sets: [
        { kb_id: 'set-install', parent_kb_id: null, name: 'install', system_name: 'install', general_status: 'Ok', compilation_status: 'Success', deployment_statuses: { main: 'Installed' }, rule_count: installed },
        { kb_id: 'set-windows', parent_kb_id: 'set-install', name: 'Windows', system_name: 'windows', general_status: 'Ok', compilation_status: 'Success', deployment_statuses: { main: 'Installed' }, rule_count: RULES.filter((r) => kbFields(r.uuid).deployment_sets.includes('set-windows')).length },
        { kb_id: 'set-linux', parent_kb_id: 'set-install', name: 'Linux', system_name: 'linux', general_status: 'Outdated', compilation_status: 'Success', deployment_statuses: { main: 'Outdated' }, rule_count: RULES.filter((r) => kbFields(r.uuid).deployment_sets.includes('set-linux')).length },
      ],
    }
    return HttpResponse.json(response)
  }),

  // --- Клоны и граф -----------------------------------------------------
  http.get('/api/siem/clones', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(CLONES)
  }),

  http.get('/api/siem/clones/compare', ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const url = new URL(request.url)
    const a = url.searchParams.get('rule_a') ?? ''
    const b = url.searchParams.get('rule_b') ?? ''
    const pair = CLONES.find((c) => (c.rule_a === a && c.rule_b === b) || (c.rule_a === b && c.rule_b === a))
    const bodyA = `event Start:\n    key: src.ip, subject.name\n    filter {\n        msgid == "4624"\n        and subject.name != null\n        and logon_type == 10\n    }\n\nrule ${a}: Start\n\nemit {\n    $importance = "medium"\n}\n`
    const bodyB = `event Start:\n    key: src.ip, subject.name\n    filter {\n        msgid == "4625"\n        and subject.name != null\n        and logon_type == 10\n        and filter::Whitelist_Accounts(subject.name)\n    }\n\nrule ${b}: Start\n\nemit {\n    $importance = "high"\n}\n`
    const la = bodyA.split('\n')
    const lb = bodyB.split('\n')
    const lines: DiffLine[] = []
    let i = 0
    let j = 0
    while (i < la.length || j < lb.length) {
      const x = la[i]
      const y = lb[j]
      if (x === y) { lines.push({ kind: 'equal', a: x, b: y }); i++; j++; continue }
      if (y !== undefined && y.includes('Whitelist')) { lines.push({ kind: 'insert', a: null, b: y }); j++; continue }
      lines.push({ kind: 'replace', a: x ?? null, b: y ?? null }); i++; j++
    }
    const response: CloneCompare = {
      a: { uuid: 'aaaa', name: a, title: `Заголовок ${a}`, body: bodyA },
      b: { uuid: 'bbbb', name: b, title: `Заголовок ${b}`, body: bodyB },
      similarity: pair?.similarity ?? null,
      signature: {
        msgids: { common: ['4688'], only_a: ['4624'], only_b: ['4625'] },
        fields: { common: ['src.ip', 'subject.name'], only_a: [], only_b: [] },
        filters: { common: [], only_a: [], only_b: ['Whitelist_Accounts'] },
      },
      lines,
      changed_lines: lines.filter((l) => l.kind !== 'equal').length,
    }
    return HttpResponse.json(response)
  }),

  http.get('/api/siem/graph', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const edges = RULES.filter((r) => r.table_reads > 0)
      .slice(0, 40)
      .map((r, i) => ({ parent: RULES[(i * 7) % RULES.length].name, child: r.name }))
    const response: GraphResponse = {
      edges,
      unresolved: { correlation_name: ['DEMO_Legacy_Detect_Removed'] },
    }
    return HttpResponse.json(response)
  }),

  // --- Профиль ------------------------------------------------------------
  http.get('/api/siem/profile', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    return HttpResponse.json(currentProfile)
  }),

  http.get('/api/siem/profile/suggest', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const response: ProfileSuggestResponse = {
      tables: {
        scoping: TABLE_RANKING.filter((t) => t.is_scoping).map((t) => t.name),
        watched: TABLE_RANKING.filter((t) => t.risk > 20 && !t.is_scoping).map((t) => t.name),
      },
      builtin_accounts: BUILTIN_ACCOUNTS,
      field_roles: FIELD_ROLES,
    field_roles_default: { environmental: ['src.ip', 'dst.host'], technical: ['msgid'] },
      name_scheme: NAME_SCHEME_SUGGESTION,
      confirmed_by: null,
      confirmed_at: null,
    }
    return HttpResponse.json(response)
  }),

  http.get('/api/siem/profile/fields', () => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const items = FIELDS.map((f, i) => ({
      field: f,
      rule_count: 200 - i * 7,
      role: i < 3 ? 'environmental' : i < 6 ? 'technical' : 'unknown',
      source: i < 4 ? 'taxonomy' : i < 6 ? 'builtin' : 'none',
      from_profile: false,
    }))
    return HttpResponse.json({
      total: items.length,
      unknown: items.filter((i) => i.role === 'unknown').length,
      from_taxonomy: items.filter((i) => i.source === 'taxonomy').length,
      items,
    })
  }),

  http.post('/api/siem/profile/preview', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as {
      tables: { scoping: string[] }
      field_roles: { environmental: string[] }
      builtin_accounts: string[]
    }
    // Правдоподобная арифметика: средовое поле добавляет замечания,
    // встроенная учётка убирает, отмеченный список ограничивает правила.
    return HttpResponse.json({
      finding_count:
        FINDINGS.length + body.field_roles.environmental.length * 40 -
        body.builtin_accounts.length * 8,
      scoped_count: body.tables.scoping.length * 30,
      group_count: ATTACK_GROUPS.length,
    })
  }),

  http.put('/api/siem/profile', async ({ request }) => {
    if (!sessionActive) return HttpResponse.json({ detail: 'Сессия не найдена, войдите заново' }, { status: 401 })
    const body = (await request.json()) as Omit<InstallationProfile, 'table_ranking'>
    currentProfile.tables = body.tables
    currentProfile.builtin_accounts = body.builtin_accounts
    currentProfile.field_roles = body.field_roles
    currentProfile.name_scheme = body.name_scheme ?? currentProfile.name_scheme
    profileConfirmed = true
    return new HttpResponse(null, { status: 204 })
  }),
]
