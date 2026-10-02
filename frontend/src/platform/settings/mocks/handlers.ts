/**
 * Обработчики MSW для платформенной части: профиль и пароль, а также
 * общие настройки (/api/settings/*) — пользователи, безопасность,
 * журнал действий, модель и база ATT&CK.
 *
 * Сессия проверяется тем же способом, что и в моках модулей: мок,
 * отвечающий данными до входа, показывал бы экран, которого в продукте
 * не бывает.
 */
import { http, HttpResponse } from 'msw'
import type { Role } from '@/api/auth'
import type { AttackBundleDiff, AttackBundleState, PendingBundle } from '@/modules/attack/api/types'
import { startMockBundleDownload } from '@/modules/attack/mocks/handlers'
import { LLM_SETTINGS } from '@/modules/siem/mocks/data'
import { TECHNIQUE_CATALOG } from '@/modules/siem/mocks/fixtures'
import { noSession, setMockDisplayName } from '@/modules/siem/mocks/handlers'
import { applyTheme, readStoredTheme, type Theme } from '@/lib/theme'
import type {
  AuditItem,
  CreateUserRequest,
  LlmSettings,
  OidcSettings,
  OidcSettingsInput,
  PatchUserRequest,
  SecuritySettings,
  UserRow,
} from '@/platform/settings/api/types'

/** Пароль «pw» в макете считается текущим — иначе не посмотреть ни успех, ни отказ. */
const MOCK_PASSWORD = 'pw'

const MIN_PASSWORD = 8

/** Логин текущего пользователя в макете — тот же, что отдаёт мок
 *  /api/auth/me в modules/siem/mocks/handlers.ts. Одна из учёток списка
 *  носит его, иначе защиту своей строки не увидеть. Администратор в
 *  списке — другая учётка: иначе обе защиты («себя изменить нельзя» и
 *  «последний администратор») легли бы на одну строку, и вторую не
 *  посмотреть. */
const MOCK_ME = 'analyst'

const ROLES: Role[] = ['admin', 'analyst', 'auditor']

let nextUserId = 5
const users: UserRow[] = [
  {
    id: 1,
    login: 'admin',
    display_name: 'Пётр Смирнов',
    role: 'admin',
    is_active: true,
    last_login_at: '2026-09-12T08:41:00Z',
    created_at: '2026-05-04T10:00:00Z',
    auth_source: 'local',
  },
  {
    id: 2,
    login: MOCK_ME,
    display_name: 'Анна Кузнецова',
    role: 'analyst',
    is_active: true,
    last_login_at: '2026-09-11T14:07:00Z',
    created_at: '2026-06-18T09:30:00Z',
    auth_source: 'local',
  },
  {
    id: 3,
    login: 'aud',
    display_name: null,
    role: 'auditor',
    is_active: false,
    last_login_at: null,
    created_at: '2026-08-02T12:15:00Z',
    auth_source: 'local',
  },
  // Учётка из провайдера: у неё нет пароля, и сбрасывать его нечем —
  // без такой строки пометку «FAM» и спрятанную кнопку не посмотреть.
  {
    id: 4,
    login: 'i.petrov',
    display_name: 'Иван Петров',
    role: 'analyst',
    is_active: true,
    last_login_at: '2026-09-13T07:22:00Z',
    created_at: '2026-09-01T11:40:00Z',
    auth_source: 'oidc',
  },
]

/** Маска секрета — та же, что отдаёт сервер. */
const SECRET_MASK = '••••'

/** Настройки входа через провайдера. Секрет хранится отдельно от ответа:
 *  наружу он не уходит, как и в продукте. */
const oidc: OidcSettingsInput = {
  enabled: false,
  display_name: 'Avanpost',
  public_url: 'https://stools.example.ru',
  issuer_url: 'https://fam.example.ru',
  client_id: 'stools',
  client_secret: 's3cret',
  scopes: 'openid profile email groups',
  groups_claim: 'groups',
  login_claim: 'preferred_username',
  name_claim: 'name',
  group_roles: [{ group: 'stools-admins', role: 'admin' }],
}

function oidcView(): OidcSettings {
  return {
    ...oidc,
    client_secret: oidc.client_secret ? SECRET_MASK : '',
    has_secret: oidc.client_secret !== '',
    redirect_uri: oidc.public_url.replace(/\/+$/, '') + '/api/auth/oidc/callback',
  }
}

const security: SecuritySettings = {
  session_ttl_hours: 12,
  idle_timeout_minutes: 0,
  audit_retention_days: 90,
}

/** Шестьдесят событий: отказы, изменения и разбор выгрузок вперемешку —
 *  на одной странице (50) отбор и пагинацию видно сразу. */
const AUDIT_SHAPES: Array<[string, string, number, string | null]> = [
  ['POST', '/api/siem/snapshots', 201, 'выгрузка knowledgebase_2026_08_24.zip'],
  ['PUT', '/api/siem/settings', 204, 'адрес модели изменён'],
  ['POST', '/api/settings/users', 201, 'создан пользователь ann'],
  ['PATCH', '/api/settings/users/2', 200, 'роль: аналитик'],
  ['DELETE', '/api/settings/users/7', 403, 'нужна роль: администратор'],
  ['PUT', '/api/siem/profile', 403, 'нужна роль: аналитик'],
  ['POST', '/api/siem/attack/confirm', 204, 'разметка группы Kerberos подтверждена'],
]

const audit: AuditItem[] = Array.from({ length: 60 }, (_, i) => {
  const id = 60 - i
  const [method, path, status, summary] = AUDIT_SHAPES[id % AUDIT_SHAPES.length]
  const actor = users[id % users.length]
  return {
    id,
    at: new Date(Date.UTC(2026, 8, 12, 9, 0) - i * 37 * 60_000).toISOString(),
    user_id: actor.id,
    login: actor.login,
    role: actor.role,
    method,
    path,
    status,
    ip: `10.10.0.${20 + (id % 6)}`,
    summary,
  }
})

/** Действующая матрица в макете. Изменяемая: без этого не посмотреть, что
 *  меняет применение скачанного или загруженного файла. */
const bundle: AttackBundleState = {
  version: '19.2',
  source: 'builtin',
  loaded_at: '2026-08-26T09:00:00Z',
  loaded_by: null,
  technique_count: TECHNIQUE_CATALOG.length,
  tactic_count: 15,
  translated: TECHNIQUE_CATALOG.length,
  missing: 0,
  stale: 0,
  replacement: null,
}

/** Версия, которую «отдаёт» сайт MITRE, и адрес, с которого она идёт. */
const ONLINE_VERSION = '19.3'
const ONLINE_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

/** Разница придумана: важно не правдоподобие чисел, а то, что видны все
 *  пять счётчиков и предупреждение о смене состава тактик. */
function bundleDiff(version: string | null): AttackBundleDiff {
  return {
    version,
    current_version: bundle.version,
    added: ['T1665', 'T1666'],
    changed: ['T1059.001', 'T1078', 'T1558.003'],
    removed: ['T1064'],
    tactics_added: ['resource-development'],
    tactics_removed: [],
    untranslated: 2,
    stale_translations: 1,
  }
}

/** Скачанное, ждущее подтверждения, и момент, с которого его «уже скачали»:
 *  до конца задания ручная перезагрузка экрана не должна его показывать. */
let pending: { readyAt: number; value: PendingBundle } | null = null

function pendingNow(): PendingBundle | null {
  if (!pending || Date.now() < pending.readyAt) return null
  return pending.value
}

/** Матрицу приняли — версия и происхождение меняются, перевод отстаёт. */
function acceptBundle(version: string | null, source: 'uploaded' | 'online', diff: AttackBundleDiff) {
  bundle.version = version
  bundle.source = source
  bundle.loaded_at = new Date().toISOString()
  bundle.loaded_by = source === 'online' ? null : MOCK_ME
  bundle.missing = diff.untranslated
  bundle.stale = diff.stale_translations
  bundle.translated = bundle.technique_count - diff.untranslated
}

const conflict = (detail: string) => HttpResponse.json({ detail }, { status: 409 })
const unprocessable = (detail: string) => HttpResponse.json({ detail }, { status: 422 })

const activeAdmins = () => users.filter((u) => u.role === 'admin' && u.is_active).length

export const platformHandlers = [
  http.post('/api/auth/password', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { current?: string; new?: string }
    if (body.current !== MOCK_PASSWORD) {
      return HttpResponse.json({ detail: 'текущий пароль неверен' }, { status: 400 })
    }
    return new HttpResponse(null, { status: 204 })
  }),

  http.patch('/api/auth/me', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { display_name?: string | null; theme?: Theme }
    // Как на сервере: незаданное поле не трогают. Тема тут не хранится —
    // её помнит localStorage, который уже переписал сам переключатель.
    if ('display_name' in body) setMockDisplayName(body.display_name ?? null)
    if (body.theme && body.theme !== readStoredTheme()) applyTheme(body.theme)
    return new HttpResponse(null, { status: 204 })
  }),

  // --- Пользователи -----------------------------------------------------

  http.get('/api/settings/users', () => {
    const denied = noSession()
    if (denied) return denied
    return HttpResponse.json(users)
  }),

  http.post('/api/settings/users', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as CreateUserRequest
    if (users.some((u) => u.login === body.login)) {
      return conflict('пользователь с таким логином уже есть')
    }
    if (!ROLES.includes(body.role)) return unprocessable('роль должна быть одной из: ' + ROLES.join(', '))
    if ((body.password ?? '').length < MIN_PASSWORD) {
      return unprocessable(`пароль короче ${MIN_PASSWORD} символов`)
    }
    const row: UserRow = {
      id: nextUserId++,
      login: body.login,
      display_name: body.display_name,
      role: body.role,
      is_active: true,
      last_login_at: null,
      created_at: new Date().toISOString(),
      auth_source: 'local',
    }
    users.push(row)
    return HttpResponse.json(row, { status: 201 })
  }),

  http.patch('/api/settings/users/:id', async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const row = users.find((u) => u.id === Number(params.id))
    if (!row) return HttpResponse.json({ detail: 'пользователь не найден' }, { status: 404 })
    const body = (await request.json()) as PatchUserRequest

    // Те же две защиты, что на сервере: без них не проверить, как экран
    // показывает отказ по правке, о которой клиент знать не мог.
    const losesAdmin =
      row.role === 'admin' &&
      row.is_active &&
      ((body.role !== undefined && body.role !== 'admin') || body.is_active === false)
    if (losesAdmin && row.login === MOCK_ME) return conflict('нельзя понизить или заблокировать себя')
    if (losesAdmin && activeAdmins() <= 1) return conflict('это последний активный администратор')

    if (body.display_name !== undefined) row.display_name = body.display_name
    if (body.role !== undefined) row.role = body.role
    if (body.is_active !== undefined) row.is_active = body.is_active
    return HttpResponse.json(row)
  }),

  http.delete('/api/settings/users/:id', ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const index = users.findIndex((u) => u.id === Number(params.id))
    if (index === -1) return HttpResponse.json({ detail: 'пользователь не найден' }, { status: 404 })
    const row = users[index]
    if (row.login === MOCK_ME) return conflict('нельзя удалить себя')
    if (row.role === 'admin' && row.is_active && activeAdmins() <= 1) {
      return conflict('это последний активный администратор')
    }
    users.splice(index, 1)
    return new HttpResponse(null, { status: 204 })
  }),

  http.post('/api/settings/users/:id/password', async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const row = users.find((u) => u.id === Number(params.id))
    if (!row) return HttpResponse.json({ detail: 'пользователь не найден' }, { status: 404 })
    if (row.auth_source === 'oidc') return conflict('пароль этой учётки задаётся в провайдере входа')
    const body = (await request.json()) as { password?: string }
    if ((body.password ?? '').length < MIN_PASSWORD) {
      return unprocessable(`пароль короче ${MIN_PASSWORD} символов`)
    }
    return new HttpResponse(null, { status: 204 })
  }),

  // --- Безопасность -----------------------------------------------------

  http.get('/api/settings/security', () => {
    const denied = noSession()
    if (denied) return denied
    return HttpResponse.json(security)
  }),

  http.put('/api/settings/security', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as Partial<SecuritySettings>
    Object.assign(security, body)
    return new HttpResponse(null, { status: 204 })
  }),

  // --- Модель -----------------------------------------------------------

  http.get('/api/settings/llm', () => noSession() ?? HttpResponse.json(LLM_SETTINGS)),

  http.put('/api/settings/llm', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    Object.assign(LLM_SETTINGS, (await request.json()) as LlmSettings)
    return new HttpResponse(null, { status: 204 })
  }),

  http.post('/api/settings/llm/test', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { base_url?: string }
    if (!body.base_url?.trim()) {
      return HttpResponse.json({ ok: false, latency_ms: null, error: 'адрес модели не задан' })
    }
    return HttpResponse.json({ ok: true, latency_ms: 420, error: null })
  }),

  // --- Вход по OIDC -----------------------------------------------------

  http.get('/api/settings/oidc', () => noSession() ?? HttpResponse.json(oidcView())),

  http.put('/api/settings/oidc', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as OidcSettingsInput
    const secret = body.client_secret === '' || body.client_secret === SECRET_MASK
      ? oidc.client_secret
      : body.client_secret
    // Те же две проверки, что на сервере: без них не посмотреть, как экран
    // показывает 422 по включению без заполненных полей.
    const missing: string[] = ['public_url', 'issuer_url', 'client_id'].filter(
      (name) => !body[name as 'public_url' | 'issuer_url' | 'client_id'],
    )
    if (!secret) missing.push('client_secret')
    if (body.group_roles.length === 0) missing.push('group_roles')
    if (body.enabled && missing.length > 0) {
      return unprocessable('нельзя включить OIDC без полей: ' + missing.join(', '))
    }
    Object.assign(oidc, body, { client_secret: secret })
    return new HttpResponse(null, { status: 204 })
  }),

  http.post('/api/settings/oidc/test', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { issuer_url?: string }
    const issuer = body.issuer_url?.trim() ?? ''
    if (issuer === '') {
      return HttpResponse.json({
        ok: false,
        issuer: null,
        endpoints: null,
        keys: 0,
        error: 'адрес провайдера не задан',
      })
    }
    return HttpResponse.json({
      ok: true,
      issuer,
      endpoints: {
        authorization: `${issuer}/oauth2/authorize`,
        token: `${issuer}/oauth2/token`,
        jwks: `${issuer}/oauth2/jwks`,
        userinfo: `${issuer}/oauth2/userinfo`,
      },
      keys: 2,
      error: null,
    })
  }),

  // --- База ATT&CK ------------------------------------------------------

  http.get('/api/settings/attack', () => noSession() ?? HttpResponse.json(bundle)),

  http.post('/api/settings/attack/preview', () =>
    noSession() ?? HttpResponse.json(bundleDiff('20.0')),
  ),

  http.post('/api/settings/attack', () => {
    const denied = noSession()
    if (denied) return denied
    const diff = bundleDiff('20.0')
    acceptBundle(diff.version, 'uploaded', diff)
    return HttpResponse.json(diff)
  }),

  http.post('/api/settings/attack/notice/dismiss', () => {
    const denied = noSession()
    if (denied) return denied
    bundle.replacement = null
    return new HttpResponse(null, { status: 204 })
  }),

  http.get('/api/settings/attack/translation/gaps', () =>
    noSession() ?? HttpResponse.json({ total: 0, items: [] }),
  ),

  http.post('/api/settings/attack/translate', () =>
    noSession() ?? conflict('переводить нечего: все техники переведены'),
  ),

  http.post('/api/settings/attack/download', () => {
    const denied = noSession()
    if (denied) return denied
    if (pending && Date.now() < pending.readyAt) return conflict('загрузка уже идёт')
    const job = startMockBundleDownload()
    pending = {
      readyAt: job.finishesAt,
      value: {
        version: ONLINE_VERSION,
        downloaded_at: new Date(job.finishesAt).toISOString(),
        url: ONLINE_URL,
        diff: bundleDiff(ONLINE_VERSION),
      },
    }
    return HttpResponse.json({ job_id: job.id }, { status: 202 })
  }),

  http.get('/api/settings/attack/pending', () => noSession() ?? HttpResponse.json(pendingNow())),

  http.post('/api/settings/attack/pending/apply', () => {
    const denied = noSession()
    if (denied) return denied
    const waiting = pendingNow()
    if (!waiting) return conflict('нечего применять: скачанного бандла нет')
    acceptBundle(waiting.version, 'online', waiting.diff)
    pending = null
    return HttpResponse.json(waiting.diff)
  }),

  http.delete('/api/settings/attack/pending', () => {
    const denied = noSession()
    if (denied) return denied
    pending = null
    return new HttpResponse(null, { status: 204 })
  }),

  // --- Журнал действий --------------------------------------------------

  http.get('/api/settings/audit', ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const url = new URL(request.url)
    const items = selected(url)
    const page = Number(url.searchParams.get('page') ?? 1)
    const pageSize = Number(url.searchParams.get('page_size') ?? 50)
    return HttpResponse.json({
      total: items.length,
      items: items.slice((page - 1) * pageSize, page * pageSize),
    })
  }),

  http.get('/api/settings/audit/export.csv', ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const rows = selected(new URL(request.url)).map((e) =>
      [e.at, e.login, e.role ?? '', e.method, e.path, e.status, e.ip ?? '', e.summary ?? ''].join(';'),
    )
    const header = ['время', 'пользователь', 'роль', 'метод', 'путь', 'код', 'ip', 'сводка'].join(';')
    return new HttpResponse('﻿' + [header, ...rows].join('\r\n'), {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="audit.csv"',
      },
    })
  }),
]

/** Отбор журнала по параметрам адреса — общий для списка и выгрузки. */
function selected(url: URL): AuditItem[] {
  const userId = url.searchParams.get('user_id')
  const since = url.searchParams.get('since')
  const until = url.searchParams.get('until')
  const deniedOnly = url.searchParams.get('denied_only') === 'true'
  return audit.filter((e) => {
    if (userId && e.user_id !== Number(userId)) return false
    if (since && e.at < new Date(since).toISOString()) return false
    if (until && e.at > new Date(until).toISOString()) return false
    if (deniedOnly && e.status !== 403) return false
    return true
  })
}
