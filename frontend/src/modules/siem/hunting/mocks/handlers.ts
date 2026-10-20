/**
 * Обработчики MSW раздела Threat Hunting (/api/siem/hunting/*) поверх фикстур ./data.
 * Состояние живёт в памяти страницы: ханты, настройки, прогоны и большие ханты можно менять,
 * до перезагрузки. Статусы находок меняет платформа (`/api/findings/*`); здесь — только минимум для карточки
 * находки (состояние, настройки статусов, справочник исполнителей): смена статуса и исполнителя правит находку в памяти.
 * Подключается в `siem/mocks/browser.ts` рядом с остальными модулями.
 */
import { http, HttpResponse } from 'msw'
import { noSession } from '@/modules/siem/mocks/handlers'
import type { FindingEvent, FindingState, FindingStatus } from '@/platform/findings/types'
import type {
  DeepCreate,
  DeepDetail,
  DeepView,
  EventsPage,
  HuntFindingRow,
  HuntIn,
  HuntListItem,
  HuntRunEntry,
  HuntView,
  ImportRow,
  QueryView,
  RunDetail,
  RunView,
  ThFindingList,
  ThFindingListItem,
  ThFindingView,
  ThSettings,
  ThSettingsView,
} from '@/modules/siem/hunting/api/types'
import { DEEP_ACTIVE } from '@/modules/siem/hunting/api/types'
import {
  buildJobs,
  DEEP,
  eventRow,
  FINDINGS,
  HUNTS,
  IMPORT_NEW,
  ME,
  NOW,
  RUN_QUERIES,
  RUNS,
  SETTINGS,
  TODAY,
  type FindingRecord,
  type HuntRecord,
  type QueryRecord,
} from './data'

const hunts: HuntRecord[] = structuredClone(HUNTS)
const findings: FindingRecord[] = structuredClone(FINDINGS)
const runs: RunView[] = structuredClone(RUNS)
const runQueries = structuredClone(RUN_QUERIES)
const deeps: DeepDetail[] = structuredClone(DEEP)
const jobs = buildJobs()
let settings: ThSettings = { ...SETTINGS }

const OPEN: FindingStatus[] = ['new', 'in_work', 'fixed', 'reopened']
const ALL_STATUSES: FindingStatus[] = ['new', 'in_work', 'risk_accepted', 'false_positive', 'fixed', 'resolved', 'reopened']
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/

const maxId = (rows: { id: number }[]) => rows.reduce((m, r) => Math.max(m, r.id), 0)
const fail = (status: number, detail: string) => HttpResponse.json({ detail }, { status })

const splitFields = (s: string) => s.split(',').map((f) => f.trim()).filter(Boolean)

/** Подписи выравниваются по полям: недостающие — именем поля. */
function alignLabels(fields: string[], labels: string): string[] {
  const given = labels.trim() ? labels.split(',').map((l) => l.trim()) : []
  return [...given, ...fields.slice(given.length)].slice(0, fields.length)
}

// --- Виды ---------------------------------------------------------------------

const liveHunts = () => hunts.filter((h) => !h.deleted)

function lastRunOf(rows: typeof runQueries) {
  return rows.reduce<(typeof runQueries)[number] | null>((best, r) => (best === null || r.id > best.id ? r : best), null)
}

function huntListItem(h: HuntRecord): HuntListItem {
  const last = lastRunOf(runQueries.filter((r) => r.hunt_code === h.code))
  return {
    id: h.id,
    code: h.code,
    name: h.name,
    technique_id: h.technique_id,
    enabled: h.enabled,
    queries: h.queries.length,
    last_run: last ? { at: last.started_at, status: last.status } : null,
    new_findings: findings.filter((f) => f.hunt_code === h.code && f.status === 'new').length,
    updated_at: h.updated_at,
  }
}

function huntView(h: HuntRecord): HuntView {
  const queries: QueryView[] = h.queries.map((qr) => {
    const last = lastRunOf(runQueries.filter((r) => r.query_pk === qr.id))
    return {
      id: qr.id,
      query_id: qr.query_id,
      position: qr.position,
      query: qr.query,
      fields: qr.fields,
      fields_label: qr.fields_label,
      limit: qr.limit,
      enabled: qr.enabled,
      last: last ? { at: last.started_at, events: last.events, status: last.status } : null,
      new_findings: findings.filter((f) => f.hunt_code === h.code && f.query_id === qr.query_id && f.status === 'new').length,
    }
  })
  const history: HuntRunEntry[] = runQueries
    .filter((r) => r.hunt_code === h.code)
    .sort((a, b) => b.id - a.id)
    .slice(0, 30)
    .map((r) => ({
      id: r.id, query_id: r.query_id, status: r.status, started_at: r.started_at, duration_ms: r.duration_ms,
      events: r.events, error: r.error, finding_id: r.finding_id,
    }))
  const rows: HuntFindingRow[] = findings
    .filter((f) => f.hunt_code === h.code)
    .sort((a, b) => b.id - a.id)
    .slice(0, 50)
    .map((f) => ({
      id: f.id, kind: f.kind, query_id: f.query_id, period_from: f.period_from, period_to: f.period_to,
      event_count: f.event_count, created_at: f.created_at, status: f.status,
    }))
  return {
    id: h.id, code: h.code, name: h.name, description: h.description, technique_id: h.technique_id,
    enabled: h.enabled, updated_at: h.updated_at, updated_by: h.updated_by, queries, runs: history, findings: rows,
  }
}

const nightOf = (f: FindingRecord) => runs.find((r) => r.id === f.run_id)?.target_date ?? null

function findingItem(f: FindingRecord): ThFindingListItem {
  return {
    id: f.id,
    hunt_code: f.hunt_code,
    hunt_name: hunts.find((h) => h.code === f.hunt_code)?.name ?? '',
    query_id: f.query_id,
    target_date: nightOf(f),
    period_from: f.period_from,
    period_to: f.period_to,
    event_count: f.event_count,
    limit_hit: f.limit_hit,
    created_at: f.created_at,
    status: f.status,
    assignee: f.assignee,
    due_date: f.due_date,
    overdue: OPEN.includes(f.status) && f.due_date !== null && f.due_date < TODAY,
  }
}

const STATUS_TITLES: Record<FindingStatus, string> = {
  new: 'Новая',
  in_work: 'В работе',
  risk_accepted: 'Принят риск',
  false_positive: 'Ложное срабатывание',
  fixed: 'Исправлено',
  resolved: 'Устранена',
  reopened: 'Переоткрыта',
}

function findingView(f: FindingRecord): ThFindingView {
  const item = findingItem(f)
  const deep = deeps.find((d) => d.id === f.deep_id)
  return {
    ...item,
    key: `th:${f.id}`,
    kind: f.kind,
    columns: f.columns,
    events_purged: false,
    run_id: f.run_id,
    deep_id: f.deep_id,
    partial: deep ? deep.partial : false,
    limit_hit_slices: deep ? deep.limit_hit_slices : null,
    state: {
      status: f.status,
      status_title: STATUS_TITLES[f.status],
      assignee: f.assignee,
      due_date: f.due_date,
      overdue: item.overdue,
      risk_until: f.risk_until,
      updated_by: f.status === 'new' ? '' : ME,
      updated_at: f.status === 'new' ? null : f.created_at,
    },
  }
}

function deepView(d: DeepDetail): DeepView {
  const finding = findings.find((f) => f.deep_id === d.id)
  return {
    id: d.id, title: d.title, source: d.source, period_from: d.period_from, period_to: d.period_to, status: d.status,
    slices_done: d.slices_done, slices_total: d.slices_total, events: d.events, finding_id: finding?.id ?? null,
    status_state: finding?.status ?? null, job_id: d.job_id, created_by: d.created_by, created_at: d.created_at,
  }
}

function deepDetail(d: DeepDetail): DeepDetail {
  const finding = findings.find((f) => f.deep_id === d.id)
  return { ...d, ...deepView(d), finding: finding ? findingView(finding) : null }
}

/** Отмена снимает и задачу строки: у ждущей строки задачи нет. */
function cancelJob(id: number | null): void {
  const job = jobs.find((j) => j.id === id)
  if (job && job.status === 'running') {
    job.status = 'cancelled'
    job.cancel_requested = true
    job.finished_at = NOW
  }
}

const runView = (r: RunView): RunView => ({ ...r, errors: runQueries.filter((q) => q.run_id === r.id && q.status === 'failed').length })

// --- Разбор присланного ---------------------------------------------------------

function validateHunt(body: HuntIn): string | null {
  if (!body.code?.trim() || !body.name?.trim()) return 'код и название обязательны'
  if (body.technique_id && !TECHNIQUE.test(body.technique_id)) return 'техника ATT&CK задаётся как T1234 или T1234.001'
  if (!body.queries?.length) return 'у ханта нет запросов'
  for (const qr of body.queries) {
    if (!qr.query_id?.trim() || !qr.query?.trim() || !splitFields(qr.fields ?? '').length) {
      return `запрос ${qr.query_id || '?'}: нужны номер, текст и поля`
    }
  }
  return null
}

/** Запросы ханта по присланным: тот же `query_id` сохраняет номер, остальные получают новый. */
function syncQueries(h: HuntRecord, incoming: HuntIn['queries']): void {
  let next = Math.max(...hunts.flatMap((x) => x.queries.map((qr) => qr.id)), 0) + 1
  h.queries = incoming.map((qin, position): QueryRecord => {
    const fields = splitFields(qin.fields)
    const kept = h.queries.find((qr) => qr.query_id === qin.query_id.trim())
    return {
      id: kept?.id ?? next++,
      query_id: qin.query_id.trim(),
      position,
      query: qin.query.trim(),
      fields: fields.join(', '),
      fields_label: alignLabels(fields, qin.fields_label ?? '').join(', '),
      limit: qin.limit ?? null,
      enabled: qin.enabled ?? true,
    }
  })
}

function createHunt(body: HuntIn, enabled: boolean): HuntRecord {
  const h: HuntRecord = {
    id: maxId(hunts) + 1, code: body.code.trim(), name: body.name.trim(), description: body.description ?? '',
    technique_id: body.technique_id || null, enabled, deleted: false, updated_at: NOW, updated_by: ME, queries: [],
  }
  syncQueries(h, body.queries)
  hunts.push(h)
  return h
}

const codeTaken = (code: string) => hunts.some((h) => h.code === code.trim())

/** Статусы приходят повторением ключа или через запятую. */
function statusesOf(params: URLSearchParams): FindingStatus[] | null {
  const raw = params.getAll('status').flatMap((s) => s.split(',')).filter(Boolean)
  if (raw.includes('all')) return null
  return raw.length ? (raw as FindingStatus[]) : OPEN
}

function filterFindings(params: URLSearchParams, except?: 'status' | 'hunt'): FindingRecord[] {
  const statuses = statusesOf(params)
  const huntCodes = params.getAll('hunt').flatMap((s) => s.split(',')).filter(Boolean)
  const from = params.get('date_from')
  const to = params.get('date_to')
  const limitHit = params.get('limit_hit')
  return findings.filter((f) => {
    if (f.kind !== 'nightly') return false
    if (except !== 'status' && statuses && !statuses.includes(f.status)) return false
    if (except !== 'hunt' && huntCodes.length && !huntCodes.includes(f.hunt_code)) return false
    const night = nightOf(f)
    if (from && (night ?? '') < from) return false
    if (to && (night ?? '') > to) return false
    if (limitHit !== null && String(f.limit_hit) !== limitHit) return false
    return true
  })
}

function sortedFindings(params: URLSearchParams): ThFindingListItem[] {
  const sort = params.get('sort') ?? 'created_at'
  const dir = params.get('order') === 'asc' ? 1 : -1
  const key = (i: ThFindingListItem): string | number => {
    switch (sort) {
      case 'night': return i.target_date ?? ''
      case 'hunt': return i.hunt_code
      case 'query': return i.query_id
      case 'events': return i.event_count
      case 'status': return i.status
      default: return i.created_at
    }
  }
  return filterFindings(params).map(findingItem).sort((a, b) => {
    const av = key(a)
    const bv = key(b)
    return (av < bv ? -1 : av > bv ? 1 : a.id - b.id) * dir
  })
}

function csv(rows: unknown[][]): string {
  const cell = (v: unknown) => `"${String(v ?? '').replaceAll('"', '""')}"`
  return `\uFEFF${rows.map((r) => r.map(cell).join(',')).join('\r\n')}\r\n`
}

function download(body: string, name: string, type: string): Response {
  return new HttpResponse(body, { headers: { 'Content-Type': type, 'Content-Disposition': `attachment; filename="${name}"` } })
}

const sliceCount = (from: string, to: string) => Math.ceil((Date.parse(to) - Date.parse(from)) / (settings.slice_hours * 3_600_000))

/** Раздел занят, пока идёт какая-нибудь задача: новый хант и повтор прогона ждут в очереди. */
const busy = () => deeps.some((d) => d.status === 'running') || runs.some((r) => r.status === 'running')

function newDeep(body: {
  title: string; source: DeepDetail['source']; query: string; fields: string[]; labels: string[]; limit: number; from: string; to: string
}): DeepDetail {
  return {
    id: maxId(deeps) + 1, title: body.title, source: body.source, period_from: body.from, period_to: body.to, status: 'queued',
    slices_done: 0, slices_total: sliceCount(body.from, body.to), events: 0, finding_id: null, status_state: null, job_id: null,
    created_by: ME, created_at: NOW, query: body.query, fields: body.fields, labels: body.labels, limit: body.limit,
    limit_hit_slices: 0, partial: false, error: null, finished_at: null, finding: null,
  }
}

/** Новый прогон даты в очереди; раздел свободен — сразу с задачей, как у диспетчера. Прежний живой прогон даты заменяется. */
function queueRun(date: string, period: { from: string; to: string }, total: number): RunView {
  for (const r of runs) if (r.target_date === date && r.status !== 'superseded') r.status = 'superseded'
  const created: RunView = {
    id: maxId(runs) + 1, target_date: date, period_from: period.from, period_to: period.to, status: 'queued',
    started_at: null, finished_at: null, queries_total: total, queries_done: 0, findings: 0, errors: 0, error: null, job_id: null,
  }
  runs.push(created)
  // Раздел занят — прогон дождётся конца текущей задачи, и задачи у него пока нет.
  if (!busy()) {
    const job = { id: maxId(jobs) + 1, kind: 'nightly', stage: 'connecting', status: 'running' as const, progress: 0, processed: 0, total, message: 'подключение к MaxPatrol', error: null, cancel_requested: false, started_at: NOW, finished_at: null, started_by: ME }
    jobs.push(job)
    created.job_id = job.id
    created.status = 'running'
    created.started_at = NOW
  }
  return created
}

const dateBusy = (date: string) => runs.some((r) => r.target_date === date && (r.status === 'queued' || r.status === 'running'))
const ruDate = (date: string) => `${date.slice(8)}.${date.slice(5, 7)}.${date.slice(0, 4)}`

// --- Обработчики ------------------------------------------------------------------

const P = '/api/siem/hunting'

export const huntingHandlers = [
  // Библиотека
  http.get(`${P}/hunts`, ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const p = new URL(request.url).searchParams
    const needle = (p.get('q') ?? '').trim().toLowerCase()
    const enabled = p.get('enabled')
    const technique = p.get('technique')
    const rows = liveHunts().filter(
      (h) =>
        (enabled === null || String(h.enabled) === enabled) &&
        (!technique || h.technique_id === technique) &&
        (!needle || h.code.toLowerCase().includes(needle) || h.name.toLowerCase().includes(needle)),
    )
    return HttpResponse.json(rows.map(huntListItem))
  }),

  http.post(`${P}/hunts`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as HuntIn
    const invalid = validateHunt(body)
    if (invalid) return fail(422, invalid)
    if (codeTaken(body.code)) return fail(409, `код занят: ${body.code.trim()}`)
    return HttpResponse.json(huntView(createHunt(body, body.enabled ?? true)), { status: 201 })
  }),

  // Выгрузка и импорт библиотеки.
  http.get(`${P}/library/export`, () => {
    const denied = noSession()
    if (denied) return denied
    const lines = liveHunts().flatMap((h) => [
      `${h.code}:`,
      `  name: ${h.name}`,
      `  description: ${h.description}`,
      '  query_list:',
      ...h.queries.flatMap((qr) => [
        `    - query_id: ${qr.query_id}`,
        `      query: ${JSON.stringify(qr.query)}`,
        `      fields: ${qr.fields}`,
        `      fields_label: ${qr.fields_label}`,
        ...(qr.limit !== null ? [`      limit: ${qr.limit}`] : []),
      ]),
    ])
    return download(`${lines.join('\n')}\n`, 'th-library-2026-10-19.yaml', 'text/yaml')
  }),

  // Содержимое файла мок не разбирает: в «файле» всегда один новый хант, один изменённый и один совпадающий.
  http.post(`${P}/library/import/preview`, () => {
    const denied = noSession()
    if (denied) return denied
    const rows: ImportRow[] = [
      { code: IMPORT_NEW.code, action: codeTaken(IMPORT_NEW.code) ? 'same' : 'new', changes: [] },
      { code: 'TH-WIN-001', action: 'changed', changes: ['название', 'Q2 изменён'] },
      { code: 'TH-NET-001', action: 'same', changes: [] },
    ]
    return HttpResponse.json({ rows, hunts: rows.length })
  }),

  http.post(`${P}/library/import`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const form = await request.formData()
    const replace = String(form.get('replace') ?? '').split(',').map((c) => c.trim()).filter(Boolean)
    let created = 0
    if (!codeTaken(IMPORT_NEW.code)) {
      createHunt({ code: IMPORT_NEW.code, name: IMPORT_NEW.name, description: IMPORT_NEW.description, technique_id: IMPORT_NEW.technique_id, queries: [IMPORT_NEW.query] }, true)
      created = 1
    }
    const replaced = replace.includes('TH-WIN-001') ? 1 : 0
    return HttpResponse.json({ created, replaced, skipped: 1 - replaced })
  }),

  http.get(`${P}/hunts/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const h = liveHunts().find((x) => x.id === Number(params.id))
    return h ? HttpResponse.json(huntView(h)) : fail(404, 'хант не найден')
  }),

  http.put(`${P}/hunts/:id`, async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const h = liveHunts().find((x) => x.id === Number(params.id))
    if (!h) return fail(404, 'хант не найден')
    const body = (await request.json()) as HuntIn
    // Код при правке не меняется: на него ссылаются находки и история прогонов.
    const invalid = validateHunt({ ...body, code: h.code })
    if (invalid) return fail(422, invalid)
    h.name = body.name.trim()
    h.description = body.description ?? ''
    h.technique_id = body.technique_id || null
    h.enabled = body.enabled ?? h.enabled
    h.updated_at = NOW
    h.updated_by = ME
    syncQueries(h, body.queries)
    return HttpResponse.json(huntView(h))
  }),

  http.delete(`${P}/hunts/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const h = liveHunts().find((x) => x.id === Number(params.id))
    if (!h) return fail(404, 'хант не найден')
    h.deleted = true
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${P}/hunts/:id/enabled`, async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const h = liveHunts().find((x) => x.id === Number(params.id))
    if (!h) return fail(404, 'хант не найден')
    h.enabled = ((await request.json()) as { enabled: boolean }).enabled
    h.updated_at = NOW
    h.updated_by = ME
    return HttpResponse.json(huntView(h))
  }),

  http.post(`${P}/queries/check`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { query: string; fields: string }
    if (!body.query.trim() || !splitFields(body.fields).length) return HttpResponse.json({ ok: false, message: 'запрос и поля обязательны' })
    if (body.query.includes('???')) return HttpResponse.json({ ok: false, message: 'MaxPatrol отклонил запрос: ошибка разбора' })
    return HttpResponse.json({ ok: true, message: 'запрос принят, за последний час есть события' })
  }),

  http.post(`${P}/queries/:pk/enabled`, async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const h = liveHunts().find((x) => x.queries.some((qr) => qr.id === Number(params.pk)))
    const query = h?.queries.find((qr) => qr.id === Number(params.pk))
    if (!h || !query) return fail(404, 'запрос не найден')
    query.enabled = ((await request.json()) as { enabled: boolean }).enabled
    h.updated_at = NOW
    h.updated_by = ME
    return HttpResponse.json(huntView(h))
  }),

  // Настройки
  http.get(`${P}/settings`, () => {
    const denied = noSession()
    if (denied) return denied
    return HttpResponse.json(settingsView())
  }),

  http.put(`${P}/settings`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as ThSettings
    if (!HHMM.test(body.window_from) || !HHMM.test(body.window_to)) return fail(422, 'время в формате ЧЧ:ММ (00:00–23:59)')
    settings = { ...body }
    return HttpResponse.json(settingsView())
  }),

  // Находки (экспорт и список объявлены до `/findings/:id`)
  http.get(`${P}/findings/export`, ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const url = new URL(request.url)
    const rows = sortedFindings(url.searchParams).map((i) => [
      STATUS_TITLES[i.status], i.hunt_code, i.hunt_name, i.query_id, i.target_date, i.event_count,
      i.limit_hit ? 'да' : 'нет', i.created_at, i.assignee, i.due_date,
    ])
    const head = ['Статус', 'Хант', 'Название', 'Запрос', 'Ночь', 'Событий', 'Достигнут лимит', 'Найдено', 'Исполнитель', 'Срок']
    const fmt = url.searchParams.get('format') === 'xlsx' ? 'xlsx' : 'csv'
    return download(csv([head, ...rows]), `th-findings.${fmt}`, 'text/csv; charset=utf-8')
  }),

  http.get(`${P}/findings`, ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const p = new URL(request.url).searchParams
    const limit = Number(p.get('limit') ?? 100)
    if (limit > 1000) return fail(422, 'limit не может превышать 1000')
    const offset = Number(p.get('offset') ?? 0)
    const items = sortedFindings(p)
    const byStatus = filterFindings(p, 'status')
    const byHunt = filterFindings(p, 'hunt')
    const body: ThFindingList = {
      total: items.length,
      items: items.slice(offset, offset + limit),
      facets: {
        status: Object.fromEntries(ALL_STATUSES.map((s) => [s, byStatus.filter((f) => f.status === s).length])),
        hunt: Object.fromEntries(
          [...new Set(byHunt.map((f) => f.hunt_code))].sort().map((code) => [code, byHunt.filter((f) => f.hunt_code === code).length]),
        ),
      },
    }
    return HttpResponse.json(body)
  }),

  http.get(`${P}/findings/:id/events/export`, ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const f = findings.find((x) => x.id === Number(params.id))
    if (!f) return fail(404, 'находка не найдена')
    const rows = Array.from({ length: f.event_count }, (_, i) => eventRow(f, i))
    const fmt = new URL(request.url).searchParams.get('format') === 'xlsx' ? 'xlsx' : 'csv'
    return download(csv([f.columns.map((c) => c.label), ...rows]), `th-finding-${f.id}-events.${fmt}`, 'text/csv; charset=utf-8')
  }),

  http.get(`${P}/findings/:id/events`, ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const f = findings.find((x) => x.id === Number(params.id))
    if (!f) return fail(404, 'находка не найдена')
    const p = new URL(request.url).searchParams
    const limit = Number(p.get('limit') ?? 100)
    if (limit > 1000) return fail(422, 'limit не может превышать 1000')
    const offset = Number(p.get('offset') ?? 0)
    const end = Math.min(f.event_count, offset + limit)
    const page: EventsPage = { total: f.event_count, rows: Array.from({ length: Math.max(end - offset, 0) }, (_, i) => eventRow(f, offset + i)) }
    return HttpResponse.json(page)
  }),

  http.get(`${P}/findings/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const f = findings.find((x) => x.id === Number(params.id))
    return f ? HttpResponse.json(findingView(f)) : fail(404, 'находка не найдена')
  }),

  // Ночные прогоны
  http.get(`${P}/runs`, ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const p = new URL(request.url).searchParams
    const limit = Number(p.get('limit') ?? 60)
    const offset = Number(p.get('offset') ?? 0)
    const rows = [...runs].sort((a, b) => (a.target_date < b.target_date ? 1 : a.target_date > b.target_date ? -1 : b.id - a.id))
    return HttpResponse.json(rows.slice(offset, offset + limit).map(runView))
  }),

  // Последняя наступившая ночь в моках — TODAY (окно в 01:00, «сейчас» — утро).
  http.get(`${P}/runs/expected`, () => {
    const denied = noSession()
    if (denied) return denied
    const oldest = runs.reduce((m, r) => (r.target_date < m ? r.target_date : m), TODAY)
    return HttpResponse.json({ from: oldest, to: TODAY })
  }),

  http.post(`${P}/runs/rerun-date`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const { target_date: date } = (await request.json()) as { target_date: string }
    if (date > TODAY) return fail(422, `ночь ${ruDate(date)} ещё не наступила`)
    if (dateBusy(date)) return fail(409, `прогон за ${ruDate(date)} ещё не завершён`)
    const next = new Date(`${date}T00:00:00Z`)
    next.setUTCDate(next.getUTCDate() + 1)
    const total = [...runs].sort((a, b) => b.id - a.id)[0]?.queries_total ?? 0
    const created = queueRun(date, { from: `${date}T00:00:00Z`, to: next.toISOString().replace('.000Z', 'Z') }, total)
    return HttpResponse.json({ run_id: created.id, job_id: created.job_id }, { status: 202 })
  }),

  http.get(`${P}/runs/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const r = runs.find((x) => x.id === Number(params.id))
    if (!r) return fail(404, 'прогон не найден')
    const detail: RunDetail = { ...runView(r), queries: runQueries.filter((q) => q.run_id === r.id).map(({ run_id: _run, ...q }) => q) }
    return HttpResponse.json(detail)
  }),

  http.post(`${P}/runs/:id/rerun`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const old = runs.find((x) => x.id === Number(params.id))
    if (!old) return fail(404, 'прогон не найден')
    if (dateBusy(old.target_date)) return fail(409, `прогон за ${old.target_date.slice(8)}.${old.target_date.slice(5, 7)} уже идёт или ждёт`)
    const created = queueRun(old.target_date, { from: old.period_from, to: old.period_to }, old.queries_total)
    return HttpResponse.json({ run_id: created.id, job_id: created.job_id }, { status: 202 })
  }),

  http.post(`${P}/runs/:id/cancel`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const r = runs.find((x) => x.id === Number(params.id))
    if (!r) return fail(404, 'прогон не найден')
    if (r.status !== 'queued' && r.status !== 'running') return fail(409, 'прогон уже завершён')
    cancelJob(r.job_id)
    r.status = 'cancelled'
    r.finished_at = NOW
    return HttpResponse.json(runView(r))
  }),

  // Большие ханты
  http.get(`${P}/deep`, () => {
    const denied = noSession()
    if (denied) return denied
    return HttpResponse.json([...deeps].sort((a, b) => b.id - a.id).map(deepView))
  }),

  http.post(`${P}/deep`, async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as DeepCreate
    let text = ''
    let fields: string[] = []
    let labels: string[] = []
    let limit = settings.default_limit
    let source: DeepDetail['source'] = null
    let title = ''
    if (body.hunt_query_id !== undefined) {
      const h = liveHunts().find((x) => x.queries.some((qr) => qr.id === body.hunt_query_id))
      const qr = h?.queries.find((x) => x.id === body.hunt_query_id)
      if (!h || !qr) return fail(404, 'запрос библиотеки не найден')
      text = qr.query
      fields = splitFields(qr.fields)
      labels = splitFields(qr.fields_label)
      limit = qr.limit ?? limit
      source = { hunt_code: h.code, query_id: qr.query_id }
      title = `${h.code} ${qr.query_id}`
    }
    if (body.query?.trim()) text = body.query.trim()
    if (body.fields !== undefined && splitFields(body.fields).length) {
      fields = splitFields(body.fields)
      labels = alignLabels(fields, body.fields_label ?? '')
    } else if (body.fields_label !== undefined) {
      labels = alignLabels(fields, body.fields_label)
    }
    if (!text || !fields.length) return fail(422, 'запрос и поля обязательны')
    let from: string
    let to: string
    if (body.period_from || body.period_to) {
      if (!body.period_from || !body.period_to) return fail(422, 'период: нужны обе даты — начало и конец')
      from = new Date(body.period_from).toISOString()
      to = new Date(body.period_to).toISOString()
    } else {
      const end = new Date(NOW)
      const start = new Date(end)
      start.setUTCMonth(start.getUTCMonth() - (body.months ?? settings.default_depth_months))
      from = start.toISOString()
      to = end.toISOString()
    }
    if (Date.parse(from) >= Date.parse(to)) return fail(422, 'период: начало должно быть раньше конца')
    const created = newDeep({
      title: body.title?.trim() || title || text.replace(/\s+/g, ' ').slice(0, 60), source, query: text, fields, labels,
      limit: body.limit ?? limit, from, to,
    })
    deeps.push(created)
    return HttpResponse.json(deepView(created), { status: 202 })
  }),

  http.get(`${P}/deep/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const d = deeps.find((x) => x.id === Number(params.id))
    return d ? HttpResponse.json(deepDetail(d)) : fail(404, 'большой хант не найден')
  }),

  http.post(`${P}/deep/:id/cancel`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const d = deeps.find((x) => x.id === Number(params.id))
    if (!d) return fail(404, 'большой хант не найден')
    if (!DEEP_ACTIVE.includes(d.status)) return fail(409, 'большой хант уже завершён')
    cancelJob(d.job_id)
    d.status = 'cancelled'
    d.partial = d.slices_done > 0
    d.finished_at = NOW
    return HttpResponse.json(deepView(d))
  }),

  http.post(`${P}/deep/:id/rerun`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const old = deeps.find((x) => x.id === Number(params.id))
    if (!old) return fail(404, 'большой хант не найден')
    const created = newDeep({
      title: old.title, source: old.source, query: old.query, fields: old.fields, labels: old.labels, limit: old.limit,
      from: old.period_from, to: old.period_to,
    })
    deeps.push(created)
    return HttpResponse.json(deepView(created), { status: 202 })
  }),

  http.post(`${P}/deep/:id/save-to-library`, async ({ params, request }) => {
    const denied = noSession()
    if (denied) return denied
    const d = deeps.find((x) => x.id === Number(params.id))
    if (!d) return fail(404, 'большой хант не найден')
    if (d.source !== null) return fail(409, 'запрос взят из библиотеки — он уже там')
    const body = (await request.json()) as { code: string; name: string }
    const hunt: HuntIn = {
      code: body.code, name: body.name, enabled: false,
      queries: [{ query_id: 'Q1', query: d.query, fields: d.fields.join(', '), fields_label: d.labels.join(', '), limit: d.limit }],
    }
    const invalid = validateHunt(hunt)
    if (invalid) return fail(422, invalid)
    if (codeTaken(body.code)) return fail(409, `код занят: ${body.code.trim()}`)
    return HttpResponse.json(huntView(createHunt(hunt, false)), { status: 201 })
  }),

  // Задачи раздела: идущие сверху, затем завершённые; отмены у них нет.
  http.get(`${P}/jobs`, ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const limit = Number(new URL(request.url).searchParams.get('limit') ?? 50)
    const running = jobs.filter((j) => j.status === 'running').sort((a, b) => b.id - a.id)
    const finished = jobs.filter((j) => j.status !== 'running').sort((a, b) => b.id - a.id).slice(0, limit)
    return HttpResponse.json([...running, ...finished])
  }),

  http.get(`${P}/jobs/:id`, ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const j = jobs.find((x) => x.id === Number(params.id))
    return j ? HttpResponse.json(j) : fail(404, 'задача не найдена')
  }),

  // Платформа статусов — минимум для FindingWorkBlock в карточке находки
  http.get('/api/findings/state', ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const f = thFindingByKey(new URL(request.url).searchParams.get('key'))
    return f ? HttpResponse.json(stateOf(f)) : fail(404, 'находка не найдена')
  }),

  http.put('/api/findings/state', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const body = (await request.json()) as { key: string; status?: FindingStatus; assignee?: string | null; due_date?: string | null; risk_until?: string | null; comment?: string }
    const f = thFindingByKey(body.key)
    if (!f) return fail(404, 'находка не найдена')
    const before = f.status
    if (body.status !== undefined) f.status = body.status
    if (body.assignee !== undefined) f.assignee = body.assignee
    if (body.due_date !== undefined) f.due_date = body.due_date
    if (body.risk_until !== undefined) f.risk_until = body.risk_until
    const prev = stateEvents.get(f.id) ?? []
    stateEvents.set(f.id, [
      { at: new Date().toISOString(), actor: ME, kind: 'status', from_status: before, to_status: f.status, comment: body.comment ?? '', details: {} },
      ...prev,
    ])
    return HttpResponse.json(stateOf(f))
  }),

  // Массовая смена из очереди находок: только ключи или фильтр модуля siem_th, прочие модули — дальше по списку обработчиков.
  http.post('/api/findings/bulk', async ({ request }) => {
    const body = (await request.clone().json()) as {
      module: string; keys?: string[]; filter?: Record<string, unknown>
      change: { status?: FindingStatus; assignee?: string | null; due_date?: string | null; risk_until?: string | null; comment?: string }
    }
    if (body.module !== 'siem_th') return undefined
    const denied = noSession()
    if (denied) return denied
    let targets: FindingRecord[]
    if (body.filter) {
      const params = new URLSearchParams()
      for (const [k, v] of Object.entries(body.filter)) {
        if (v === undefined || v === null) continue
        for (const one of Array.isArray(v) ? v : [v]) params.append(k, String(one))
      }
      targets = filterFindings(params)
    } else {
      targets = (body.keys ?? []).map(thFindingByKey).filter((f): f is FindingRecord => f !== undefined)
    }
    const { change } = body
    for (const f of targets) {
      const before = f.status
      if (change.status !== undefined) f.status = change.status
      if (change.assignee !== undefined) f.assignee = change.assignee
      if (change.due_date !== undefined) f.due_date = change.due_date
      if (change.risk_until !== undefined) f.risk_until = change.risk_until
      stateEvents.set(f.id, [
        { at: new Date().toISOString(), actor: ME, kind: 'status', from_status: before, to_status: f.status, comment: change.comment ?? '', details: {} },
        ...(stateEvents.get(f.id) ?? []),
      ])
    }
    return HttpResponse.json({ changed: targets.length })
  }),

  http.get('/api/settings/findings', () => {
    const denied = noSession()
    if (denied) return denied
    const counted = Object.fromEntries(ALL_STATUSES.map((s) => [s, OPEN.includes(s)])) as Record<FindingStatus, boolean>
    return HttpResponse.json({ counted, risk_max_days: null, risk_accept_role: 'analyst' })
  }),

  http.get('/api/users/directory', () => {
    const denied = noSession()
    if (denied) return denied
    return HttpResponse.json([{ login: 'analyst', display_name: 'Аналитик' }, { login: 'auditor', display_name: 'Аудитор' }])
  }),
]

/** История решений по находкам, принятых за время жизни страницы. */
const stateEvents = new Map<number, FindingEvent[]>()

const thFindingByKey = (key: string | null) => findings.find((f) => `th:${f.id}` === key)

function stateOf(f: FindingRecord): FindingState {
  return {
    module: 'siem_th', scope_id: 1, key: `th:${f.id}`, status: f.status, status_title: STATUS_TITLES[f.status],
    assignee: f.assignee, assignee_name: f.assignee, due_date: f.due_date,
    overdue: OPEN.includes(f.status) && f.due_date !== null && f.due_date < TODAY,
    risk_until: f.risk_until, reason: '', present: true, first_seen_at: f.created_at,
    updated_by: stateEvents.has(f.id) ? ME : '', updated_at: stateEvents.get(f.id)?.[0].at ?? null,
    events: stateEvents.get(f.id) ?? [],
  }
}

function settingsView(): ThSettingsView {
  return {
    ...settings,
    schedule: {
      id: 1,
      interval_hours: 24,
      window_from: settings.window_from,
      window_to: settings.window_to,
      enabled: settings.nightly_enabled,
      next_run_at: settings.nightly_enabled ? `2026-10-20T${settings.window_from}:00Z` : null,
      last_run_at: '2026-10-19T01:03:00Z',
      last_job_id: 7,
      tz: 'UTC',
    },
  }
}
