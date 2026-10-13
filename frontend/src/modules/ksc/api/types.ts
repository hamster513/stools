/** Типы API модуля Kaspersky Security Center (docs/ksc/api.md, спека §7). */

import type { FindingStatus } from '@/platform/findings/types'
import type {
  FindingBase,
  FindingDetail as CollectorFindingDetail,
  FindingsResponse as CollectorFindingsResponse,
  OverviewBase,
  ScheduleView,
  Severity,
  SnapshotBase,
} from '@/platform/collector/types'

export { SEVERITIES, SEVERITY_LABELS, STAGE_LABELS } from '@/platform/collector/types'
export type { CheckSummary, FindingsQuery, Job, JobStatus, ScheduleIn, ScheduleView, Severity } from '@/platform/collector/types'
export type { FindingStatus } from '@/platform/findings/types'

export interface Server {
  id: number
  name: string
  version: string
  snapshots: number
  last_snapshot_id: number | null
  last_snapshot_at: string | null
}

export interface Snapshot extends SnapshotBase {
  server_id: number
  source: 'file' | 'online'
  hosts: number
}

export interface Coverage {
  ad_total: number | null
  ksc_total: number
  both: number | null
  ad_only: number | null
  ksc_only: number | null
  with_agent: number
  with_protection: number
  protection_on: number
  bases_fresh: number
}

export interface Overview extends OverviewBase {
  server: { id: number; name: string; version: string }
  snapshot: (NonNullable<OverviewBase['snapshot']> & { hosts: number }) | null
  coverage: Coverage | null
  /** Свод изменений последнего снапшота; null — снапшотов нет. */
  changes: ChangesSummary | null
}

export interface Finding extends FindingBase {
  host: string
}

export type FindingsResponse = CollectorFindingsResponse<Finding>
export type FindingDetail = CollectorFindingDetail<Finding>

export type HostAgent = 'none' | 'silent' | 'alive'
export type HostProtection = 'none' | 'off' | 'on'
export type HostBases = 'fresh' | 'old' | 'unknown'

export const AGENT_LABELS: Record<HostAgent, string> = {
  none: 'нет агента',
  silent: 'молчит',
  alive: 'на связи',
}

export const PROTECTION_LABELS: Record<HostProtection, string> = {
  none: 'нет защиты',
  off: 'выключена',
  on: 'работает',
}

export const BASES_LABELS: Record<HostBases, string> = {
  fresh: 'свежие',
  old: 'устарели',
  unknown: 'неизвестно',
}

export const IN_AD_LABELS: Record<string, string> = {
  both: 'в AD и KSC',
  ksc_only: 'только KSC',
}

export const RTP_STATE_LABELS: Record<number, string> = {
  0: 'неизвестно',
  1: 'остановлена',
  2: 'приостановлена',
  3: 'запускается',
  9: 'сбой',
  10: 'не установлена',
  11: 'не поддерживается лицензией',
}

/** Расширенные поля хоста (блок «Система» карточки), из `HostRecord.extra`. */
export interface HostExtra {
  os_build: number
  cpu_arch: number
  vm_type: number
  reboot_required: boolean
  reboot_requested_at: string | null
  reboot_reason: number
  edr_status: number
  managed_by_other_server: boolean
}

/** KLHST_WKS_CPU_ARCH. */
export const CPU_ARCH_LABELS: Record<number, string> = {
  1: 'x86',
  2: 'x64',
  4: 'arm64',
}

/** HST_VM_TYPE. */
export const VM_TYPE_LABELS: Record<number, string> = {
  2: 'физическая машина',
  3: 'VMware',
  4: 'Hyper-V',
  8: 'Xen',
  9: 'KVM',
  1: 'виртуальная машина',
}

export function vmTypeLabel(code: number): string {
  return VM_TYPE_LABELS[code] ?? 'неизвестно'
}

export interface Host {
  id: number
  host_id: string
  name: string
  fqdn: string
  domain: string
  group: string
  os: string
  ip: string
  agent: HostAgent
  agent_version: string
  last_seen_at: string | null
  product: string
  product_version: string
  protection: HostProtection
  rtp_state: number
  bases_at: string | null
  bases: HostBases
  last_fullscan_at: string | null
  status: 'ok' | 'warning' | 'critical'
  threats: number
  unassigned: boolean
  in_ad: 'both' | 'ksc_only' | null
  components: [string, number][]
  extra: HostExtra
  findings: number
  /** `null` — сборщик не присылал теги; `[]` — теги собраны, у хоста их нет. */
  tags: string[] | null
}

/** Состояние компонента защиты в фильтре хостов: `none` — у хоста нет такого компонента. */
export type ComponentState = 'on' | 'off' | 'other' | 'none'

export interface HostsQuery {
  /** Многозначные фасеты уходят повторением ключа (buildQuery): внутри фасета «ИЛИ». */
  group?: string[]
  product?: string[]
  agent?: HostAgent[]
  protection?: HostProtection[]
  bases?: HostBases[]
  in_ad?: string[]
  status?: string[]
  /** Названия компонентов защиты; без `component_state` — хосты, у которых он есть. */
  component?: string[]
  /** Одно состояние — для выбранных компонентов. */
  component_state?: ComponentState
  /** Теги; `-` — хосты без тегов. */
  tag?: string[]
  /** Хосты групп, где действует политика. */
  policy?: number
  q?: string
  limit?: number
  offset?: number
}

export interface HostsResponse {
  total: number
  items: Host[]
  facets: {
    group: Record<string, number>
    product: Record<string, number>
    agent: Record<HostAgent, number>
    protection: Record<HostProtection, number>
    bases: Record<HostBases, number>
    in_ad: Record<string, number>
    status: Record<string, number>
    component: Record<string, { on: number; off: number; other: number }>
    /** Нет в ответе, если теги не собраны. */
    tag?: Record<string, number>
  } | null
  /** В выгрузке снапшота была секция тегов. */
  tags_collected: boolean
}

/** Политика, действующая на хост (по группе хоста). */
export interface HostPolicy {
  id: number
  name: string
  product: string
  active: boolean
  /** Создана в группе хоста; иначе унаследована. */
  own: boolean
}

export interface HostDetail extends Omit<Host, 'findings'> {
  findings: { key: string; check: string; check_title: string; severity: Severity; status: FindingStatus; status_title: string; details: Record<string, unknown> }[]
  /** Учитываемые находки хоста — то же правило, что счётчик в списке хостов. */
  findings_counted: number
  policies: HostPolicy[]
}

/** Условие активации профиля словами: группа — список условий, внутри группы «и», между группами «или». */
export interface HostProfileCondition {
  field: 'tag' | 'nla' | 'cpus' | 'unknown'
  text: string
}

/** Профиль политики и его активация на хосте (`/hosts/{host_id}/profiles`), трактовка условия — по тегам хоста. */
export interface HostProfile {
  name: string
  enabled: boolean
  priority: number
  /** true — активен, false — нет, null — не определить (условие не по тегам, теги не собраны). */
  active: boolean | null
  /** «по тегу X», «нет подходящего тега», «правил активации нет», «профиль выключен», «условие не по тегам», «теги хоста не собраны». */
  reason: string
  matched_tags: string[]
  condition: HostProfileCondition[][]
  settings: number
  /** Записей профиля; null — продукт политики не описан (записей нет потому, что извлекателя нет). */
  exclusions: number | null
  net_rules: number | null
}

export interface HostProfilesPolicy extends HostPolicy {
  /** Профили этой политики собраны (у агента и сервера — всегда нет). */
  profiles_collected: boolean
  profiles: HostProfile[]
}

export interface HostTagProfile {
  policy_id: number
  policy_name: string
  profile: string
  enabled: boolean
}

export interface HostProfiles {
  /** Секция профилей была хотя бы у одной политики снапшота. */
  profiles_collected: boolean
  /** Теги хоста; null — не собраны. */
  tags: string[] | null
  policies: HostProfilesPolicy[]
  /** Для каждого тега хоста — профили, в условии которых он встречается (включая выключенные). */
  by_tag: { tag: string; profiles: HostTagProfile[] }[]
}

export interface LockCount {
  total: number
  locked: number
  /** Настройки с признаком замка; 0 — замки в политике не распознаны. */
  with_lock_flag: number
}

export interface PolicyItem {
  id: number
  name: string
  product: string
  active: boolean
  inherited: boolean
  accept_parent: boolean
  modified_at: string | null
  modified_group: string
  locks: LockCount | null
  has_contents: boolean
}

export interface TaskItem {
  id: string
  name: string
  type: string
  product: string
  inherited: boolean
  schedule: number
  last_run_at: string | null
  ok: number
  warning: number
  failed: number
}

export interface PolicyFinding {
  key: string
  check: string
  check_title: string
  severity: Severity
}

export interface PolicyGroup {
  id: number
  name: string
  path: string
  level: number
  hosts: number
  policies: PolicyItem[]
  tasks: TaskItem[]
  findings: PolicyFinding[]
}

export interface PoliciesResponse {
  groups: PolicyGroup[]
}

export interface PolicyHeader {
  id: number
  name: string
  product: string
  version: string
  group: string
}

export interface LockSummary {
  total: number
  locked: number
  /** Доля замкнутых среди настроек с признаком замка. */
  share: number
  /** Настройки с признаком замка; 0 — замки в политике не распознаны. */
  with_lock_flag: number
}

export interface PolicySetting {
  path: string
  value: string
  locked: boolean | null
  inherited_lock: boolean
  lock_from: string
}

export interface PolicySection {
  name: string
  settings: PolicySetting[]
}

export interface PolicyContents {
  policy: PolicyHeader
  summary: LockSummary | null
  sections: PolicySection[]
  errors: string[]
}

export interface PolicyLocks {
  locked: number
  /** Настройки с признаком замка; 0 — замки в политике не распознаны. */
  with_lock_flag: number
}

/** Политика в плоском списке «Политики и задачи» → «Политики». */
export interface PolicyListItem {
  id: number
  name: string
  product: string
  version: string
  /** Группа, в которой политика создана. */
  group: string
  active: boolean
  accept_parent: boolean
  modified_at: string | null
  has_contents: boolean
  /** Содержимое собрано не полностью (часть секций не прочиталась): списки записей и настроек могут быть неполными. */
  contents_partial: boolean
  /** Для продукта есть извлекатель исключений и сетевых правил. */
  described: boolean
  /** Групп, где политика действует, и хостов прямо в них. */
  groups: number
  hosts: number
  /** null — профили не собраны; 0 — собраны, профилей нет. */
  profiles: number | null
  exclusions: number
  net_rules: number
  /** null — содержимого нет в выгрузке. */
  locks: PolicyLocks | null
  /** Оценка по считаемым находкам оценки; null — оценки нет, почему — в `grade_reason`. */
  grade: PolicyGrade | null
  grade_reason: string
  /** Считаемые находки оценки этой политики (по `details.policy_id`). */
  findings: number
}

export type PolicyGrade = 'bad' | 'ok' | 'good'

export const GRADE_LABELS: Record<PolicyGrade, string> = { bad: 'плохая', ok: 'нормальная', good: 'хорошая' }

/** Находка оценки политики (`/policies/{pid}/findings`): и считаемые, и нет. */
export interface PolicyGradeFinding {
  key: string
  check: string
  check_title: string
  severity: Severity
  status: FindingStatus
  status_title: string
  /** Статус входит в учитываемые: находка влияет на оценку. */
  counted: boolean
  details: Record<string, unknown>
}

export interface PolicyGradeFindings {
  items: PolicyGradeFinding[]
}

/** Настройка политики, распознанная словарём продукта. */
export interface DescribedSetting {
  section: string
  path: string
  title: string
  value: string
  /** Значение как есть (JSON-текст, длиннее 200 знаков обрезается). */
  raw: string
  locked: boolean | null
  /** false — подпись значения не подтверждена (показан «код N»). */
  verified: boolean
}

export interface SettingsComponentGroup {
  component: string
  title: string
  /** null — у компонента нет признака «включён» или его нет в политике. */
  enabled: boolean | null
  settings: DescribedSetting[]
}

export interface OtherSetting {
  section: string
  path: string
  value: string
  locked: boolean | null
}

/** Вкладка «Настройки» (`/policies/{pid}/settings`). */
export interface PolicySettings {
  /** Для продукта есть словарь; false — все настройки в `other`. */
  described: boolean
  known: number
  total: number
  groups: SettingsComponentGroup[]
  other: OtherSetting[]
}

export interface PolicyCard extends PolicyListItem {
  settings_total: number
  settings_known: number
  /** Ошибки сбора: содержимого и чтения профилей. */
  errors: string[]
  /** Записей журнала изменений этого снапшота по политике. */
  changes: number
}

export interface PolicyListQuery {
  q?: string
  /** Многозначные фасеты уходят повторением ключа (buildQuery). */
  product?: string[]
  active?: boolean
  /** Оценки или `none` — без оценки. */
  grade?: (PolicyGrade | 'none')[]
}

export interface PolicyListResponse {
  items: PolicyListItem[]
  facets: Record<string, Record<string, number>>
  /** Хотя бы у одной политики снапшота профили собраны; иначе профили в выгрузке не собирались. */
  profiles_collected: boolean
}

export interface PolicyScopeGroup {
  group_id: number
  path: string
  /** Политика создана в этой группе; false — унаследована. */
  own: boolean
  hosts: number
}

export interface PolicyScope {
  groups: PolicyScopeGroup[]
  hosts: number
}

export interface ProfileDiffItem {
  section: string
  path: string
  value: string
  /** Значение той же настройки в политике; null — в политике её нет (или содержимого политики нет в выгрузке). */
  policy_value: string | null
  locked: boolean | null
}

export interface PolicyProfile {
  name: string
  enabled: boolean
  priority: number
  /** Атрибуты профиля как пришли (включённость, условие активации), секреты скрыты при загрузке. */
  condition: Record<string, unknown>
  settings: number
  errors: string[]
  diff: ProfileDiffItem[]
}

export interface PolicyProfiles {
  collected: boolean
  errors: string[]
  profiles: PolicyProfile[]
}

/** Задача в плоском списке «Политики и задачи» → «Задачи». */
export interface TaskListItem {
  id: string
  name: string
  type: string
  product: string
  /** Путь группы задачи; пусто — задача для набора устройств. */
  group: string
  schedule: number
  last_run_at: string | null
  ok: number
  warning: number
  failed: number
}

export interface TasksQuery {
  q?: string
  /** Типы задач повторением ключа (buildQuery). */
  type?: string[]
  failed?: boolean
}

export interface TasksResponse {
  items: TaskListItem[]
  facets: Record<string, Record<string, number>>
}

/** Исключение политики или профиля (`profile` — пустая строка у самой политики). */
export interface ExclusionItem {
  id: number
  policy_id: number
  policy_name: string
  profile: string
  kind: string
  value: string
  components: string[]
  enabled: boolean
  comment: string
  /** Коды рисков (`EXCLUSION_RISKS`); пусто — риска нет или исключение выключено. */
  risks: string[]
  /** Объяснения рисков в том же порядке; код, которого уже нет в правилах, — как есть. */
  risk_titles: string[]
  key: string
  /** В скольких политиках встречается тот же ключ (по всему снапшоту, без учёта фильтров). */
  policies: number
  /** Значение более широкого исключения той же политики и профиля; null — не перекрыто. */
  covered_by: string | null
}

/** Риск исключения в карточке: серьёзность, заголовок, что именно открывает, как сузить. Неизвестный код — серьёзность пустая, заголовок — сам код. */
export interface RiskDetail {
  code: string
  severity: Severity | ''
  title: string
  detail: string
  recommendations: string[]
}

/** Та же запись (по `key`) в другой политике или профиле снапшота — профили своей политики тоже входят. */
export interface SameInItem {
  row_id: number
  policy_id: number
  policy_name: string
  profile: string
  enabled: boolean
}

/** Карточка исключения (`/exclusions/{row_id}`): элемент списка плюс подробности рисков и та же запись в других политиках и профилях. */
export interface ExclusionDetail extends ExclusionItem {
  risk_details: RiskDetail[]
  same_in: SameInItem[]
  /** Хостов под политикой записи. */
  policy_hosts: number
  /** Содержимое политики записи собрано не полностью. */
  policy_partial: boolean
}

export type ExclusionDup = 'multi' | 'single' | 'covered'

export const EXCLUSION_DUP_LABELS: Record<ExclusionDup, string> = {
  multi: 'в нескольких политиках',
  single: 'только в одной политике',
  covered: 'перекрытые',
}

/** Подписи известных кодов; неизвестный код показывается как есть. */
export const EXCLUSION_KIND_LABELS: Record<string, string> = { path: 'путь', mask: 'маска', hash: 'хеш', threat: 'угроза', trusted_app: 'доверенная программа' }

/** Код риска исключения (`core/exclusion_risks.RISKS`) → короткая подпись и серьёзность; объяснение приходит в `risk_titles`. */
export const EXCLUSION_RISKS: Record<string, { label: string; severity: Severity }> = {
  whole_drive: { label: 'весь диск', severity: 'High' },
  user_writable: { label: 'каталог пользователя', severity: 'High' },
  ext_mask: { label: 'маска исполняемых', severity: 'High' },
  name_only: { label: 'имя без пути', severity: 'Medium' },
  interpreter: { label: 'интерпретатор', severity: 'High' },
  broad_trust: { label: 'широкое доверие', severity: 'Medium' },
  threat_any: { label: 'любая угроза', severity: 'High' },
}

/** Слой сетевого правила (код) → подпись. */
export const NET_LAYER_LABELS: Record<string, string> = { packet: 'пакетное', app: 'программы' }

export interface ExclusionsQuery {
  q?: string
  /** Многозначные фасеты уходят повторением ключа (buildQuery). */
  policy_id?: number[]
  kind?: string[]
  enabled?: boolean
  dup?: ExclusionDup[]
  /** true — с рисками, false — без. */
  risky?: boolean
  /** Записи, действующие на хост: его политик и активных на нём профилей. */
  host_id?: string
  limit?: number
  offset?: number
}

export interface ExclusionSummaryItem {
  policy_id: number
  policy_name: string
  hosts: number
  total: number
  by_kind: Record<string, number>
  /** Исключений с рисками. */
  risky: number
  /** Содержимое политики собрано не полностью — список может быть неполным. */
  partial: boolean
}

/** Профиль, активацию которого на хосте не определить: его записи остаются в списке с пометкой «возможно». */
export interface UndeterminedProfile {
  policy_id: number
  policy_name: string
  profile: string
}

export interface ExclusionsResponse {
  total: number
  items: ExclusionItem[]
  /** Только при offset=0, иначе null. */
  facets: {
    policy: Record<string, number>
    kind: Record<string, number>
    enabled: Record<'true' | 'false', number>
    dup: Record<ExclusionDup, number>
    risky: Record<'true' | 'false', number>
  } | null
  /** Без фильтров, по политикам с описанным продуктом и собранным содержимым; только при offset=0. */
  summary: ExclusionSummaryItem[] | null
  /** Продукты политик с содержимым, для которых нет извлекателя: пустой список значит «не описан», а не «нет». */
  undescribed: string[]
  /** Только с `host_id`. */
  undetermined?: UndeterminedProfile[]
}

export interface NetRuleItem {
  id: number
  policy_id: number
  policy_name: string
  profile: string
  layer: string
  position: number
  name: string
  action: string
  direction: string
  protocol: string
  local_ports: string
  remote_ports: string
  addresses: string
  enabled: boolean
  key: string
}

/** Карточка сетевого правила (`/net-rules/{row_id}`). */
export interface NetRuleDetail extends NetRuleItem {
  same_in: SameInItem[]
  policy_hosts: number
  policy_partial: boolean
}

export interface NetRulesQuery {
  q?: string
  /** Многозначные фасеты уходят повторением ключа (buildQuery). */
  policy_id?: number[]
  action?: string[]
  direction?: string[]
  enabled?: boolean
  /** Записи, действующие на хост: его политик и активных на нём профилей. */
  host_id?: string
  limit?: number
  offset?: number
}

export interface NetRulesResponse {
  total: number
  items: NetRuleItem[]
  /** Только при offset=0, иначе null. */
  facets: {
    policy: Record<string, number>
    action: Record<string, number>
    direction: Record<string, number>
    layer: Record<string, number>
    enabled: Record<'true' | 'false', number>
  } | null
  undescribed: string[]
  /** Политики описанного продукта, содержимое которых собрано не полностью: их правила могут быть неполными. */
  partial: number[]
  /** Только с `host_id`. */
  undetermined?: UndeterminedProfile[]
}

export type ChangeKind = 'policy' | 'scope' | 'profile' | 'setting' | 'net_rule' | 'exclusion'
export type ChangeAction = 'added' | 'removed' | 'changed'

export const CHANGE_KIND_LABELS: Record<ChangeKind, string> = {
  policy: 'политика',
  scope: 'привязка к группе',
  profile: 'профиль',
  setting: 'настройка',
  net_rule: 'сетевое правило',
  exclusion: 'исключение',
}

/** Во множественном числе — для «не сравнивались: …». */
export const CHANGE_KIND_PLURAL: Record<ChangeKind, string> = {
  policy: 'политики',
  scope: 'привязки к группам',
  profile: 'профили',
  setting: 'настройки',
  net_rule: 'сетевые правила',
  exclusion: 'исключения',
}

export const CHANGE_ACTION_LABELS: Record<ChangeAction, string> = {
  added: 'добавлено',
  removed: 'удалено',
  changed: 'изменено',
}

export interface ChangeItem {
  id: number
  snapshot_id: number
  collected_at: string
  kind: ChangeKind
  action: ChangeAction
  policy_id: number | null
  policy_name: string
  profile: string
  section: string
  path: string
  /** Как сохранены (JSON); у настройки — `{value?, locked?, removed?, added?}`. */
  before: unknown
  after: unknown
}

/** Свод изменений снапшота (`summary_view`). */
export interface ChangesSummary {
  /** С каким снапшотом сравнивали; null — сравнивать не с чем. */
  prev: number | null
  /** null — изменения у снапшота не считались (нужен пересчёт). */
  total: number | null
  /** Вид → сравнивался ли; false — «не сравнивалось», а не «без изменений». */
  compared: Partial<Record<ChangeKind, boolean>>
  truncated: boolean
  reason: string | null
}

export interface ChangesSnapshot extends ChangesSummary {
  id: number
  collected_at: string
}

export interface ChangesQuery {
  /** Многозначные фасеты уходят повторением ключа (buildQuery). */
  kind?: ChangeKind[]
  action?: ChangeAction[]
  policy_id?: number[]
  snapshot_id?: number[]
  limit?: number
  offset?: number
}

export interface ChangesResponse {
  total: number
  items: ChangeItem[]
  /** Только при offset=0, иначе null. */
  facets: { kind: Partial<Record<ChangeKind, number>>; action: Partial<Record<ChangeAction, number>> } | null
  /** Все снапшоты сервера, новые первыми, со сводом изменений. */
  snapshots: ChangesSnapshot[]
}

export interface ServerAdmin {
  account: string
  internal: boolean
  role: string
  group: string
}

export interface ServerCert {
  function: string
  subject: string
  not_after: string
  days_left: number
}

export interface ServerSecondaryServer {
  name: string
  address: string
  version: string
  last_connected: string | null
  status: number
}

export interface ServerUpdateAgent {
  host: string
  group: string
}

export interface ServerFinding {
  key: string
  check: string
  check_title: string
  severity: Severity
  target: string
}

export interface ServerData {
  two_factor_required_for_all: boolean | null
  admins: ServerAdmin[]
  certs: ServerCert[]
  secondary_servers: ServerSecondaryServer[]
  update_agents: ServerUpdateAgent[]
  warnings: string[]
  findings: ServerFinding[]
}

export interface Connection {
  id: number
  title: string
  host: string
  port: number
  username: string
  password_set: boolean
  verify_tls: boolean
  internal: boolean
  domain: string
  server_id: number | null
  skip_policy_contents: boolean
  /** Расписание сбора; null — не задано. */
  schedule: ScheduleView | null
}

export interface ConnectionIn {
  title: string
  host: string
  port: number
  username: string
  password: string
  verify_tls: boolean
  internal: boolean
  domain: string
  skip_policy_contents: boolean
}

export interface KscConfig {
  agent_silent_days: number
  bases_old_days: number
  fullscan_days: number
  license_days: number
  key_components: Record<string, string[]>
  allowlist_hosts: string[]
  task_failed_share: number
  task_stale_days: number
  reboot_pending_days: number
  cert_days: number
  admin_role_patterns: string[]
  policy_lock_share: number
  policy_contents_max_policies: number
  /** Подстроки пути каталогов с правом записи пользователя — риск `user_writable`. */
  exclusion_user_writable: string[]
  /** Маски расширений исполняемых файлов — риск `ext_mask`. */
  exclusion_exec_extensions: string[]
  /** Имена файлов интерпретаторов и системных загрузчиков — риск `interpreter`. */
  exclusion_interpreters: string[]
  /** Коды компонентов словаря KES: выключение — POLICY_COMPONENT_OFF, признак «включён» без замка — POLICY_KEY_UNLOCKED. */
  policy_key_components: string[]
}

export interface SettingsView {
  config: KscConfig
  defaults: KscConfig
  checks: { code: string; title: string; description: string }[]
}

export const JOB_KIND_LABELS: Record<string, string> = {
  import_file: 'Загрузка выгрузки',
  collect: 'Сбор из KSC',
  reanalyze: 'Пересчёт снапшота',
}
