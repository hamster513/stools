/** Типы API модуля Assets. */
import type { ScheduleView } from '@/platform/collector/types'
import type { FindingChange, FindingStatus } from '@/platform/findings/types'

export { STAGE_LABELS } from '@/platform/collector/types'
export type { Job, JobStatus, ScheduleIn } from '@/platform/collector/types'

export const JOB_KIND_LABELS: Record<string, string> = {
  dns: 'Обновление DNS',
  rt: 'Проход RackTables',
  sync: 'Синхронизация с модулями',
}

export type AssetSource = 'vm' | 'ksc' | 'ad' | 'dns' | 'rt'
export const SOURCES: AssetSource[] = ['vm', 'ksc', 'ad', 'dns', 'rt']
export const SOURCE_LABELS: Record<AssetSource | 'siem', string> = {
  vm: 'VM',
  ksc: 'KSC',
  ad: 'AD',
  dns: 'DNS',
  rt: 'RT',
  siem: 'SIEM',
}

export type DiscrepancyCode = 'stale' | 'conflict' | 'no_av' | 'ad_inactive' | 'no_network'
export const CODES: DiscrepancyCode[] = ['stale', 'conflict', 'no_av', 'ad_inactive', 'no_network']
export const CODE_LABELS: Record<DiscrepancyCode, string> = {
  stale: 'данные устарели',
  conflict: 'источники расходятся',
  no_av: 'нет агента антивируса',
  ad_inactive: 'неактивный компьютер AD',
  no_network: 'сеть не описана',
}
/** Фильтр списка: код расхождения или `any` — хоть одно расхождение. */
export type CodeFilter = DiscrepancyCode | 'any'
export const ANY_CODE_LABEL = 'любое расхождение'
/** Подсветка ячейки в таблице источников: те же токены, что у видов находок. */
export const MARK_TEXT: Record<'stale' | 'conflict', string> = {
  stale: 'text-kind-1',
  conflict: 'text-kind-2',
}

export type Criticality = 'Critical' | 'High' | 'Medium' | 'Low'
export const CRITICALITIES: Criticality[] = ['Critical', 'High', 'Medium', 'Low']
export const CRITICALITY_LABELS: Record<Criticality | 'none', string> = {
  Critical: 'критическая',
  High: 'высокая',
  Medium: 'средняя',
  Low: 'низкая',
  none: 'не задана',
}

/** LAPS по наблюдению AD: есть ли у компьютера срок пароля LAPS. */
export type LapsFilter = 'yes' | 'no'
export const LAPS_VALUES: LapsFilter[] = ['yes', 'no']
export const LAPS_LABELS: Record<LapsFilter, string> = { yes: 'есть', no: 'нет' }

export type PinnableField = 'name' | 'fqdn' | 'domain' | 'ip' | 'os'

export interface AssetSourceBadge {
  source: AssetSource
  /** Источник видит хост сейчас. */
  live: boolean
  /** Видит и видел недавно (моложе порога устаревания). */
  fresh: boolean
  seen_at: string
}

/** Сеть актива с признаками её группы: где хост — внутри, в DMZ, снаружи. */
export interface AssetNetwork {
  id: number
  cidr: string
  title: string
  zone: string | null
  zone_title: string | null
  placement: Placement
  internet_facing: boolean
  confidential: boolean
}

/** Признак кластера Windows из наблюдения AD: учётка кластера и роль — виртуальные имена, не хосты. */
export type ClusterKind = 'cluster' | 'role' | 'node'
export const CLUSTER_KINDS: ClusterKind[] = ['cluster', 'role', 'node']
export const CLUSTER_LABELS: Record<ClusterKind, string> = {
  cluster: 'кластер',
  role: 'роль кластера',
  node: 'узел кластера',
}

export interface AssetItem {
  id: number
  cluster: ClusterKind | null
  name: string
  fqdn: string
  domain: string
  ip: string
  os: string
  network: AssetNetwork | null
  first_seen: string | null
  last_seen: string | null
  criticality: Criticality | ''
  tags: string[]
  pinned: Partial<Record<PinnableField, boolean>>
  sources: AssetSourceBadge[]
  discrepancy_count: number
  codes: DiscrepancyCode[]
}

export interface AssetsFacets {
  source: Record<AssetSource, number>
  /** Активы с расхождением кода под статусами фильтра (без фильтра — учитываемые в подсчётах). */
  code: Record<CodeFilter, number>
  zone: Record<string, number>
  /** Расположение по группе сети актива; '' — вне сети или группа без расположения. */
  placement: Record<Placement, number>
  criticality: Record<Criticality | 'none', number>
  /** Только активы с наблюдением AD. */
  laps: Record<LapsFilter, number>
  /** Только активы с признаком кластера в наблюдении AD. */
  cluster: Record<ClusterKind, number>
  /** Расхождения по статусам — без фильтра статуса. */
  disc_status: Record<FindingStatus, number>
  /** Просроченные расхождения — без фильтра статуса и срока. */
  disc_overdue: number
}

export interface AssetsResponse {
  total: number
  items: AssetItem[]
  facets: AssetsFacets | null
  /** Сверка с ячейкой сводки AD — только при фильтре `ad_snapshot` + `ad_cell` и offset=0. */
  ad_cell?: AdCellCheck
}

/**
 * Сверка списка с ячейкой сводки AD (`ad_snapshot` + `ad_cell`). `found` — сколько участников ячейки нашлось в
 * «Активах» без учёта прочих фильтров страницы; `not_managed` — учётки, которых «Активы» не заводят (доверия);
 * `other` — участники другого вида (компьютеры на странице пользователей и наоборот); `summary_n` — число ячейки на
 * странице сводки AD (оба вида вместе), `null` — числа нет. У сводки без сохранённых настроек состав считается по
 * текущим настройкам AD, и `in_summary + other` может с ним разойтись.
 */
export interface AdCellCheck {
  label: string
  collected_at: string
  domain: string
  in_summary: number
  found: number
  not_managed: number
  other: number
  summary_n: number | null
}

export interface AssetsQuery {
  q?: string
  /** Многозначные фасеты уходят повторением ключа (buildQuery): внутри фасета «ИЛИ». */
  source_has?: AssetSource[]
  source_missing?: AssetSource[]
  code?: CodeFilter[]
  network_id?: number[]
  zone?: string[]
  /** internal | dmz | external | `-` (не задано). */
  placement?: string[]
  tag?: string
  criticality?: (Criticality | 'none')[]
  laps?: LapsFilter[]
  cluster?: ClusterKind[]
  /** Статусы расхождений (ключ повторяется); без него — учитываемые в подсчётах. */
  disc_status?: string[]
  /** Исполнитель расхождения: `me`, `none` или логин; несколько — «ИЛИ». */
  assignee?: string[]
  overdue?: boolean
  /** Состав ячейки сводки AD: снапшот и ячейка задаются вместе (ссылки со страницы «Сводка»). */
  ad_snapshot?: number
  ad_cell?: string
}

export interface Observation {
  id: number
  source: AssetSource
  source_key: string
  name: string
  fqdn: string
  domain: string
  ip: string
  ips: string[]
  os: string
  seen_at: string | null
  gone_at: string | null
  extra: Record<string, unknown>
  /** Поле → stale | conflict: какие ячейки подсветить. */
  marks: Partial<Record<'name' | 'fqdn' | 'ip', 'stale' | 'conflict'>>
}

/** Расхождение карточки — находка статусов платформы (module `assets`, scope 0, `key`). */
export interface Discrepancy {
  code: DiscrepancyCode
  source: AssetSource | ''
  field: string
  value: string
  current: string
  text: string
  key: string
  status: FindingStatus
  status_title: string
  assignee: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  /** Входит ли статус в подсчёты (настройка платформы `counted`). */
  counted: boolean
}

/** Массовая смена статуса расхождения `code` у отмеченных активов. */
export interface DiscrepancyBulk {
  ids: number[]
  code: DiscrepancyCode
  change: FindingChange
}

export interface AssetLinks {
  ad_finding_count: number | null
  ad_domain_id: number | null
  ad_query: string | null
  ksc_host_id: string | null
  ksc_server_id: number | null
  vm_host_id: number | null
  vm_cve_count: number | null
}

export interface AssetDetail extends AssetItem {
  network_manual: boolean
  note: string
  merged_into: number | null
  created_at: string | null
  updated_at: string | null
  observations: Observation[]
  discrepancies: Discrepancy[]
  links: AssetLinks
  /** Пользователи хоста, и пропавшие (`gone`); null — не собраны (нет живого наблюдения KSC с users_collected). */
  users: HostUser[] | null
  /** Группы с сеансом из KSC — только показ; null — не собраны. */
  session_groups: { sid: string; sam: string; active: boolean }[] | null
  /** Владелец задан в KSC, но среди пользователей хоста его нет. */
  owner_unresolved: boolean
}

/** Связь пользователя с хостом: сеанс (в системе на момент сбора / заходил раньше), владелец по KSC, локальная группа. */
export type UserHostKind = 'session' | 'owner' | 'local_group'

export interface HostUser {
  user_id: number
  sam: string
  display_name: string
  domain: string
  local: boolean
  kind: UserHostKind
  active: boolean
  seen_at: string | null
  gone: boolean
}

export interface AssetPatch {
  criticality?: Criticality | ''
  tags?: string[]
  note?: string
  /** Сеть вручную; null вместе с network_manual: false — вернуть расчёт по адресу. */
  network_id?: number | null
  network_manual?: boolean
}

/** Массовое изменение: теги добавляются и снимаются, не переданная критичность не меняется. */
export interface BulkPatch {
  ids: number[]
  criticality?: Criticality | ''
  tags_add?: string[]
  tags_remove?: string[]
}

/** Сеть /24 (IPv6 — /64) вокруг адреса: то, что предлагается создать для актива без сети. */
export function defaultCidr(ip: string): string {
  const v4 = ip.split('.')
  return v4.length === 4 ? `${v4.slice(0, 3).join('.')}.0/24` : `${ip}/64`
}

/** Расположение группы сетей; '' — не задано. */
export type Placement = 'internal' | 'dmz' | 'external' | ''
export const PLACEMENTS: Placement[] = ['internal', 'dmz', 'external', '']
/** Те же подписи, что в выгрузке сетей. */
export const PLACEMENT_LABELS: Record<Placement, string> = { internal: 'внутренняя', dmz: 'DMZ', external: 'внешняя', '': 'не задано' }

/** Признаки группы строкой: «DMZ · доступна из интернета · конфиденциальные данные»; '' — признаков нет. */
export function placementText(n: { placement: Placement; internet_facing: boolean; confidential?: boolean }): string {
  return [n.placement ? PLACEMENT_LABELS[n.placement] : '', n.internet_facing ? 'доступна из интернета' : '', n.confidential ? 'конфиденциальные данные' : '']
    .filter(Boolean).join(' · ')
}

/** Откуда у сети группа: вручную, по правилу, публичный адрес RackTables, не назначена. */
export type ZoneSource = 'manual' | 'rule' | 'racktables' | ''
export const ZONE_SOURCES: ZoneSource[] = ['manual', 'rule', 'racktables', '']
export const ZONE_SOURCE_LABELS: Record<ZoneSource, string> = { manual: 'вручную', rule: 'по правилу', racktables: 'публичный адрес (RackTables)', '': 'не назначена' }

/** Откуда сеть: описана вручную или создана проходом RackTables. */
export type NetworkOrigin = '' | 'racktables'
export const NETWORK_ORIGINS: NetworkOrigin[] = ['', 'racktables']
export const NETWORK_ORIGIN_LABELS: Record<NetworkOrigin, string> = { '': 'вручную', racktables: 'RackTables' }

/** Поля сети, которые задаёт человек. `zone_mode`: rules — группу назначают правила, manual — закрепить `zone`. */
export interface NetworkIn {
  cidr: string
  title: string
  description: string
  zone: string | null
  zone_mode?: 'manual' | 'rules'
  site: string
  owner: string
  vlan: number | null
  tags: string[]
}

/** Фильтры списка сетей; многозначные — повтором ключа, `-` — не задано. */
export interface NetworksQuery {
  q?: string
  zone?: string[]
  placement?: string[]
  zone_source?: string[]
  origin?: string[]
}

/** Расписание задачи модуля (DNS, RackTables, синхронизация) — общее расписание планировщика (platform/collector). */
export type NetworkSchedule = ScheduleView

/** Строка списка сетей (`GET /networks`, по страницам). */
export interface NetworkItem {
  id: number
  cidr: string
  title: string
  zone: string | null
  zone_title: string | null
  /** Расположение группы; '' — не задано или сеть без группы. */
  placement: Placement
  internet_facing: boolean
  zone_source: ZoneSource
  vlan: number | null
  site: string
  tags: string[]
  implicit_tags: string[]
  /** Пусто — описана вручную; racktables — создана проходом RackTables, который обновляет её название, описание, VLAN и теги. */
  origin: NetworkOrigin
  /** Активов в сети (без слитых). */
  assets: number
}

export interface NetworkList {
  total: number
  items: NetworkItem[]
  /** Только на первой странице (offset = 0); '' — не задано. */
  facets: Record<'zone' | 'placement' | 'zone_source' | 'origin', Record<string, number>> | null
}

export interface NetworkRef {
  id: number
  cidr: string
  title: string
}

/** Карточка сети (`GET /networks/{id}`; её же возвращают POST и PUT). */
export interface Network extends NetworkItem {
  description: string
  owner: string
  confidential: boolean
  zone_rule_id: number | null
  zone_rule: { id: number; match: RuleMatch; value: string; position: number } | null
  origin_key: string
  origin_seen_at: string | null
  /** Объемлющие — от узкой к широкой. */
  parents: NetworkRef[]
  children_count: number
  /** Вложенные — по адресу, не больше 100. */
  children: NetworkRef[]
  created_at: string
  updated_at: string
}

/** Группа сетей (в API — зона) с признаками; в расчёт риска признаки не идут. */
export interface Zone {
  name: string
  title: string
  description: string
  placement: Placement
  /** Сети группы доступны из интернета. */
  internet_facing: boolean
  /** В сетях группы конфиденциальные данные. */
  confidential: boolean
  /** Сколько сетей ссылается на зону: пока не ноль, удалить её нельзя. */
  networks: number
}

export type ZoneIn = Omit<Zone, 'networks'>
export type ZonePatch = Partial<Omit<Zone, 'name' | 'networks'>>

/** Условие правила группы: по имени сети (без учёта регистра), тегу (явному или унаследованному), адресу. */
export type RuleMatch = 'name_prefix' | 'name_contains' | 'name_glob' | 'tag' | 'cidr'
export const RULE_MATCHES: RuleMatch[] = ['name_prefix', 'name_contains', 'name_glob', 'tag', 'cidr']
export const RULE_MATCH_LABELS: Record<RuleMatch, string> = {
  name_prefix: 'имя начинается с',
  name_contains: 'имя содержит',
  name_glob: 'имя по шаблону',
  tag: 'есть тег',
  cidr: 'сеть внутри',
}

/** Правило отнесения сети к группе: проверяются по порядку, срабатывает первое включённое подошедшее. */
export interface ZoneRule {
  id: number
  position: number
  enabled: boolean
  zone: string
  match: RuleMatch
  value: string
  note: string
  /** Сетей сейчас в группе по этому правилу. */
  networks: number
  created_at: string
  updated_at: string
}

export type ZoneRuleIn = Pick<ZoneRule, 'match' | 'value' | 'zone' | 'enabled' | 'note'>

/** Какие не ручные сети забрало бы правило на этом месте (первые 20); база не меняется. */
export interface ZoneRulePreview {
  count: number
  sample: { id: number; cidr: string; title: string; zone_before: string | null }[]
}

export type DnsMode = 'direct' | 'ad'

/** DNS-сервер: прямые и обратные запросы (`direct`) или чтение зон AD через подключение AD (`ad`). */
export interface DnsIn {
  title: string
  mode: DnsMode
  /** Имя или адрес сервера; пусто — системный резолвер. */
  server: string
  ad_connection_id: number | null
  zones: string[]
  forward: boolean
  reverse: boolean
  zone_read: boolean
  rate_per_s: number
  timeout_ms: number
  enabled: boolean
}

export interface DnsServer extends DnsIn {
  id: number
  schedule_id: number | null
  last_run_at: string | null
  schedule: NetworkSchedule | null
}

/** Подключение к JSON API RackTables: сети и имена адресов → сети Assets и наблюдения RT. */
export interface RacktablesIn {
  title: string
  url: string
  username: string
  /** Пусто при обновлении — оставить прежний. */
  password: string
  verify_tls: boolean
  rate_per_s: number
  timeout_ms: number
  enabled: boolean
}

export interface Racktables extends Omit<RacktablesIn, 'password'> {
  id: number
  password_set: boolean
  schedule_id: number | null
  last_run_at: string | null
  schedule: NetworkSchedule | null
}

/** Подключение AD из `/api/ad/connections` — то, что нужно для выбора в форме DNS. */
export interface AdConnectionRef {
  id: number
  title: string
  host: string
}

/** Пороги расхождений и автосинхронизация после импорта модулей. */
export interface AssetSettings {
  /** Компьютер AD без входа и без других источников дольше — «неактивный». */
  inactive_days: number
  /** Наблюдение старше опорного на столько дней — «данные устарели». */
  stale_days: number
  sync_after_import: boolean
}

export type SyncSource = 'vm' | 'ksc' | 'ad'

/** `GET /sync/status`: последняя синхронизация и что лежит по каждому источнику модулей. */
export interface SyncStatus {
  last_sync_at: string | null
  last_job_id: number | null
  running_job_id: number | null
  sources: Record<string, { live: number; gone: number; seen_at: string | null }>
}

export interface AssetsOverview {
  assets_total: number
  /** Ключ "" — активы без сети или в сети без зоны. */
  by_zone: Record<string, number>
  by_source: Record<AssetSource, number>
  codes: Record<CodeFilter, number>
  networks: { total: number; no_network_assets: number }
  last_dns: { dns_id: number; title: string; last_run_at: string | null }[]
  sync: { last_sync_at: string | null; running_job_id: number | null }
}

// ---- Пользователи как активы ----

export type UserSource = 'ad' | 'ksc' | 'siem'
export const USER_SOURCES: UserSource[] = ['ad', 'ksc', 'siem']

/** Включённость по AD; `unknown` — AD учётку не видел (только KSC, локальная, домен без выгрузки). */
export type UserState = 'enabled' | 'disabled' | 'unknown'
export const USER_STATES: UserState[] = ['enabled', 'disabled', 'unknown']
export const USER_STATE_LABELS: Record<UserState, string> = { enabled: 'включена', disabled: 'отключена', unknown: 'неизвестно' }
export function userState(enabled: boolean | null): UserState {
  return enabled === null ? 'unknown' : enabled ? 'enabled' : 'disabled'
}

/** active — хоть один сеанс «в системе на момент сбора»; past — сеансы только прошлые; none — сеансов нет. */
export type UserSession = 'active' | 'past' | 'none'
export const USER_SESSIONS: UserSession[] = ['active', 'past', 'none']
export const USER_SESSION_LABELS: Record<UserSession, string> = { active: 'в системе на момент сбора', past: 'заходил раньше', none: 'сеансов нет' }

export type YesNo = 'yes' | 'no'
export const YES_NO: YesNo[] = ['yes', 'no']
export const YES_NO_LABELS: Record<YesNo, string> = { yes: 'да', no: 'нет' }

export type UserCode = 'disabled_session' | 'not_in_ad' | 'privileged_on_workstation' | 'owner_without_session'
export const USER_CODES: UserCode[] = ['disabled_session', 'not_in_ad', 'privileged_on_workstation', 'owner_without_session']
/** Те же подписи, что в выгрузке `/users/export`. */
export const USER_CODE_LABELS: Record<UserCode, string> = {
  disabled_session: 'сеанс отключённой учётки',
  not_in_ad: 'нет в AD',
  privileged_on_workstation: 'привилегированная на рабочей станции',
  owner_without_session: 'владелец без сеанса',
}
export type UserCodeFilter = UserCode | 'any'

export interface UserSourceBadge {
  source: UserSource
  live: boolean
  fresh: boolean
  seen_at: string
}

export interface UserItem {
  id: number
  sam: string
  upn: string
  display_name: string
  domain: string
  local: boolean
  enabled: boolean | null
  privileged: boolean
  sources: UserSourceBadge[]
  /** Хостов, где учётка в системе на момент сбора. */
  hosts_active: number
  /** Хостов с живыми связями любого вида. */
  hosts_total: number
  last_seen: string | null
  codes: UserCode[]
}

export interface UsersFacets {
  source: Record<UserSource, number>
  state: Record<UserState, number>
  session: Record<UserSession, number>
  local: Record<YesNo, number>
  privileged: Record<YesNo, number>
  code: Record<UserCodeFilter, number>
}

export interface UsersResponse {
  total: number
  items: UserItem[]
  facets: UsersFacets | null
  /** Сверка с ячейкой сводки AD — только при фильтре `ad_snapshot` + `ad_cell` и offset=0. */
  ad_cell?: AdCellCheck
}

/** Многозначные — повторением ключа: внутри оси «или», между осями «и». */
export interface UsersQuery {
  q?: string
  source?: UserSource[]
  state?: UserState[]
  session?: UserSession[]
  local?: YesNo[]
  privileged?: YesNo[]
  code?: UserCodeFilter[]
  /** Пользователи со связью с этими активами-хостами (и пропавшей тоже). */
  host_id?: number[]
  /** Состав ячейки сводки AD: снапшот и ячейка задаются вместе (ссылки со страницы «Сводка»). */
  ad_snapshot?: number
  ad_cell?: string
}

export interface UserObservation {
  id: number
  source: UserSource
  source_key: string
  seen_at: string | null
  gone_at: string | null
  data: Record<string, unknown>
}

export interface UserGroup {
  sid: string
  name: string
  /** true — прямое членство (и основная группа), false — через вложенную группу. */
  direct: boolean
  source: string
  /** Доменная группа в разделе «Группы»; null — записи нет (ссылки нет). */
  group_id: number | null
}

export interface UserDevice {
  asset_id: number
  name: string
  ip: string
  os: string
  kind: UserHostKind
  active: boolean
  seen_at: string | null
  gone_at: string | null
  /** false — пользователи на хосте не собраны: сеанс считается прошлым. */
  users_collected: boolean
  /** Живая связь на хосте без сбора старше stale_days: показывается, в расхождениях не участвует. */
  stale: boolean
}

export interface UserDiscrepancy {
  code: UserCode
  host_asset_id: number | null
  text: string
}

export interface UserDetail extends UserItem {
  sid: string
  name_key: string
  first_seen: string | null
  merged_into: number | null
  note: string
  tags: string[]
  created_at: string | null
  updated_at: string | null
  observations: UserObservation[]
  /** Прямые, затем вложенные, по имени. */
  groups: UserGroup[]
  /** Оговорки домена AD учётки (список участников группы мог быть обрезан). */
  group_notes: string[]
  /** Живые сначала. */
  devices: UserDevice[]
  discrepancies: UserDiscrepancy[]
}

export interface UserPatch {
  note?: string
  tags?: string[]
}

// ---- Группы как активы ----

/** Число с разрядами, как на обзоре модуля: 1 200. */
export function num(n: number): string {
  return n.toLocaleString('ru-RU')
}

export type GroupKind = 'local' | 'domain'
export const GROUP_KINDS: GroupKind[] = ['local', 'domain']
export const GROUP_KIND_LABELS: Record<GroupKind, string> = { local: 'локальная', domain: 'доменная' }

export type GroupSource = 'ad' | 'vm'
export const GROUP_SOURCES: GroupSource[] = ['ad', 'vm']
export const GROUP_SOURCE_LABELS: Record<GroupSource, string> = { ad: 'AD', vm: 'VM' }

/** Не выбрано — сервер отдаёт только живые (`gone` — группа пропала из последней синхронизации). */
export type GroupState = 'live' | 'gone'
export const GROUP_STATES: GroupState[] = ['live', 'gone']
export const GROUP_STATE_LABELS: Record<GroupState, string> = { live: 'живые', gone: 'пропавшие' }

export type GroupMembers = 'some' | 'none'
export const GROUP_MEMBERS: GroupMembers[] = ['some', 'none']
export const GROUP_MEMBERS_LABELS: Record<GroupMembers, string> = { some: 'есть прямые участники', none: 'без участников' }

export interface GroupItem {
  id: number
  name: string
  /** Домен у доменной, имя хоста у локальной. */
  domain_label: string
  host_asset_id: number | null
  local: boolean
  /** Семейство ОС локальной группы по снимку VM; у доменной пусто. */
  os_family: '' | 'windows' | 'linux'
  sid: string
  description: string
  sources: GroupSource[]
  members_direct: number
  /** false — доменная группа, которую видит только VM (в выгрузках AD её нет). */
  in_ad: boolean
  gone: boolean
}

export interface GroupsFacets {
  kind: Record<GroupKind, number>
  source: Record<GroupSource, number>
  state: Record<GroupState, number>
  members: Record<GroupMembers, number>
}

export interface GroupsResponse {
  total: number
  items: GroupItem[]
  facets: GroupsFacets | null
}

/** Многозначные — повторением ключа: внутри оси «или», между осями «и». */
export interface GroupsQuery {
  q?: string
  kind?: GroupKind[]
  source?: GroupSource[]
  state?: GroupState[]
  members?: GroupMembers[]
  /** Локальные группы этих активов-хостов. */
  host_id?: number[]
}

export type GroupMemberKind = 'group' | 'user' | 'computer' | 'well_known' | 'unknown'

export interface GroupMember {
  kind: GroupMemberKind
  /** По виду: user_id, group_id или актив-хост; null — без записи. */
  id: number | null
  name: string
  domain: string
  sid: string
  /** Участник через primaryGroupID (основная группа). */
  primary: boolean
  source: GroupSource
  /** Пояснение встроенного субъекта, у прочих пусто. */
  text: string
}

export interface GroupRef {
  id: number
  name: string
}

export interface GroupMemberOf extends GroupRef {
  domain: string
  direct: boolean
}

export interface GroupLocalOf {
  group_id: number
  name: string
  host_asset_id: number | null
  host_name: string
  /** Группы цепочки между этой группой и локальной (кратчайшая), [] — прямо. */
  via: GroupRef[]
}

export interface GroupFact {
  local_group: string
  local_group_sid: string
  via: GroupRef[]
  hosts_total: number
  /** Первые 50 по имени хоста. */
  hosts: { group_id: number; host_asset_id: number | null; host_name: string }[]
}

export type GpoVia = 'restricted_groups' | 'gpp'
export const GPO_VIA_LABELS: Record<GpoVia, string> = { restricted_groups: 'Restricted Groups', gpp: 'GPP' }

export interface GroupPolicy {
  local_group: string
  via: GpoVia
  action: string
  gpo_name: string
  /** У GPO есть фильтр безопасности: список хостов может быть шире действующего. */
  filtered: boolean
  hosts_total: number
  hosts: { name: string; asset_id: number | null }[]
  /** Доменный предок, через которого запись касается группы; null — сама группа. */
  through: GroupRef | null
}

export interface GroupGpoNotes {
  domain: string
  links_known: boolean
  files_known: boolean
  notes: string[]
}

export interface GroupDetail extends GroupItem {
  host_name: string
  first_seen: string | null
  last_seen: string | null
  gone_at: string | null
  /** У локальной — последний снимок VM, где её семейство записано полностью; null — такого нет (и у доменной). */
  vm_snapshot_at: string | null
  /** Не больше 1000; всего — members_total. */
  members: GroupMember[]
  members_total: number
  member_of: GroupMemberOf[]
  /** Не больше 1000; всего — local_member_of_total. */
  local_member_of: GroupLocalOf[]
  local_member_of_total: number
  rights: { fact: GroupFact[]; policy: GroupPolicy[]; notes: GroupGpoNotes[] }
}

export interface GroupExpandedItem {
  kind: 'user' | 'computer'
  id: number | null
  name: string
  domain: string
  sid: string
  via: GroupRef[]
  paths: number
}

export interface GroupExpanded {
  /** Пользователей и компьютеров (встроенные и тупики не входят). */
  total: number
  items: GroupExpandedItem[]
  well_known: { sid: string; name: string; text: string; via: GroupRef[]; paths: number }[]
  /** Не больше 500; всего — dead_ends_total. */
  dead_ends: { kind: 'group' | 'unknown'; id: number | null; name: string; domain: string; sid: string; via: GroupRef[]; paths: number; reason: string }[]
  dead_ends_total: number
  notes: string[]
}
