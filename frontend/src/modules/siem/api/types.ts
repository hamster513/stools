/**
 * Типы запросов и ответов API модуля SIEM Rules Analyzer.
 *
 * Единственный источник — docs/api-contract.md в корне репозитория. Любое
 * расхождение между этим файлом и контрактом — дефект фронтенда, не бэкенда.
 * Типы держим здесь и не раскидываем по компонентам.
 */

// Матрица ATT&CK одна на все модули и живёт в платформенном модуле
// `attack`. Экраны SIEM продолжают звать её словарь тактик отсюда:
// перенос типов — не повод править каждый импорт.
export { tacticLabel } from '@/modules/attack/api/types'

// Статусы находок — общие статусы платформы (platform/findings).
import type { FindingStatus } from '@/platform/findings/types'
export type { FindingStatus }

// ---------------------------------------------------------------------------
// Общие
// ---------------------------------------------------------------------------

export interface ApiError {
  detail: string
}

// ---------------------------------------------------------------------------
// Снапшоты
// ---------------------------------------------------------------------------

export interface SnapshotListItem {
  id: number
  created_at: string
  filename: string
  rule_count: number
  finding_count: number
  kb_version: string | null
  /** Разбор завершён хотя бы раз. Активный снапшот — разобранный с наибольшим id. */
  parsed: boolean
  /** Откуда снапшот: загруженный файл или сбор из базы знаний по API. */
  source_type: 'upload' | 'api'
  kb_host: string | null
  kb_database: string | null
}

export interface CreateSnapshotResponse {
  job_id: number
  snapshot_id: number
  duplicate?: boolean
}

/** Класс находки: 1 — дублирует список, …, 5 — одиночный литерал. */
export type FindingKind = '1' | '2' | '3' | '4' | '5'

export type ObjectType = 'correlation' | 'filter' | 'enrichment'

export type Polarity = 'negation' | 'assertion'

export interface TableRankingEntry {
  name: string
  exists: boolean
  value_count: number
  dependant_count: number
  is_empty: boolean
  is_scoping: boolean
  risk: number
}

export interface SnapshotDelta {
  finding_count: number
  rule_count: number
}

export interface SnapshotSummary {
  id: number
  created_at: string
  filename: string
  rule_count: number
  group_count: number
  rules_without_code: number
  unsupported_count: number
  edge_count: number
  scoped_count: number
  finding_count: number
  findings_by_kind: Record<FindingKind, number>
  findings_by_polarity: Record<Polarity, number>
  findings_by_object_type: Record<ObjectType, number>
  objects_with_findings: number
  in_table_count: number
  divergence_count: number
  clone_count: number
  rules_without_msgid: number
  name_scheme_coverage: string
  profile_confirmed: boolean
  authors: Record<string, number>
  table_ranking: TableRankingEntry[]
  delta: SnapshotDelta | null
  /** Откуда снапшот: загруженный файл или сбор из базы знаний по API. */
  source_type: 'upload' | 'api'
  kb_host: string | null
  kb_database: string | null
}

// ---------------------------------------------------------------------------
// Задания
// ---------------------------------------------------------------------------

export type JobStage =
  | 'pending'
  | 'connecting'
  | 'listing'
  | 'exporting'
  | 'parsing'
  | 'analyzing'
  | 'persisting'
  | 'done'
export type JobStatus = 'running' | 'done' | 'failed'

export interface JobStatusResponse {
  id: number
  stage: JobStage
  status: JobStatus
  progress: number
  error: string | null
  snapshot_id: number | null
}

// ---------------------------------------------------------------------------
// Находки
// ---------------------------------------------------------------------------

export type FindingSeverity = 'high' | 'medium' | 'low'

export interface FindingListItem {
  id: number
  /** Ключ находки для статусов платформы (module `siem`, scope 0). */
  key: string
  kind: FindingKind
  severity: FindingSeverity
  object_type: ObjectType
  object_name: string
  object_uuid: string
  field: string
  polarity: Polarity
  in_table: boolean
  /** Форма значения независимо от класса: сетевое имя, попавшее
   *  в «дублирует список», иначе в интерфейсе не найти. */
  shape: ValueShape
  table_name: string | null
  status: FindingStatus
  status_title: string
  assignee: string | null
  assignee_name: string | null
  due_date: string | null
  overdue: boolean
  risk_until: string | null
  first_seen_at: string | null
  age_days: number | null
  /** Находки нет в активном снапшоте: показана по последнему, где была. */
  gone: boolean
  has_value: boolean
}

export interface FindingsFacets {
  kind: Partial<Record<FindingKind, number>>
  polarity: Partial<Record<Polarity, number>>
  object_type: Partial<Record<ObjectType, number>>
  in_table: { true?: number; false?: number }
  shape: Record<string, number>
  status: Partial<Record<FindingStatus, number>>
  /** Логин → число; `none` — без исполнителя. */
  assignee: Record<string, number>
  flags: { overdue: number; risk_expiring: number }
  /** Поля не перечислимы заранее — их набор зависит от выгрузки.
   *  Сервер отдаёт их по убыванию числа находок. */
  field: Record<string, number>
}

export interface FindingsListResponse {
  total: number
  items: FindingListItem[]
  facets: FindingsFacets
  /** Снапшот — активный (последний разобранный): только у него есть пропавшие находки. */
  is_latest: boolean
  /** Статусы — на сегодня у любого снапшота, находки — на дату снапшота. */
  statuses_as_of: 'today'
  /** Соли ключей нет, а решения есть: статусы не сопоставить, все показаны как «Новая». */
  status_keys_broken: boolean
}

/** Форма значения: сетевой адрес, подсеть, имя узла — или обычное значение.
 *  В фильтре обычное значение называется `plain`: пустая строка в строке
 *  запроса неотличима от «параметр не задан». */
export type ValueShape = 'ip' | 'cidr' | 'fqdn' | null
export type ShapeFilter = 'ip' | 'cidr' | 'fqdn' | 'plain'

export interface FindingsQuery {
  /** Находки одного правила — вход из инвентаря. */
  object_uuid?: string
  snapshot_id: number
  /** Многозначные фасеты уходят повторением ключа (buildQuery): `kind=1&kind=2`. */
  kind?: FindingKind[]
  polarity?: Polarity[]
  object_type?: ObjectType[]
  in_table?: boolean
  shape?: ShapeFilter[]
  /** Коды (ключ повторяется) или `all`; не задан — открытые. */
  status?: string[] | 'all'
  /** `me`, `none` или логин; несколько — «ИЛИ». */
  assignee?: string[]
  overdue?: boolean
  risk_expiring?: boolean
  /** Одна находка по ключу — ссылка `?key=`. */
  key?: string
  field?: string[]
  q?: string
  sort?: string
  order?: 'asc' | 'desc'
  limit?: number
  offset?: number
}

export interface AffectedRule {
  uuid: string
  name: string
}

export interface FindingDetail {
  value: string
  body_excerpt: string
  table_name: string | null
  affected_rules: AffectedRule[]
}

// ---------------------------------------------------------------------------
// Расхождения правило ↔ список
// ---------------------------------------------------------------------------

export interface DivergenceItem {
  id: number
  field: string
  table_name: string
  hardcoded_in: string
  blast_radius: number
  has_value: boolean
}

export interface DivergencesResponse {
  total: number
  items: DivergenceItem[]
}

export interface DivergencesQuery {
  snapshot_id: number
  limit?: number
  offset?: number
}

// ---------------------------------------------------------------------------
// Правила
// ---------------------------------------------------------------------------

export type ParseStatus = 'ok' | 'unsupported' | 'error'

export interface RuleListItem {
  uuid: string
  name: string
  author: string
  category: string
  group: string
  rule_id: string
  origin: string
  parse_status: ParseStatus
  msgid_count: number
  finding_count: number
  table_reads: number
  scoped: boolean
  /** Находки без вердикта «принято» — только они требуют внимания. */
  open_finding_count: number
  /** Наибольшая тяжесть среди открытых находок; null — открытых нет. */
  max_severity: FindingSeverity | null
  /** Установлено ли правило в SIEM по списку объектов базы знаний; null —
   *  снапшот из файла или правила в списке KB нет. */
  installed: boolean | null
  folder_path: string | null
  /** В списке — kb_id наборов установки, в карточке — их имена. */
  deployment_sets: string[]
  /** Правило наследует разметку своей группы; может отсутствовать, пока
   *  разметка ATT&CK не запускалась. */
  attack?: RuleAttackInfo
}

export interface RulesListResponse {
  total: number
  items: RuleListItem[]
}

export interface RulesQuery {
  snapshot_id: number
  author?: string
  category?: string
  group?: string
  q?: string
  limit?: number
  offset?: number
}

/**
 * Требования правила к телеметрии.
 *
 * Собственные и унаследованные msgid разделены намеренно: правило-потомок
 * без собственных msgid не означает «логи не нужны» — оно наследует
 * требования по цепочке зависимостей.
 */
export interface RuleMsgids {
  own: string[]
  inherited: string[]
}

/** Соседи правила в графе зависимостей, по именам. */
export interface RuleDependencies {
  parents: string[]
  children: string[]
}

export interface RuleFindingSummary {
  id: number
  kind: FindingKind
  field: string
  status: FindingStatus
  /** Статус учитывается в подсчётах (настройка платформы `counted`). */
  counted: boolean
}

/** Отрезок тела правила, занятый значением находки. */
export interface RuleBodySpan {
  start: number
  end: number
  kind: FindingKind | number
  status: FindingStatus
  /** Неучитываемое замечание (принят риск, ложное срабатывание) гасится. */
  counted: boolean
}

export interface RuleDetail {
  uuid: string
  name: string
  author: string
  category: string
  group: string
  rule_id: string
  origin: string
  parse_status: ParseStatus
  scoped: boolean
  title_ru: string | null
  /** Установлено ли правило в SIEM по списку объектов базы знаний; null —
   *  снапшот из файла или правила в списке KB нет. */
  installed: boolean | null
  folder_path: string | null
  /** В списке — kb_id наборов установки, в карточке — их имена. */
  deployment_sets: string[]
  title_en: string | null
  /** Что правило сообщает при срабатывании — из локализации выгрузки. */
  description_ru: string | null
  description_en: string | null
  /** Где в теле сидят находки: значения наружу не идут, только отрезки. */
  body_spans?: RuleBodySpan[]
  body_hash: string
  msgids: RuleMsgids
  dependencies: RuleDependencies
  table_reads: string[]
  table_writes: string[]
  findings: RuleFindingSummary[]
  body: string
  attack?: RuleAttackInfo
}

// ---------------------------------------------------------------------------
// Клоны и граф
// ---------------------------------------------------------------------------

export interface CloneEntry {
  rule_a: string
  rule_b: string
  similarity: number
}

export interface CloneSide {
  uuid: string
  name: string
  title: string | null
  /** Тела нет у правил, которые не разобрались. */
  body: string | null
}

export interface SignatureSplit {
  common: string[]
  only_a: string[]
  only_b: string[]
}

export type DiffLineKind = 'equal' | 'replace' | 'insert' | 'delete'

/** Строка выкладки бок о бок; у вставки пусто слева, у удаления — справа. */
export interface DiffLine {
  kind: DiffLineKind
  a: string | null
  b: string | null
}

export interface CloneCompare {
  a: CloneSide
  b: CloneSide
  /** null, если пара не из таблицы клонов: сравнить можно любые два правила. */
  similarity: number | null
  signature: { msgids: SignatureSplit; fields: SignatureSplit; filters: SignatureSplit }
  lines: DiffLine[]
  changed_lines: number
}

export interface GraphEdge {
  parent: string
  child: string
}

export interface GraphResponse {
  edges: GraphEdge[]
  unresolved: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Профиль инсталляции
// ---------------------------------------------------------------------------

/** Статистика одной позиции имени (kbaudit.naming.SegmentStat). */
export interface NameSchemeSegment {
  position: number
  /** author | category | group | rule_id; null — свободное описание. */
  role: string | null
  coverage: number
  distinct: number
  numeric_share: number
  examples: string[]
}

/**
 * Схема именования правил, выведенная из выгрузки (kbaudit.naming.NameScheme).
 * Форма — ядра, а не макета: экран показывает то, что ядро посчитало.
 */
export interface NameScheme {
  separator: string
  segments: string[]
  total: number
  coverage: number
  group_count: number
  stats: NameSchemeSegment[]
  depth: number
  score: number
}

export interface ProfileTables {
  scoping: string[]
  watched: string[]
}

export interface InstallationProfile {
  /** Принципалы, встроенные в платформу: учтены без всякой настройки. */
  builtin_accounts_default?: string[]
  /** Роли полей, встроенные в инструмент. */
  field_roles_default?: FieldRolesPatch
  tables: ProfileTables
  builtin_accounts: string[]
  /** Дополнения к встроенным ролям: списки имён полей, а не пары. */
  field_roles: FieldRolesPatch
  name_scheme: NameScheme | null
  confirmed_by: string | null
  confirmed_at: string | null
}

export interface UpdateProfileRequest {
  snapshot_id: number
  tables: ProfileTables
  builtin_accounts: string[]
  /** Дополнения к встроенным ролям: списки имён полей, а не пары. */
  field_roles: FieldRolesPatch
  name_scheme?: NameScheme
}

export type ProfileSuggestResponse = InstallationProfile

// ---------------------------------------------------------------------------
// Разметка ATT&CK
// ---------------------------------------------------------------------------

/** Уверенность разметки качественная: число создаёт ложную точность. */
export type AttackConfidence = 'высокая' | 'средняя' | 'низкая'

export type AttackSource = 'llm' | 'manual' | 'reference'

/** Состояние разметки группы: черновик модели должен быть отличим от решения человека. */
export type AttackStatus = 'unmapped' | 'suggested' | 'confirmed'

export interface AttackTechniqueMapping {
  technique_id: string
  /** Перевод есть у всех 697 техник бандла; null возможен только если
   *  бандл новее перевода. */
  name_ru: string | null
  /** Английское название остаётся: часть техник узнаваема только по нему. */
  name: string
  tactics: string[]
  confidence: AttackConfidence | ''
  evidence?: string
  source?: AttackSource | ''
  /** Техники нет в действующей матрице: отозвана или переименована. */
  missing?: boolean
  /** Техника отозвана MITRE, и разметка показана по её замене. В базе
   *  остаётся то, что подтвердил человек, — перенос только показывается. */
  moved_from?: string | null
}

export interface AttackGroup {
  group: string
  rule_count: number
  /** Состояние группы — самое слабое среди её правил: группа, где размечено
   *  девятнадцать правил из двадцати одного, не размечена целиком. */
  status: AttackStatus
  /** Правил без разметки, подтверждённых и унаследовавших разметку группы. */
  unmapped_rules: number
  confirmed_rules: number
  inherited_rules: number
  techniques: AttackTechniqueMapping[]
  /** Что видела модель — без этого разобраться в спорной разметке через
   *  полгода невозможно, кандидаты меняются вместе с бандлом и моделью. */
  candidates: string[]
  model: string | null
  attack_version: string | null
  reviewed_by: string | null
  reviewed_at: string | null
  /** Подтверждено на другой версии матрицы — повод пересмотреть. */
  version_outdated?: boolean
}

export interface AttackGroupsResponse {
  total: number
  items: AttackGroup[]
}

export interface AttackGroupsQuery {
  snapshot_id: number
  status?: AttackStatus
}

export interface AttackCoverage {
  attack_version: string
  /** Единица разметки — правило. Счёт по группам показывал сорок четыре
   *  решения там, где их сто восемьдесят семь. */
  rule_count: number
  group_count: number
  /** Правил, чья разметка досталась от группы и для них не уточнялась. */
  inherited: number
  confirmed: number
  suggested: number
  unmapped: number
  techniques_covered: number
  by_tactic: Record<string, number>
  model: string | null
  /** Пустой адрес модели — законное состояние, а не ошибка: без неё
   *  работает всё, кроме предложений. Экран обязан это объяснять. */
  llm_configured: boolean
  outdated_groups: number
  missing_techniques: string[]
}

export interface AttackRunRequest {
  snapshot_id: number
}

export interface AttackRunResponse {
  job_id: number
}

export interface AttackConfirmRequest {
  snapshot_id: number
  /** Разметить одно правило. Ровно одно из двух: правило или группа. */
  rule_uuid?: string
  /** Разметить всю группу разом — правила получат её разметку с пометкой,
   *  что для каждого в отдельности она не проверена. */
  group?: string
  /** Пустой список — тоже решение: «это правило ни одной технике
   *  не соответствует» отличается от «ещё не смотрели». */
  techniques: string[]
  reason?: string
}

/** Правило с маркировкой — та же, что в инвентаре. */
export interface AttackRuleBrief {
  uuid: string
  name: string
  parse_status: ParseStatus
  scoped: boolean
  open_finding_count: number
  max_severity: FindingSeverity | null
}

export interface AttackGroupDetail extends AttackGroup {
  reason: string | null
  rules: AttackRuleBrief[]
  /** Правил с неразобранным телом: разметка такой группы стоит меньше. */
  unparsed: number
  with_findings: number
}

export interface FieldRolesPatch {
  environmental: string[]
  technical: string[]
}

export type FieldRole = 'environmental' | 'technical' | 'unknown'

/** Откуда взялась роль: решение человека, таксономия выгрузки,
 *  встроенный список инструмента — или ниоткуда. */
export type FieldRoleSource =
  | 'profile'
  | 'taxonomy'
  | 'documentation'
  | 'builtin'
  | 'none'

export interface ProfileFieldItem {
  field: string
  rule_count: number
  role: FieldRole
  source: FieldRoleSource
  /** Роль задана человеком: снять можно только свою. */
  from_profile: boolean
}

export interface ProfileFieldsResponse {
  total: number
  /** Поле без роли не анализируется вовсе. */
  unknown: number
  /** Ролей, выведенных из описания полей в taxonomy.json выгрузки. */
  from_taxonomy: number
  items: ProfileFieldItem[]
}

export interface ProfilePreview {
  finding_count: number
  scoped_count: number
  group_count: number
}

export interface TableListItem {
  name: string
  value_count: number
  is_empty: boolean
  /** Сколько правил читают этот список. */
  read_by: number
}

export interface TableListsResponse {
  total: number
  items: TableListItem[]
}

export interface TableValuesResponse {
  name: string
  total: number
  shown: number
  columns: string[]
  /** Колонки-комментарии: человек пишет их для себя, а не для сравнения. */
  comment_columns: string[]
  /** Состав списка строками — приходит только по явному запросу. */
  rows: Record<string, string>[]
}

export interface TableReadersResponse {
  name: string
  total: number
  items: { uuid: string; name: string }[]
}

/** Разметка, унаследованная правилом от своей группы. */
export interface RuleAttackInfo {
  status: AttackStatus
  group: string | null
  techniques: AttackTechniqueMapping[]
  /** Разметка досталась от группы и для этого правила не уточнялась.
   *  Показывать её как проверенную нельзя. */
  inherited?: boolean
}

// ---------------------------------------------------------------------------
// Настройки
// ---------------------------------------------------------------------------

export interface AttackSettings {
  top_k: number
  attack_version: string
}

/** Настройки модуля. Модель сюда не входит: она общая для платформы и
 *  живёт в общих настройках (`/api/settings/llm`). */
export interface Settings {
  attack: AttackSettings
}

export interface UpdateSettingsRequest {
  attack: AttackSettings
}

export interface KbConnectionView {
  host: string
  kb_port: number
  verify_tls: boolean
  /** Персональный API-токен MaxPatrol задан; само значение наружу не отдаётся. */
  api_token_set: boolean
  configured: boolean
}

export interface KbConnectionUpdate {
  host: string
  kb_port: number
  /** Пусто — оставить прежний токен. */
  api_token: string
  verify_tls: boolean
}

export interface KbTestResponse {
  ok: boolean
  message: string
  version: string
  database: string
  events_ok: boolean
  events_message: string
}

export interface DeploymentSetView {
  kb_id: string
  parent_kb_id: string | null
  name: string
  system_name: string
  general_status: string
  compilation_status: string
  deployment_statuses: Record<string, string>
  rule_count: number
}

export interface DeploymentSetsResponse {
  available: boolean
  sets: DeploymentSetView[]
  objects_total: number
  installed: number
  kb_not_exported: string[]
}

// ---------------------------------------------------------------------------
// Метки для интерфейса
// ---------------------------------------------------------------------------

export const ATTACK_STATUS_LABELS: Record<AttackStatus, string> = {
  unmapped: 'не размечено',
  suggested: 'предложено моделью',
  confirmed: 'подтверждено человеком',
}

export const FINDING_KIND_LABELS: Record<FindingKind, string> = {
  '1': 'дублирует список',
  '2': 'IP / CIDR / FQDN',
  '3': 'not in_list из 3+',
  '4': 'доменный SID',
  '5': 'одиночный литерал',
}

/**
 * Что именно не так — человеческим языком.
 *
 * Общее для всех классов: претензия не к полю, а к **значению**, с которым
 * это поле сравнивают прямо в теле правила. Поле называется лишь затем,
 * чтобы найти место в коде.
 */
export const FINDING_KIND_EXPLANATION: Record<FindingKind, string> = {
  '1': 'Значение зашито в теле правила, хотя оно же лежит в табличном списке. Список поправят — правило об этом не узнает и продолжит работать по старому значению.',
  '2': 'В теле правила зашит сетевой адрес, подсеть или имя узла. Это описание конкретной инсталляции: сменится адресация — правило придётся править руками в каждом месте.',
  '3': 'Поле сравнивается через отрицание сразу с тремя и более значениями. Такой перечень исключений — накопленный вручную белый список: он растёт с каждым разбором ложного срабатывания и нигде не учитывается.',
  '4': 'В теле зашит идентификатор безопасности конкретного домена. В другой инсталляции такое правило не сработает вовсе, и молча.',
  '5': 'Единичное значение зашито прямо в теле, минуя табличный список. Поменять его можно только правкой правила.',
}

/** Что с этим делать. Совет, а не предписание: решение принимает человек. */
export const FINDING_KIND_ADVICE: Record<FindingKind, string> = {
  '1': 'Заменить литерал обращением к тому же списку — тогда правило и список перестанут расходиться.',
  '2': 'Вынести адрес в табличный список, чтобы смена адресации не требовала правки правил.',
  '3': 'Перенести перечень исключений в табличный список: там он виден, считается и переживает обновление правила.',
  '4': 'Вынести идентификатор домена в настройку инсталляции.',
  '5': 'Проверить, должно ли значение быть настраиваемым. Если да — вынести в список.',
}

export const OBJECT_TYPE_LABELS: Record<ObjectType, string> = {
  correlation: 'корреляция',
  filter: 'фильтр',
  enrichment: 'обогащение',
}

export const POLARITY_LABELS: Record<Polarity, string> = {
  negation: 'отрицание',
  assertion: 'утверждение',
}

export const SHAPE_LABELS: Record<ShapeFilter, string> = {
  fqdn: 'имя узла',
  ip: 'IP-адрес',
  cidr: 'подсеть',
  plain: 'обычное значение',
}

/** Итог сверки одного правила с эталоном. */
export type ReferenceVerdict =
  | 'same'
  | 'reference_finer'
  | 'reference_coarser'
  | 'partial'
  | 'different'
  | 'no_markup'

export interface ReferenceItem {
  uuid: string
  name: string
  /** Идентификатор правила в исходной таблице, как его написал человек. */
  source_key: string
  verdict: ReferenceVerdict
  ours: string[]
  theirs: string[]
  /** Что стояло в таблице до переноса на действующую версию ATT&CK. */
  original: string[]
  note: string
  status: AttackStatus
  inherited: boolean
}

export interface ReferenceCompare {
  loaded: boolean
  source: string | null
  imported_at: string | null
  imported_by: string | null
  compared: number
  counts: Partial<Record<ReferenceVerdict, number>>
  items: ReferenceItem[]
  /** Строки эталона, которым не нашлось правила в выгрузке. */
  unmatched: { source_key: string; theirs: string[] }[]
  rules_without_reference: number
}

export interface ReferenceImportResult {
  source: string
  rows: number
  rows_without_techniques: number
  matched_rules: number
  matched_by: Record<string, number>
  unmatched_keys: string[]
  rules_without_reference: number
  /** Ссылок на техники, отозванные MITRE и перенесённые на замену. */
  migrated_techniques: number
  unknown_techniques: string[]
  columns: Record<string, string>
}

export interface ApplyReferenceRequest {
  snapshot_id: number
  /** Одно правило. Без него принимается всё, что отобрано `verdicts`. */
  rule_uuid?: string
  /** Итоги сверки, которые принимаются. Пусто — все сверенные правила. */
  verdicts?: ReferenceVerdict[]
}

export interface ApplyReferenceResult {
  applied: number
  skipped_empty: number
  considered: number
}
