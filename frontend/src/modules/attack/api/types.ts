/**
 * Типы запросов и ответов API модуля ATT&CK.
 *
 * Матрица здесь одна на все модули: SIEM отдаёт покрытие правилами, VM и AD —
 * экспозицию, а склейка живёт на бэкенде. Поэтому ни имён правил, ни узлов,
 * ни находок в этих типах нет — только идентификаторы слоёв и их ячейки.
 */

// ---------------------------------------------------------------------------
// Применяемость здесь
// ---------------------------------------------------------------------------

/** Применяемость техники здесь — из загруженной выгрузки.
 *
 *  Пусто, а не нули, когда выгрузки нет: ноль читался бы как «здесь не
 *  применяют», хотя на самом деле никто не отчитывался. */
export interface RuUsage {
  actors: number
  malware: number
  tools: number
  procedures: number
  /** Процедур с конкретной командой — материал для правила. */
  commands: number
  actor_names: string[]
}

/** Чья выгрузка и когда загружена. Чужую аналитику нельзя показывать
 *  как безымянный факт. */
export interface RuSource {
  source: string
  imported_at: string | null
  imported_by: string | null
  attack_version: string | null
  row_count: number
}

export interface RuProcedure {
  technique_id: string
  procedure: string
  command_line: string
  actors: string[]
  malware: string[]
  tools: string[]
}

export interface RuTechniqueItem {
  technique_id: string
  name: string
  ru: RuUsage | null
  world_groups: number
}

/** Расхождение двух источников. Четыре состояния, а не два флага:
 *  «нет у источника» значит «источник не отчитывался». */
export interface RuTtpState {
  source: RuSource | null
  attack_version: string
  counts: Partial<Record<'both' | 'ru_only' | 'world_only' | 'none', number>>
  ru_only: RuTechniqueItem[]
  world_only: RuTechniqueItem[]
  unknown: string[]
}

export interface RuTtpImportResult {
  rows: number
  techniques: number
  without_technique: number
  moved: number
  unknown: string[]
  columns: Record<string, string>
  attack_version: string | null
}

// ---------------------------------------------------------------------------
// Слои модулей
// ---------------------------------------------------------------------------

export type LayerKind = 'coverage' | 'exposure'

export interface LayerMeta {
  id: string
  title: string
  kind: LayerKind
  /** Формы единицы: [«хост», «хоста», «хостов»]. */
  unit: [string, string, string]
  available: boolean
  note: string | null
}

export interface LayerItem {
  title: string
  subtitle: string
  href: string
}

export interface LayerCell {
  count: number
  /** Только у покрытия: confirmed | suggested. */
  status: 'confirmed' | 'suggested' | null
  items?: LayerItem[]
}

// ---------------------------------------------------------------------------
// Матрица и карточка техники
// ---------------------------------------------------------------------------

export interface AttackMatrixCell {
  technique_id: string
  name: string
  name_ru: string | null
  subtechnique_count: number
  /** Насколько техника распространена: 0 — данных нет, 4 — очень часто.
   *  Ноль и единица различаются: «сенсор не видит» и «редко» — разное. */
  level: number
  actor_groups: number
  campaigns: number
  sightings: number
  ru: RuUsage | null
  layers: Record<string, LayerCell | null>
  covered: boolean
  /** Экспозиция есть, покрытия нет. */
  gap: boolean
}

export interface AttackMatrixColumn {
  shortname: string
  name: string
  techniques: AttackMatrixCell[]
  covered: number
  gaps: number
  /** Ни одна техника тактики не закрыта: пропущен целый шаг атаки. */
  blind: boolean
  /** Разведку и подготовку ресурсов сенсоры не видят по своей природе. */
  observable: boolean
}

export interface AttackMatrix {
  attack_version: string
  /** Окно наблюдения телеметрии — она заморожена, и это должно быть видно. */
  sightings_window: string | null
  ru_source: RuSource | null
  layers: LayerMeta[]
  /** Тактики в порядке MITRE: это последовательность шагов атаки. */
  tactics: AttackMatrixColumn[]
}

export interface AttackSubtechnique {
  technique_id: string
  name: string
  name_ru: string | null
  covered: boolean
  /** Распространённость 0..4 — по ней подтехники и отсортированы:
   *  человеку, пришедшему уточнять разметку, важно с чего начать. */
  level: number
  actor_groups: number
  sightings: number
  ru: RuUsage | null
}

export interface AttackTechniqueDetail {
  technique_id: string
  name: string
  name_ru: string | null
  description_ru: string | null
  description: string
  tactics: string[]
  is_subtechnique: boolean
  parent_id: string | null
  subtechniques: AttackSubtechnique[]
  ru: RuUsage | null
  /** Процедуры из выгрузки: у непокрытой техники это готовый материал
   *  для правила, а не справка о том, что бывает. */
  ru_procedures: RuProcedure[]
  layers: Record<string, LayerCell | null>
  covered: boolean
  gap: boolean
}

export interface AttackTechniqueSummary {
  technique_id: string
  name: string
  name_ru: string | null
  description_ru: string | null
  tactics: string[]
  is_subtechnique: boolean
  parent_id: string | null
}

export interface AttackTechniquesResponse {
  total: number
  items: AttackTechniqueSummary[]
}

// ---------------------------------------------------------------------------
// Цепочки кампаний
// ---------------------------------------------------------------------------

export interface ChainStep {
  tactic: string
  /** Шаг, не закрытый ни одним правилом. */
  blind: boolean
  /** Разведку и подготовку ресурсов сенсоры не видят по определению. */
  observable: boolean
  total: number
  covered: number
  uncovered: { technique_id: string; name: string; ru: RuUsage | null }[]
}

export interface AttackChain {
  id: string
  name: string
  first_seen: string | null
  last_seen: string | null
  technique_count: number
  uncovered_count: number
  blind_steps: number
  steps: ChainStep[]
}

export interface AttackChains {
  total: number
  items: AttackChain[]
  attack_version: string
  /** Кампании ATT&CK отстают — дату последней надо показывать. */
  latest_seen: string
  ru_source: RuSource | null
  /** Техники, у которых в инфраструктуре есть чем их выполнить. */
  exposed: string[]
}

// ---------------------------------------------------------------------------
// Бандл и перевод
// ---------------------------------------------------------------------------

export interface BundleReplacement {
  replaced_version: string | null
  current_version: string | null
  /** Поставка оказалась старее загруженного — это откат назад. */
  downgraded: boolean
  replaced_at: string | null
}

export interface AttackBundleState {
  version: string | null
  /** builtin — вложенный в образ, uploaded — загруженный человеком файлом,
   *  online — скачанный с сайта MITRE и подтверждённый. */
  source: 'builtin' | 'uploaded' | 'online'
  loaded_at: string
  loaded_by: string | null
  technique_count: number
  tactic_count: number
  translated: number
  missing: number
  /** Перевод есть, но английский исходник с тех пор изменился. */
  stale: number
  /** Поставка перекрыла загруженную матрицу. null — замены не было. */
  replacement: BundleReplacement | null
}

export interface AttackBundleDiff {
  version: string | null
  current_version: string | null
  added: string[]
  changed: string[]
  removed: string[]
  tactics_added: string[]
  tactics_removed: string[]
  untranslated: number
  stale_translations: number
}

/** Скачанное с сайта MITRE, ждущее подтверждения. Самого бандла здесь нет —
 *  он мегабайтный; человеку нужна разница, а не файл. */
export interface PendingBundle {
  version: string | null
  downloaded_at: string
  url: string
  diff: AttackBundleDiff
}

export interface TranslationGap {
  technique_id: string
  name: string
  reason: 'missing' | 'stale'
}

export interface TranslationGapsResponse {
  total: number
  items: TranslationGap[]
}

export interface TranslateResponse {
  job_id: number
  pending: number
}

// ---------------------------------------------------------------------------
// Задачи
// ---------------------------------------------------------------------------

export interface AttackJob {
  id: number
  kind: string
  stage: string
  status: 'running' | 'done' | 'failed' | 'cancelled'
  progress: number
  processed: number
  total: number | null
  message: string
  error: string | null
  cancel_requested: boolean
  started_at: string
  finished_at: string | null
  started_by: string
}

export const JOB_KIND_LABELS: Record<string, string> = {
  translate: 'Перевод техник',
  download: 'Скачивание матрицы',
}

export const JOB_STAGE_LABELS: Record<string, string> = {
  pending: 'ожидание',
  translating: 'перевод',
  download: 'скачивание',
  parse: 'разбор',
  diff: 'сравнение',
  done: 'готово',
}

// ---------------------------------------------------------------------------
// Метки для интерфейса
// ---------------------------------------------------------------------------

/**
 * Названия тактик. Состав сверен с бандлом ATT&CK 19.2: в этой версии
 * «обход защиты» разделён на две тактики — Defense Impairment (подавление
 * средств защиты) и Stealth (скрытность). Прежняя `defense-evasion`
 * оставлена для бандлов старых версий: без неё они показывали бы латиницу.
 */
export const ATTACK_TACTIC_LABELS: Record<string, string> = {
  reconnaissance: 'разведка',
  'resource-development': 'разработка ресурсов',
  'initial-access': 'первичный доступ',
  execution: 'выполнение',
  persistence: 'закрепление',
  'privilege-escalation': 'повышение привилегий',
  'defense-impairment': 'подавление защиты',
  stealth: 'скрытность',
  'defense-evasion': 'обход защиты',
  'credential-access': 'доступ к учётным данным',
  discovery: 'разведка в системе',
  'lateral-movement': 'горизонтальное перемещение',
  collection: 'сбор данных',
  'command-and-control': 'управление и контроль',
  exfiltration: 'эксфильтрация',
  impact: 'воздействие',
}

export function tacticLabel(tactic: string): string {
  return ATTACK_TACTIC_LABELS[tactic] ?? tactic
}

/**
 * Подпись источника применяемости.
 *
 * Чужая аналитика не должна выглядеть безымянным фактом: человек обязан
 * видеть, чьё это мнение, когда оно загружено и что тактики к нему
 * не относятся — они пересчитаны по матрице MITRE.
 */
export function ruHint(source: RuSource): string {
  const when = source.imported_at ? new Date(source.imported_at).toLocaleDateString('ru') : ''
  const parts = [`Выгрузка ${source.source}`]
  if (when) parts.push(`загружена ${when}`)
  parts.push(`строк: ${source.row_count}`)
  return `${parts.join(', ')}. Тактики — из матрицы MITRE, копия из файла не хранится.`
}

/** Применяемость словами: цвет и маркер никогда не единственный носитель смысла. */
export function ruWords(usage: RuUsage): string {
  const parts = [`группировок здесь: ${usage.actors}`]
  if (usage.malware > 0) parts.push(`ВПО: ${usage.malware}`)
  if (usage.tools > 0) parts.push(`инструментов: ${usage.tools}`)
  parts.push(`процедур: ${usage.procedures}`)
  if (usage.commands > 0) parts.push(`с командой: ${usage.commands}`)
  if (usage.actor_names.length > 0) parts.push(usage.actor_names.join(', '))
  return parts.join(', ')
}
