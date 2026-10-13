/**
 * Генератор фикстур мока: единая база в памяти, из которой обработчики MSW
 * читают и в которую пишут вердикты. Объёмы совпадают с примером контракта:
 * 1093 находки, 187 правил, 488 расхождений, 16 клонов.
 */
import type {
  RuSource,
  RuUsage,
} from '@/modules/attack/api/types'
import type { LlmSettings } from '@/platform/settings/api/types'
import type {
  AffectedRule,
  AttackConfidence,
  AttackCoverage,
  AttackGroup,
  AttackSource,
  AttackStatus,
  CloneEntry,
  DivergenceItem,
  FindingKind,
  FindingListItem,
  FindingSeverity,
  FindingStatus,
  ObjectType,
  Polarity,
  RuleDetail,
  RuleAttackInfo,
  RuleListItem,
  Settings,
  TableRankingEntry,
  NameScheme,
} from '@/modules/siem/api/types'
import {
  AUTHORS,
  CATEGORIES,
  FIELDS,
  RULE_NAME_PARTS_BY_CATEGORY,
  TABLES,
  TECHNIQUE_CATALOG,
  type TableFixture,
} from './fixtures'
import { mulberry32, pick, shuffle, weightedPick } from './rng'

const rng = mulberry32(20260821)

function uuid(rngFn: () => number): string {
  const hex = () => Math.floor(rngFn() * 16).toString(16)
  const block = (n: number) => Array.from({ length: n }, hex).join('')
  return `${block(8)}-${block(4)}-${block(4)}-${block(4)}-${block(12)}`
}

// ---------------------------------------------------------------------------
// Правила
// ---------------------------------------------------------------------------

interface GeneratedRule extends RuleListItem {
  body: string
}

const GROUPS_PER_CATEGORY: Record<string, number> = { HC: 12, AC: 10, TA: 8, AN: 8, DT: 6 }

function buildGroupCatalog(): { category: string; group: string }[] {
  const catalog: { category: string; group: string }[] = []
  for (const category of CATEGORIES) {
    const n = GROUPS_PER_CATEGORY[category]
    for (let i = 0; i < n; i++) {
      catalog.push({ category, group: String((i + 1) * 2).padStart(3, '0') })
    }
  }
  return catalog
}

function buildRules(): GeneratedRule[] {
  const groupCatalog = buildGroupCatalog()
  const dtGroups = groupCatalog.filter((g) => g.category === 'DT')
  const nonDtGroups = groupCatalog.filter((g) => g.category !== 'DT')

  const authorPool: string[] = []
  for (const [author, count] of Object.entries(AUTHORS)) {
    for (let i = 0; i < count; i++) authorPool.push(author)
  }

  const ruleIdByGroup = new Map<string, number>()
  const rules: GeneratedRule[] = []

  authorPool.forEach((author, index) => {
    const groupPool = author === 'acme' ? dtGroups : nonDtGroups
    const { category, group } = pick(rng, groupPool)
    const groupKey = `${category}-${group}`
    const nextId = (ruleIdByGroup.get(groupKey) ?? 0) + 1
    ruleIdByGroup.set(groupKey, nextId)
    const ruleId = String(nextId).padStart(3, '0')
    const slugPool = RULE_NAME_PARTS_BY_CATEGORY[category]
    const slug = pick(rng, slugPool)
    const name = `${author}_${category}_${group}_${ruleId}_${slug}`

    rules.push({
      uuid: uuid(rng),
      name,
      author,
      category,
      group,
      rule_id: ruleId,
      origin: 'kb',
      parse_status: 'ok',
      msgid_count: 1 + Math.floor(rng() * 4),
      finding_count: 0,
      table_reads: 0,
      scoped: false,
      // Маркировка считается по находкам, а находки генерируются позже:
      // здесь заглушка, реальные значения подставляет ruleAttention.
      open_finding_count: 0,
      max_severity: null,
      // Поля инвентаря KB подставляет обработчик списка (kbFields в handlers.ts).
      installed: null,
      folder_path: null,
      deployment_sets: [],
      body: `event.filter(subject.account.name != null and action == "${slug}")`,
      // индекс сохраняем в имени, дублирующая информация ниже не нужна
    })
    void index
  })

  // 3 неразобранных правила
  shuffle(rng, rules.map((_, i) => i))
    .slice(0, 3)
    .forEach((i) => {
      rules[i].parse_status = 'unsupported'
    })

  // 40 правил без msgid
  shuffle(rng, rules.map((_, i) => i))
    .slice(0, 40)
    .forEach((i) => {
      rules[i].msgid_count = 0
    })

  // 60 правил, ограниченных областью действия табличным списком
  shuffle(rng, rules.map((_, i) => i))
    .slice(0, 60)
    .forEach((i) => {
      rules[i].scoped = true
      rules[i].table_reads = 1 + Math.floor(rng() * 3)
    })

  rules.forEach((r) => {
    if (!r.scoped) r.table_reads = Math.floor(rng() * 2)
  })

  return rules
}

export const RULES = buildRules()
const rulesByName = new Map(RULES.map((r) => [r.name, r]))

// ---------------------------------------------------------------------------
// Находки
// ---------------------------------------------------------------------------

interface GeneratedObject {
  uuid: string
  name: string
  object_type: ObjectType
}

function repeatKind(kind: FindingKind, count: number): FindingKind[] {
  return Array.from({ length: count }, () => kind)
}

function buildFindings(): FindingListItem[] {
  // 74 правила-корреляции несут находки, плюс объекты фильтров и обогащений
  const correlationCarriers = shuffle(rng, [...RULES]).slice(0, 74)
  const filterObjects: GeneratedObject[] = Array.from({ length: 10 }, (_, i) => ({
    uuid: uuid(rng),
    name: `DEMO_FLT_${String(i + 1).padStart(3, '0')}_Filter`,
    object_type: 'filter' as ObjectType,
  }))
  const enrichmentObjects: GeneratedObject[] = Array.from({ length: 5 }, (_, i) => ({
    uuid: uuid(rng),
    name: `DEMO_ENR_${String(i + 1).padStart(3, '0')}_Enrich`,
    object_type: 'enrichment' as ObjectType,
  }))

  // Парето-распределение: несколько объектов несут десятки находок, много — единицы.
  function paretoSlots(carriers: GeneratedObject[], total: number): GeneratedObject[] {
    const weights = carriers.map((c, i) => [c, 1 / (i + 1.6)] as const)
    return Array.from({ length: total }, () => weightedPick(rng, weights))
  }

  const correlationSlots = paretoSlots(
    correlationCarriers.map((r) => ({ uuid: r.uuid, name: r.name, object_type: 'correlation' as ObjectType })),
    1059,
  )
  const filterSlots = paretoSlots(filterObjects, 26)
  const enrichSlots = paretoSlots(enrichmentObjects, 8)

  // Классы находок: kind1 не встречается вне корреляций (расхождение — это
  // всегда «правило хардкодит вместо чтения списка»).
  const correlationKinds: FindingKind[] = shuffle(rng, [
    ...repeatKind('1', 488),
    ...repeatKind('2', 350),
    ...repeatKind('3', 31),
    ...repeatKind('4', 19),
    ...repeatKind('5', 171),
  ])
  const filterEnrichKinds: FindingKind[] = shuffle(rng, [
    ...repeatKind('2', 21),
    ...repeatKind('3', 2),
    ...repeatKind('4', 1),
    ...repeatKind('5', 10),
  ])
  const filterKinds = filterEnrichKinds.slice(0, 26)
  const enrichKinds = filterEnrichKinds.slice(26)

  const objects = [...correlationSlots, ...filterSlots, ...enrichSlots]
  const kinds = [...correlationKinds, ...filterKinds, ...enrichKinds]

  const polarities: Polarity[] = shuffle(rng, [
    ...Array.from({ length: 140 }, (): Polarity => 'negation'),
    ...Array.from({ length: 953 }, (): Polarity => 'assertion'),
  ])

  const fieldsByKind: Record<FindingKind, readonly string[]> = {
    '1': ['src.host', 'dst.host', 'object.name', 'subject.account.name', 'event_src.host'],
    '2': ['src.ip', 'dst.ip', 'object.fqdn'],
    '3': ['subject.account.name', 'subject.privileges', 'action'],
    '4': ['subject.sid'],
    '5': FIELDS,
  }

  const tableWeights = TABLES.map((t, i) => [t, 1 / (i + 1.3)] as const)

  const findings: FindingListItem[] = []
  for (let i = 0; i < 1093; i++) {
    const kind = kinds[i]
    const object = objects[i]
    const polarity = polarities[i]
    const inTable = kind === '1'
    const table: TableFixture | null = inTable ? weightedPick(rng, tableWeights) : null
    const secondTable = inTable && rng() < 0.25 ? weightedPick(rng, tableWeights) : null
    const tableName =
      table && secondTable && secondTable.name !== table.name ? `${table.name}, ${secondTable.name}` : table?.name ?? null

    findings.push({
      id: i + 1,
      key: `${object.uuid}|${kind}|mock${i + 1}`,
      kind,
      severity: kind === '1' || kind === '2' ? 'high' : kind === '5' ? 'low' : 'medium',
      object_type: object.object_type,
      object_name: object.name,
      object_uuid: object.uuid,
      field: pick(rng, fieldsByKind[kind]),
      polarity,
      in_table: inTable,
      // Форма значения задаётся классом: класс 2 — это и есть адрес или
      // имя узла, класс 1 бывает и тем и другим.
      shape: kind === '2' ? 'ip' : kind === '1' && i % 3 === 0 ? 'fqdn' : null,
      table_name: tableName,
      status: 'new',
      status_title: 'Новая',
      assignee: null,
      assignee_name: null,
      due_date: null,
      overdue: false,
      risk_until: null,
      first_seen_at: '2026-09-01T10:00:00Z',
      age_days: 31,
      gone: false,
      has_value: rng() < 0.92,
    })
  }

  // finding_count по правилам (для инвентаря)
  const counts = new Map<string, number>()
  for (const f of findings) {
    if (f.object_type !== 'correlation') continue
    counts.set(f.object_uuid, (counts.get(f.object_uuid) ?? 0) + 1)
  }
  for (const rule of RULES) {
    rule.finding_count = counts.get(rule.uuid) ?? 0
  }

  return findings
}

export const FINDINGS = buildFindings()
const findingsById = new Map(FINDINGS.map((f) => [f.id, f]))

// Изменяемое состояние статусов, живёт поверх сгенерированных находок.
export const VERDICTS = new Map<number, { status: FindingStatus; reason?: string }>()

export function findingStatus(id: number): FindingStatus {
  return VERDICTS.get(id)?.status ?? findingsById.get(id)?.status ?? 'new'
}

/** Учитывается ли статус — как настройка платформы `counted` по умолчанию. */
export function findingCounted(id: number): boolean {
  return !['risk_accepted', 'false_positive', 'resolved'].includes(findingStatus(id))
}

// ---------------------------------------------------------------------------
// Расхождения правило ↔ список
// ---------------------------------------------------------------------------

function buildDivergences(): DivergenceItem[] {
  const source = FINDINGS.filter((f) => f.kind === '1' && f.in_table && f.table_name)
  const blastByKey = new Map<string, number>()
  for (const f of source) {
    const key = `${f.field}::${f.table_name}`
    blastByKey.set(key, (blastByKey.get(key) ?? 0) + 1)
  }
  return source.map((f, i) => ({
    id: i + 1,
    field: f.field,
    table_name: f.table_name as string,
    hardcoded_in: f.object_name,
    blast_radius: blastByKey.get(`${f.field}::${f.table_name}`) ?? 1,
    has_value: f.has_value,
  }))
}

export const DIVERGENCES = buildDivergences()

// ---------------------------------------------------------------------------
// Табличные списки — ранжирование по риску
// ---------------------------------------------------------------------------

function buildTableRanking(): TableRankingEntry[] {
  const dependantsByTable = new Map<string, Set<string>>()
  for (const d of DIVERGENCES) {
    for (const name of d.table_name.split(', ')) {
      const set = dependantsByTable.get(name) ?? new Set<string>()
      set.add(d.hardcoded_in)
      dependantsByTable.set(name, set)
    }
  }
  return TABLES.map((t) => {
    const dependants = dependantsByTable.get(t.name)?.size ?? 0
    const dependantCount = t.name === 'DEMO_User_Authentications' ? 72 : dependants
    return {
      name: t.name,
      exists: t.state !== 'missing',
      value_count: t.valueCount,
      dependant_count: dependantCount,
      is_empty: t.state === 'empty' || (t.state === 'missing' && t.valueCount === 0),
      is_scoping: t.isScoping,
      risk: dependantCount,
    }
  }).sort((a, b) => b.risk - a.risk)
}

export const TABLE_RANKING = buildTableRanking()

// ---------------------------------------------------------------------------
// Клоны
// ---------------------------------------------------------------------------

function buildClones(): CloneEntry[] {
  const pairs = shuffle(rng, RULES)
    .slice(0, 32)
    .reduce<CloneEntry[]>((acc, rule, i, arr) => {
      if (i % 2 === 1) {
        acc.push({ rule_a: arr[i - 1].name, rule_b: rule.name, similarity: 0.85 + rng() * 0.14 })
      }
      return acc
    }, [])
  return pairs
}

export const CLONES = buildClones()

// ---------------------------------------------------------------------------
// Профиль инсталляции
// ---------------------------------------------------------------------------

export const NAME_SCHEME_SUGGESTION: NameScheme = {
  separator: '_',
  segments: ['author', 'category', 'group', 'rule_id'],
  total: 187,
  coverage: 187,
  group_count: 44,
  stats: [
    { position: 0, role: 'author', coverage: 187, distinct: 4, numeric_share: 0, examples: ['DEMO', 'acme', 'SOC', 'IOC'] },
    { position: 1, role: 'category', coverage: 187, distinct: 15, numeric_share: 0, examples: ['HC', 'AC', 'NAA', 'MNA'] },
    { position: 2, role: 'group', coverage: 187, distinct: 32, numeric_share: 0.9, examples: ['002', '020', '001', '003'] },
    { position: 3, role: 'rule_id', coverage: 187, distinct: 64, numeric_share: 0.9, examples: ['001', '002', '004', '003'] },
    { position: 4, role: null, coverage: 182, distinct: 106, numeric_share: 0, examples: ['Possible', 'ELK', 'Suspicious', 'New'] },
  ],
  depth: 4,
  score: 0.85,
}

export const BUILTIN_ACCOUNTS = ['SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE', 'Гость', 'Администратор']

/** Дополнения к встроенным ролям — списки имён полей, как их отдаёт API. */
export const FIELD_ROLES = {
  environmental: ['datafield8', 'event_src.hostname'],
  technical: ['logon_service'],
}


// ---------------------------------------------------------------------------
// Детализация правила
// ---------------------------------------------------------------------------

export function ruleDetail(uuid: string): RuleDetail | undefined {
  const rule = RULES.find((r) => r.uuid === uuid)
  if (!rule) return undefined
  const findings = FINDINGS.filter((f) => f.object_uuid === uuid)
  const deps = shuffle(rng, RULES.filter((r) => r.uuid !== uuid)).slice(0, rule.table_reads)
  return {
    ...rule,
    title_ru: rule.name,
    title_en: null,
    description_ru: `На узле {event_src.host} обнаружена активность «${rule.name}»`,
    description_en: null,
    body_hash: `${rule.uuid}-hash`,
    // В списке table_reads — счётчик, в подробностях — сами имена.
    table_reads: Array.from({ length: rule.table_reads }, (_, i) => `Table_${i + 1}`),
    table_writes: [],
    // Форма повторяет ответ сервера: собственные и унаследованные msgid
    // разделены, зависимости — родители и потомки по именам.
    msgids: {
      own: Array.from({ length: rule.msgid_count }, (_, i) => `${rule.name}_${i + 1}`),
      inherited: rule.msgid_count === 0 ? [`${rule.name}_base`] : [],
    },
    dependencies: {
      parents: deps.slice(0, 1).map((d) => d.name),
      children: deps.slice(1, 3).map((d) => d.name),
    },
    findings: findings.map((f) => ({ id: f.id, kind: f.kind, field: f.field, status: findingStatus(f.id), counted: findingCounted(f.id) })),
    attack: ruleAttack(rule.name),
    body: rule.body,
    // Значения в списке находок не приходят и в моке тоже: отрезки
    // берутся из самого тела — по закавыченным литералам, как их
    // находит и сервер.
    body_spans: [...rule.body.matchAll(/"([^"]{2,})"/g)]
      .slice(0, findings.length)
      .map((m, i) => ({
        start: m.index! + 1,
        end: m.index! + 1 + m[1].length,
        kind: Number(findings[i]?.kind ?? 5),
        status: findingStatus(findings[i]?.id ?? 0),
        counted: findingCounted(findings[i]?.id ?? 0),
      })),
  }
}

export function affectedRulesFor(objectName: string): AffectedRule[] {
  const rule = rulesByName.get(objectName)
  const pool = rule ? RULES.filter((r) => r.category === rule.category && r.uuid !== rule.uuid) : RULES
  return shuffle(rng, pool)
    .slice(0, 3 + Math.floor(rng() * 5))
    .map((r) => ({ uuid: r.uuid, name: r.name }))
}

// ---------------------------------------------------------------------------
// Разметка ATT&CK
// ---------------------------------------------------------------------------

/**
 * Разметка групп правил. Состояние выбирается детерминированно, но так,
 * чтобы на экране встречались все три: подтверждённое человеком,
 * предложенное моделью и неразмеченное. Иначе интерфейс проверяется
 * только в одном состоянии из трёх.
 */
function buildAttackGroups(): AttackGroup[] {
  const byGroup = new Map<string, number>()
  for (const rule of RULES) {
    const key = [rule.author, rule.category, rule.group].filter(Boolean).join('/')
    if (key) byGroup.set(key, (byGroup.get(key) ?? 0) + 1)
  }

  return Array.from(byGroup.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([group, rule_count], index) => {
      const status: AttackStatus = index % 7 === 0 ? 'unmapped' : index % 5 === 0 ? 'confirmed' : 'suggested'
      // Разметка ведётся по правилам; счётчики группы показывают, сколько
      // из них решено и сколько лишь унаследовало решение о группе.
      const unmapped_rules = status === 'unmapped' ? rule_count : index % 3
      const confirmed_rules = status === 'confirmed' ? rule_count - (index % 2) : 0
      const inherited_rules = status === 'unmapped' ? 0 : Math.max(0, rule_count - (index % 2))
      // Модель в продукте предлагает только родительские техники —
      // подтехники в конвейере разметки не участвуют вовсе.
      const parents = TECHNIQUE_CATALOG.filter((t) => !t.parent_id)
      const picked = shuffle(rng, parents).slice(0, 1 + (index % 3))
      const candidates = shuffle(rng, parents)
        .slice(0, 15)
        .map((t) => t.technique_id)
      return {
        group,
        rule_count,
        status,
        unmapped_rules,
        confirmed_rules,
        inherited_rules,
        techniques:
          status === 'unmapped'
            ? []
            : picked.map((t, i) => ({
                technique_id: t.technique_id,
                name_ru: t.name_ru,
                name: t.technique_id,
                tactics: t.tactics,
                confidence: (i === 0 ? 'высокая' : 'низкая') as AttackConfidence,
                evidence: 'в описаниях правил группы прямо упоминается соответствующий механизм',
                source: (status === 'confirmed' ? 'manual' : 'llm') as AttackSource,
              })),
        candidates: status === 'unmapped' ? [] : candidates,
        model: status === 'unmapped' ? null : 'qwen3:8b-q4_K_M',
        attack_version: status === 'unmapped' ? null : '19.2',
        reviewed_by: status === 'confirmed' ? 'analyst' : null,
        reviewed_at: status === 'confirmed' ? '2026-08-20T10:15:00Z' : null,
      }
    })
}

export const ATTACK_GROUPS = buildAttackGroups()

export function attackGroupOf(ruleName: string): AttackGroup | undefined {
  const rule = rulesByName.get(ruleName)
  if (!rule) return undefined
  const key = [rule.author, rule.category, rule.group].filter(Boolean).join('/')
  return ATTACK_GROUPS.find((g) => g.group === key)
}

/** Разметка правила: правило наследует её от своей группы. */
export function ruleAttack(ruleName: string): RuleAttackInfo {
  const group = attackGroupOf(ruleName)
  if (!group) return { status: 'unmapped', group: null, techniques: [] }
  return { status: group.status, group: group.group, techniques: group.techniques }
}

/** Открытые находки правила и наибольшая их тяжесть — маркировка инвентаря. */
export function ruleAttention(uuid: string): { open: number; worst: FindingSeverity | null } {
  const order: FindingSeverity[] = ['high', 'medium', 'low']
  let open = 0
  let worst: FindingSeverity | null = null
  for (const f of FINDINGS) {
    if (f.object_uuid !== uuid || !findingCounted(f.id)) continue
    open += 1
    if (worst === null || order.indexOf(f.severity) < order.indexOf(worst)) worst = f.severity
  }
  return { open, worst }
}

export function attackCoverage(): AttackCoverage {
  const covered = new Set<string>()
  const byTactic: Record<string, number> = {}
  for (const group of ATTACK_GROUPS) {
    for (const t of group.techniques) covered.add(t.technique_id)
  }
  for (const id of covered) {
    const t = TECHNIQUE_CATALOG.find((x) => x.technique_id === id)
    for (const tactic of t?.tactics ?? []) byTactic[tactic] = (byTactic[tactic] ?? 0) + 1
  }
  return {
    attack_version: '19.2',
    rule_count: RULES.length,
    group_count: ATTACK_GROUPS.length,
    inherited: ATTACK_GROUPS.reduce((n, g) => n + g.inherited_rules, 0),
    confirmed: ATTACK_GROUPS.filter((g) => g.status === 'confirmed').length,
    suggested: ATTACK_GROUPS.filter((g) => g.status === 'suggested').length,
    unmapped: ATTACK_GROUPS.filter((g) => g.status === 'unmapped').length,
    techniques_covered: covered.size,
    by_tactic: byTactic,
    model: 'qwen3:8b-q4_K_M',
    llm_configured: LLM_SETTINGS.base_url.trim().length > 0,
    outdated_groups: 0,
    missing_techniques: [],
  }
}

/** Порядок тактик — как в матрице MITRE: это последовательность шагов атаки. */
export const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'stealth',
  'defense-impairment',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]

/** Применяемость на макетных данных.
 *
 *  Замечена не каждая техника: смысл слоя в расхождении с мировыми
 *  данными, и слой, покрывающий всё, показать этого не может. */
export function ruUsage(techniqueId: string): RuUsage | null {
  const n = Number(techniqueId.replace(/\D/g, ''))
  if (n % 3 !== 0) return null
  const names = ['Fair Werewolf', 'Dune Werewolf', 'Chanting Werewolf', 'Vortex Werewolf']
  const actors = 1 + (n % 4)
  return {
    actors,
    malware: n % 5,
    tools: n % 3,
    procedures: 1 + (n % 9),
    commands: n % 4,
    actor_names: names.slice(0, actors),
  }
}

export const RU_SOURCE: RuSource = {
  source: 'export_ttps__all_enterprise.xlsx',
  imported_at: '2026-09-03T12:00:00Z',
  imported_by: 'tester',
  attack_version: '19.2',
  row_count: 13525,
}

/** Настройки живут в моке как изменяемое состояние: экран их сохраняет. */
export const SETTINGS: Settings = {
  attack: { top_k: 15, attack_version: '19.2' },
}

/** Настройки модели живут в общих настройках, но состояние «настроена»
 *  читает и покрытие SIEM. Держим их здесь, рядом с остальной базой мока:
 *  обработчики платформы импортируют её, а не наоборот. */
export const LLM_SETTINGS: LlmSettings = {
  base_url: 'http://ollama:11434',
  model: 'qwen3:8b-q4_K_M',
  embed_model: 'bge-m3',
  think: false,
  timeout: 180,
  enabled: true,
}
