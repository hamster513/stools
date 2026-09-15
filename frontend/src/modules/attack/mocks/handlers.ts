/**
 * Обработчики MSW модуля ATT&CK: матрица со слоями, карточка техники,
 * цепочки, бандл и применяемость здесь.
 *
 * Слои модулей на макете синтетические и выведены из идентификатора
 * техники: важно не правдоподобие чисел, а то, что видны все состояния —
 * покрытие без экспозиции, экспозиция без покрытия (разрыв) и пусто.
 *
 * Фикстуры техник и групп разметки берутся у мока SIEM: заводить вторую
 * базу тех же техник значило бы разойтись с ней на первой же правке.
 */
import { http, HttpResponse } from 'msw'
import type {
  AttackJob,
  AttackMatrix,
  AttackMatrixCell,
  LayerCell,
  LayerMeta,
} from '@/modules/attack/api/types'
import { noSession } from '@/modules/siem/mocks/handlers'
import { ATTACK_GROUPS, RU_SOURCE, ruUsage, TACTIC_ORDER } from '@/modules/siem/mocks/data'
import { TECHNIQUE_CATALOG } from '@/modules/siem/mocks/fixtures'

//: Слой применяемости в макете загружается и снимается: без этого
//: не посмотреть ни пустое состояние, ни заполненное.
let ruLoaded: string | null = null

const LAYERS: LayerMeta[] = [
  {
    id: 'siem',
    title: 'Покрытие SIEM',
    kind: 'coverage',
    unit: ['группа правил', 'группы правил', 'групп правил'],
    available: true,
    note: null,
  },
  {
    id: 'vm',
    title: 'Уязвимости',
    kind: 'exposure',
    unit: ['хост', 'хоста', 'хостов'],
    available: true,
    note: 'риск ≥ 40',
  },
  {
    id: 'ad',
    title: 'Active Directory',
    kind: 'exposure',
    unit: ['находка', 'находки', 'находок'],
    available: true,
    note: null,
  },
]

const num = (techniqueId: string) => Number(techniqueId.replace(/\D/g, ''))

/** Место техники в каталоге: по нему разложены состояния слоёв. */
const slot = (techniqueId: string) =>
  Math.max(
    0,
    TECHNIQUE_CATALOG.findIndex((t) => t.technique_id === techniqueId.split('.')[0]),
  )

/** Кто закрывает технику: группы разметки мока, свёрнутые на родителя. */
function coveringGroups(techniqueId: string) {
  return ATTACK_GROUPS.filter((g) =>
    g.techniques.some((t) => t.technique_id.split('.')[0] === techniqueId.split('.')[0]),
  ).filter((g) => g.status !== 'unmapped')
}

function siemCell(techniqueId: string, withItems: boolean): LayerCell | null {
  // Покрытие в моке прорежено намеренно: фикстурные группы называют почти
  // весь маленький каталог, и без прореживания в матрице не увидеть ни
  // одного разрыва — того самого состояния, ради которого слои и сведены.
  if (slot(techniqueId) % 3 === 1) return null
  const groups = coveringGroups(techniqueId)
  if (groups.length === 0) return null
  return {
    count: groups.length,
    status: groups.some((g) => g.status === 'confirmed') ? 'confirmed' : 'suggested',
    ...(withItems
      ? {
          items: groups.map((g) => ({
            title: g.group,
            subtitle: `правил: ${g.rule_count}`,
            href: `/siem/snapshots/2/rules?group=${encodeURIComponent(g.group)}`,
          })),
        }
      : {}),
  }
}

function vmCell(techniqueId: string, withItems: boolean): LayerCell | null {
  const n = num(techniqueId)
  // Часть уязвимых техник закрыта правилами, часть — нет: видны оба
  // состояния, и экспозиция без покрытия, и экспозиция вместе с ним.
  if (slot(techniqueId) % 4 !== 0 && slot(techniqueId) % 3 !== 1) return null
  const count = 1 + (n % 13)
  return {
    count,
    status: null,
    ...(withItems
      ? {
          items: Array.from({ length: Math.min(count, 5) }, (_, i) => ({
            title: `CVE-2024-${1000 + ((n + i) % 8999)}`,
            subtitle: `srv-${(n + i) % 200}, риск ${40 + ((n + i) % 60)}`,
            href: `/vm/vulns?host=${(n + i) % 200}`,
          })),
        }
      : {}),
  }
}

function adCell(techniqueId: string, withItems: boolean): LayerCell | null {
  const n = num(techniqueId)
  if (slot(techniqueId) % 5 !== 0) return null
  const count = 1 + (n % 4)
  return {
    count,
    status: null,
    ...(withItems
      ? {
          items: Array.from({ length: count }, (_, i) => ({
            title: `AD-${(n + i) % 20}`,
            subtitle: 'находка проверки домена',
            href: `/ad/domains/1/findings?check=AD-${(n + i) % 20}`,
          })),
        }
      : {}),
  }
}

function cellsOf(techniqueId: string, withItems: boolean): Record<string, LayerCell | null> {
  return {
    siem: siemCell(techniqueId, withItems),
    vm: vmCell(techniqueId, withItems),
    ad: adCell(techniqueId, withItems),
  }
}

const isCovered = (layers: Record<string, LayerCell | null>) => layers.siem !== null
const isExposed = (layers: Record<string, LayerCell | null>) =>
  layers.vm !== null || layers.ad !== null

function matrix(): AttackMatrix {
  return {
    attack_version: '19.2',
    sightings_window: '2021-08..2023-09',
    ru_source: ruLoaded ? { ...RU_SOURCE, source: ruLoaded } : null,
    layers: LAYERS,
    tactics: TACTIC_ORDER.map((shortname) => {
      // Только родительские: матрица в продукте показывает их, а подтехники
      // раскрываются в карточке. Иначе колонки вырастают в экран высотой.
      const techniques: AttackMatrixCell[] = TECHNIQUE_CATALOG.filter(
        (t) => !t.parent_id && t.tactics.includes(shortname),
      ).map((t) => {
        const layers = cellsOf(t.technique_id, false)
        const covered = isCovered(layers)
        return {
          technique_id: t.technique_id,
          name: t.technique_id,
          name_ru: t.name_ru,
          subtechnique_count: TECHNIQUE_CATALOG.filter((s) => s.parent_id === t.technique_id).length,
          // Уровень выводится из идентификатора: на макетных данных важно
          // не правдоподобие чисел, а то, что представлены все четыре
          // уровня и ноль — иначе раскраску не на чем посмотреть.
          level: num(t.technique_id) % 5,
          actor_groups: num(t.technique_id) % 40,
          campaigns: num(t.technique_id) % 7,
          sightings: (num(t.technique_id) % 13) * 111,
          ru: ruLoaded ? ruUsage(t.technique_id) : null,
          layers,
          covered,
          gap: isExposed(layers) && !covered,
        }
      })
      return {
        shortname,
        name: shortname,
        techniques,
        covered: techniques.filter((t) => t.covered).length,
        gaps: techniques.filter((t) => t.gap).length,
        blind: techniques.length > 0 && techniques.every((t) => !t.covered),
        observable: shortname !== 'reconnaissance' && shortname !== 'resource-development',
      }
    }),
  }
}

/** Техники с экспозицией — то же правило, что и в ячейках матрицы. */
function exposedIds(): string[] {
  return TECHNIQUE_CATALOG.filter((t) => isExposed(cellsOf(t.technique_id, false))).map(
    (t) => t.technique_id,
  )
}

/**
 * Задания модуля в макете: сейчас единственное — скачивание бандла ATT&CK.
 * Запускают его общие настройки, а опрашивают по пути модуля: задания
 * матрицы принадлежат модулю, где бы ни стояла кнопка.
 */
interface MockAttackJob {
  id: number
  kind: string
  startedAt: number
}

const ATTACK_JOBS = new Map<number, MockAttackJob>()
let attackJobSeq = 1

/** Сколько «идёт» задание и сколько «весит» бандл: числа взяты, чтобы
 *  прогресс успели увидеть глазами. */
const JOB_DURATION_MS = 4000
const BUNDLE_MB = 48

function jobStatus(job: MockAttackJob): AttackJob {
  const share = Math.min(1, (Date.now() - job.startedAt) / JOB_DURATION_MS)
  const done = share >= 1
  return {
    id: job.id,
    kind: job.kind,
    stage: done ? 'done' : 'download',
    status: done ? 'done' : 'running',
    progress: Math.round(share * 100),
    processed: Math.round(BUNDLE_MB * share),
    total: BUNDLE_MB,
    message: `скачано ${Math.round(BUNDLE_MB * share)} МБ`,
    error: null,
    cancel_requested: false,
    started_at: new Date(job.startedAt).toISOString(),
    finished_at: done ? new Date(job.startedAt + JOB_DURATION_MS).toISOString() : null,
    started_by: 'admin',
  }
}

/** Запустить скачивание бандла. Возвращает и момент завершения: мок
 *  ожидающего бандла должен молчать, пока задание идёт. */
export function startMockBundleDownload(): { id: number; finishesAt: number } {
  const id = attackJobSeq++
  const startedAt = Date.now()
  ATTACK_JOBS.set(id, { id, kind: 'download', startedAt })
  return { id, finishesAt: startedAt + JOB_DURATION_MS }
}

// Каждый обработчик закрыт сессией, как и в моке SIEM: до входа мок
// обязан отвечать 401, иначе экраны модуля живут без аутентификации.
export const attackHandlers = [
  http.get('/api/attack/matrix', () => noSession() ?? HttpResponse.json(matrix())),

  http.get('/api/attack/technique/:techniqueId', ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const id = String(params.techniqueId)
    const found = TECHNIQUE_CATALOG.find((t) => t.technique_id === id)
    if (!found) return HttpResponse.json({ detail: 'техника не найдена' }, { status: 404 })
    const parent = found.parent_id ?? id
    const covered = new Set(
      coveringGroups(parent).flatMap((g) => g.techniques.map((t) => t.technique_id)),
    )
    const subtechniques = TECHNIQUE_CATALOG.filter((t) => t.parent_id === parent)
      .map((t) => ({
        technique_id: t.technique_id,
        name: t.technique_id,
        name_ru: t.name_ru,
        covered: covered.has(t.technique_id),
        level: t.level ?? 0,
        actor_groups: t.actor_groups ?? 0,
        sightings: t.sightings ?? 0,
        ru: ruLoaded ? ruUsage(t.technique_id) : null,
      }))
      // Замеченное здесь идёт первым — тем же ключом, что и в продукте.
      .sort(
        (a, b) =>
          (b.ru?.actors ?? 0) - (a.ru?.actors ?? 0) ||
          b.level - a.level ||
          b.actor_groups - a.actor_groups,
      )
    const layers = cellsOf(parent, true)
    return HttpResponse.json({
      technique_id: id,
      name: id,
      name_ru: found.name_ru,
      description_ru: null,
      description: '',
      tactics: found.tactics,
      is_subtechnique: Boolean(found.parent_id),
      parent_id: found.parent_id ?? null,
      subtechniques,
      layers,
      covered: isCovered(layers),
      gap: isExposed(layers) && !isCovered(layers),
      ru: ruLoaded ? ruUsage(id) : null,
      ru_procedures: ruLoaded
        ? [
            {
              technique_id: id,
              procedure: 'Запускают через планировщик под именем службы обновления',
              command_line:
                "schtasks /create /tn 'GoogleUpdate' /tr C:\\ProgramData\\svc.exe /sc onlogon",
              actors: ['Fair Werewolf'],
              malware: [],
              tools: [],
            },
            {
              technique_id: id,
              procedure: 'Тот же приём без сохранения задачи на диск',
              command_line: '',
              actors: ['Dune Werewolf'],
              malware: ['Nova'],
              tools: [],
            },
          ]
        : [],
    })
  }),

  http.get('/api/attack/chains', () => {
    const denied = noSession()
    if (denied) return denied
    const tactics = [
      'resource-development',
      'initial-access',
      'execution',
      'persistence',
      'credential-access',
      'discovery',
      'lateral-movement',
      'impact',
    ]
    const items = [
      { id: 'C0027', name: 'APT28 Nearest Neighbor Campaign', last_seen: '2024-11-01', blind: [1, 5] },
      { id: 'C0040', name: 'Quad7 Activity', last_seen: '2025-08-01', blind: [2, 6] },
      { id: 'C0011', name: 'Operation Wocao', last_seen: '2022-07-01', blind: [4] },
    ].map(({ id, name, last_seen, blind }) => {
      const steps = tactics.map((tactic, index) => {
        const observable = tactic !== 'resource-development'
        const isBlind = observable && blind.includes(index)
        const total = 1 + (index % 3)
        return {
          tactic,
          blind: isBlind,
          observable,
          total,
          covered: isBlind ? 0 : total,
          uncovered: isBlind
            ? [
                {
                  technique_id: `T16${60 + index}`,
                  name: 'Непокрытая техника',
                  ru: ruLoaded ? ruUsage(`T16${60 + index}`) : null,
                },
              ]
            : [],
        }
      })
      return {
        id,
        name,
        first_seen: '2021-01-01',
        last_seen,
        technique_count: 22,
        uncovered_count: blind.length * 3,
        blind_steps: blind.length,
        steps,
      }
    })
    return HttpResponse.json({
      total: 56,
      items,
      attack_version: '19.2',
      latest_seen: '2025-12-01',
      ru_source: ruLoaded ? { ...RU_SOURCE, source: ruLoaded } : null,
      // Шаги цепочек на макете придуманы, и часть их техник помечена
      // экспозицией: иначе значок в списке непокрытого негде увидеть.
      exposed: [...exposedIds(), 'T1664', 'T1666'],
    })
  }),

  http.get('/api/attack/techniques', ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const q = new URL(request.url).searchParams.get('q')?.toLowerCase() ?? ''
    const items = TECHNIQUE_CATALOG.filter(
      (t) => !q || t.technique_id.toLowerCase().includes(q) || t.name_ru.toLowerCase().includes(q),
    ).map((t) => ({
      technique_id: t.technique_id,
      name: t.technique_id,
      name_ru: t.name_ru,
      description_ru: null,
      tactics: t.tactics,
      is_subtechnique: Boolean(t.parent_id),
      parent_id: t.parent_id ?? null,
    }))
    return HttpResponse.json({ total: items.length, items })
  }),

  http.get('/api/attack/jobs', () =>
    noSession() ?? HttpResponse.json([...ATTACK_JOBS.values()].map(jobStatus).reverse()),
  ),

  http.get('/api/attack/jobs/:id', ({ params }) => {
    const denied = noSession()
    if (denied) return denied
    const job = ATTACK_JOBS.get(Number(params.id))
    if (!job) return HttpResponse.json({ detail: 'Задание не найдено' }, { status: 404 })
    return HttpResponse.json(jobStatus(job))
  }),

  // Слой применяемости живёт в памяти мока: без него не посмотреть ни
  // пустое состояние экрана, ни заполненное.
  http.post('/api/attack/ru-ttp', async ({ request }) => {
    const denied = noSession()
    if (denied) return denied
    const form = await request.formData()
    const file = form.get('file')
    ruLoaded = file instanceof File ? file.name : 'выгрузка.xlsx'
    return HttpResponse.json({
      rows: 13525,
      techniques: 503,
      without_technique: 0,
      moved: 0,
      unknown: [],
      columns: { technique: 'ID', name: 'Техника', procedure: 'Процедура' },
      attack_version: '19.2',
    })
  }),

  http.get('/api/attack/ru-ttp', () => {
    const denied = noSession()
    if (denied) return denied
    if (!ruLoaded) {
      return HttpResponse.json({
        source: null,
        attack_version: '19.2',
        counts: {},
        ru_only: [],
        world_only: [],
        unknown: [],
      })
    }
    // В списке «замечено здесь» применяемость есть у каждой строки по
    // определению, а в списке «мир видит» её нет ни у одной: иначе мок
    // противоречил бы тому состоянию, которое сам же и показывает.
    const seen = (id: string, name: string) => ({
      technique_id: id,
      name,
      ru: {
        actors: 1 + (num(id) % 11),
        malware: num(id) % 5,
        tools: num(id) % 3,
        procedures: 1 + (num(id) % 9),
        commands: num(id) % 4,
        actor_names: ['Fair Werewolf', 'Dune Werewolf'],
      },
      world_groups: 0,
    })
    const unseen = (id: string, name: string) => ({
      technique_id: id,
      name,
      ru: null,
      world_groups: 1 + (num(id) % 40),
    })
    return HttpResponse.json({
      source: { ...RU_SOURCE, source: ruLoaded },
      attack_version: '19.2',
      counts: { both: 470, ru_only: 33, world_only: 118, none: 76 },
      ru_only: [
        seen('T1496', 'Захват вычислительных ресурсов'),
        seen('T1561', 'Затирание диска'),
        seen('T1668', 'Исключительный контроль'),
      ],
      world_only: [
        unseen('T1207', 'Поддельный контроллер домена'),
        unseen('T1574', 'Подмена пути поиска'),
      ],
      unknown: [],
    })
  }),

  http.delete('/api/attack/ru-ttp', () => {
    const denied = noSession()
    if (denied) return denied
    ruLoaded = null
    return new HttpResponse(null, { status: 204 })
  }),
]
