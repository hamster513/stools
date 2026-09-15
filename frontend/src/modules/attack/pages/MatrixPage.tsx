import { useState } from 'react'
import { Swords } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAttackMatrix } from '@/modules/attack/api/queries'
import {
  ruHint,
  ruWords,
  tacticLabel,
  type AttackMatrixCell,
  type LayerMeta,
} from '@/modules/attack/api/types'
import { plural } from '@/modules/attack/lib/plural'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { tint } from '@/lib/tint'
import { TechniqueDrawer } from '../components/TechniqueDrawer'

/**
 * Матрица ATT&CK в привычном виде: тактики — колонки, техники — ячейки.
 *
 * Рисуется своя, а не встраивается ATT&CK Navigator: тот по умолчанию
 * тянет бандл из сети, а работа при отключённой сети — критерий приёмки.
 *
 * Матрица одна на все модули. SIEM отдаёт покрытие правилами, VM и AD —
 * экспозицию: чем технику можно выполнить в этой инфраструктуре. Ценность
 * не в каждом слое по отдельности, а в их разнице — техника, которую есть
 * чем выполнить и нечем заметить.
 */
const CELL_STYLE = {
  confirmed: 'border-attack-confirmed/60 bg-attack-confirmed/15 text-text',
  suggested: 'border-attack-suggested/60 bg-attack-suggested/15 text-text',
  unmapped: 'border-grid bg-surface text-text-secondary',
} as const

/** Цвет счётчика слоя в ячейке. Незнакомый слой берёт нейтральный тон:
 *  новый модуль не должен ждать правки этого файла, чтобы показаться. */
const LAYER_TONE: Record<string, string> = { vm: 'text-risk-high', ad: 'text-kind-3' }

/**
 * Прозрачность заливки по уровню распространённости.
 *
 * Уровни считаются по квантилям, а не по равным интервалам: у телеметрии
 * максимум под двести тысяч наблюдений при медиане в шесть десятков,
 * и равные интервалы отправили бы почти все техники в самый бледный тон.
 */
const LEVEL_FILL = [0, 10, 20, 35, 55]

const fill = (level: number) => tint('var(--color-actor)', LEVEL_FILL[level])
const LEVEL_WORD = ['', 'редко', 'заметно', 'часто', 'очень часто']

//: Кнопка-переключатель: одна форма для слоёв, наложения и его фильтров,
//: чтобы было видно, что это один ряд решений, а не разные режимы.
const TOGGLE =
  'inline-flex items-center gap-1.5 rounded border px-2 py-1 ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Почему фильтры о правилах недоступны: слой покрытия выключен, и ответа
 *  «закрыто / не закрыто» у экрана сейчас нет — не «правил нет». */
const COVERAGE_OFF = 'Слой покрытия выключен: закрытость техник сейчас не показывается'

export function MatrixPage() {
  const matrix = useAttackMatrix()
  //: Слои: пусто — значит «как пришло», доступные включены.
  const [enabled, setEnabled] = useState<Record<string, boolean>>({})
  const [onlyCovered, setOnlyCovered] = useState(false)
  const [onlyUncovered, setOnlyUncovered] = useState(false)
  const [onlyExposed, setOnlyExposed] = useState(false)
  const [onlyGaps, setOnlyGaps] = useState(false)
  const [onlyRu, setOnlyRu] = useState(false)
  const [onlyWw, setOnlyWw] = useState(false)
  const [overlay, setOverlay] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)

  if (matrix.isLoading) return <FullPageSpinner />
  if (matrix.isError || !matrix.data) {
    const message =
      matrix.error instanceof ApiRequestError ? matrix.error.message : 'Не удалось загрузить матрицу'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => matrix.refetch()} />
      </div>
    )
  }

  const data = matrix.data
  const layers = data.layers
  const isOn = (id: string) => enabled[id] ?? layers.find((l) => l.id === id)?.available ?? false
  const exposure = layers.filter((l) => l.kind === 'exposure')
  const coverage = layers.filter((l) => l.kind === 'coverage')
  const coverageOn = coverage.some((l) => isOn(l.id))
  const shownExposure = exposure.filter((l) => isOn(l.id))

  const cellCovered = (c: AttackMatrixCell) => coverageOn && c.covered
  const cellExposed = (c: AttackMatrixCell) => shownExposure.some((l) => c.layers[l.id])
  //: Без слоя покрытия разрыва не существует: «есть чем выполнить, нечем
  //: заметить» — утверждение о правилах, а мы их сейчас не спрашивали.
  const cellGap = (c: AttackMatrixCell) => coverageOn && cellExposed(c) && !c.covered
  //: Статус берётся у первого включённого слоя покрытия, который эту
  //: технику назвал: цвет ячейки обязан отвечать за то, что показано.
  const cellStatus = (c: AttackMatrixCell) =>
    coverage.filter((l) => isOn(l.id)).map((l) => c.layers[l.id]?.status).find(Boolean) ??
    'confirmed'
  //: Фильтры о правилах действуют только при включённом покрытии: иначе
  //: выключение слоя втихую опустошало бы матрицу отмеченной галочкой.
  const filterCovered = coverageOn && onlyCovered
  const filterUncovered = coverageOn && onlyUncovered
  const filterGaps = coverageOn && onlyGaps

  // Техника стоит в нескольких тактиках, и складывать колонки нельзя:
  // получилось бы больше техник, чем их есть. Считаем по идентификатору.
  const unique = [
    ...new Map(data.tactics.flatMap((t) => t.techniques).map((c) => [c.technique_id, c])).values(),
  ]
  const totalCovered = unique.filter(cellCovered).length
  const totalExposed = unique.filter(cellExposed).length
  const totalGaps = unique.filter(cellGap).length
  const score = (seen: (c: AttackMatrixCell) => boolean) => {
    const all = unique.filter(seen)
    return { seen: all.length, covered: all.filter(cellCovered).length }
  }
  const ruScore = score((c) => c.ru !== null)
  const wwScore = score((c) => c.actor_groups > 0 || c.campaigns > 0)

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 overflow-y-auto p-6">
      <div>
        <h1 className="text-base font-semibold text-text">Матрица ATT&CK</h1>
        <p className="max-w-3xl text-xs text-text-secondary">
          Одна матрица на все модули: покрытие правилами SIEM и экспозиция по данным VM и AD.
          Матрица {data.attack_version}, все техники, а не только закрытые: смысл её в пробелах.
        </p>
      </div>

      {/* Слои включаются и выключаются здесь: вопрос «что закрыто» и
          вопрос «чем это можно выполнить» задают разные люди, и матрица
          должна отвечать на каждый по отдельности. */}
      <div className="flex flex-wrap items-center gap-2 text-xs text-text-secondary">
        <span className="font-semibold text-text">Слои:</span>
        {layers.map((layer) => {
          const on = isOn(layer.id)
          return (
            <button
              key={layer.id}
              type="button"
              onClick={() => setEnabled((prev) => ({ ...prev, [layer.id]: !on }))}
              aria-pressed={on}
              disabled={!layer.available}
              title={
                layer.available
                  ? `${layer.title} — ${layer.kind === 'coverage' ? 'покрытие' : 'экспозиция'}${layer.note ? `, ${layer.note}` : ''}`
                  : (layer.note ?? 'данных нет')
              }
              className={cn(
                TOGGLE,
                'disabled:cursor-not-allowed disabled:opacity-50',
                on ? 'border-primary/70 bg-primary/10 text-text' : 'border-grid bg-surface hover:border-primary/50',
              )}
            >
              {layer.title}
            </button>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center gap-3 text-xs text-text-secondary">
        {/* Без включённого слоя покрытия «закрыто X» и «разрывов G» были бы
            утверждениями о базе правил, которую сейчас никто не спрашивал. */}
        <span>
          {coverageOn ? (
            <>
              закрыто <span className="font-mono text-text">{totalCovered}</span> из{' '}
              <span className="font-mono">{unique.length}</span> техник ·{' '}
              с экспозицией <span className="font-mono text-text">{totalExposed}</span> ·{' '}
              разрывов <span className="font-mono text-actor">{totalGaps}</span>
            </>
          ) : (
            <>
              слой покрытия выключен · техник{' '}
              <span className="font-mono text-text">{unique.length}</span> ·{' '}
              с экспозицией <span className="font-mono text-text">{totalExposed}</span>
            </>
          )}
        </span>
        <label className={cn('flex items-center gap-1.5', !coverageOn && 'opacity-50')}>
          <input
            type="checkbox"
            checked={onlyCovered}
            onChange={(e) => setOnlyCovered(e.target.checked)}
            disabled={!coverageOn}
            title={coverageOn ? undefined : COVERAGE_OFF}
            className="accent-primary"
          />
          только закрытые
        </label>
        {/* Обратный фильтр: вопрос экрана — не «что сделано», а «что нет». */}
        <label className={cn('flex items-center gap-1.5', !coverageOn && 'opacity-50')}>
          <input
            type="checkbox"
            checked={onlyUncovered}
            onChange={(e) => setOnlyUncovered(e.target.checked)}
            disabled={!coverageOn}
            title={coverageOn ? undefined : COVERAGE_OFF}
            className="accent-primary"
          />
          только незакрытые
        </label>
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={onlyExposed}
            onChange={(e) => setOnlyExposed(e.target.checked)}
            className="accent-primary"
          />
          только с экспозицией
        </label>
        {/* Разрыв — не то же, что незакрытое: техника не закрыта, и её
            есть чем выполнить именно здесь. Это и есть список работы. */}
        <label className={cn('flex items-center gap-1.5', !coverageOn && 'opacity-50')}>
          <input
            type="checkbox"
            checked={onlyGaps}
            onChange={(e) => setOnlyGaps(e.target.checked)}
            disabled={!coverageOn}
            title={coverageOn ? undefined : COVERAGE_OFF}
            className="accent-primary"
          />
          только разрывы
        </label>
        <button
          type="button"
          onClick={() =>
            setOverlay((on) => {
              // Фильтры по источникам живут внутри наложения: без него
              // они невидимы и не должны втихую резать матрицу.
              if (on) {
                setOnlyRu(false)
                setOnlyWw(false)
              }
              return !on
            })
          }
          aria-pressed={overlay}
          className={cn(
            TOGGLE,
            overlay ? 'border-actor/70 bg-actor/15 text-text' : 'border-grid bg-surface hover:border-actor/50',
          )}
        >
          <Swords className="h-3.5 w-3.5" aria-hidden />
          наложить атаки
        </button>
        {/* Фильтры по источникам названы так же, как галочки на клетках:
            человек ищет в списке то слово, которое видит в матрице.
            Фильтр по РФ виден при наложении всегда, но выключен без
            выгрузки — иначе непонятно, почему его нет, и куда идти за ним. */}
        {overlay && (
          <>
            <button
              type="button"
              onClick={() => setOnlyRu((v) => !v)}
              aria-pressed={onlyRu}
              disabled={!data.ru_source}
              title={
                data.ru_source
                  ? ruHint(data.ru_source)
                  : 'Выгрузка применяемости не загружена — раздел «РФ TTP» или настройки'
              }
              className={cn(
                TOGGLE,
                'text-kind-2 disabled:cursor-not-allowed disabled:opacity-50',
                onlyRu ? 'border-kind-2/70 bg-kind-2/15' : 'border-grid bg-surface hover:border-kind-2/50',
              )}
            >
              только РФ
            </button>
            <button
              type="button"
              onClick={() => setOnlyWw((v) => !v)}
              aria-pressed={onlyWw}
              title="Техники, которые применяют мировые группировки и кампании по разметке MITRE"
              className={cn(
                TOGGLE,
                'text-actor',
                onlyWw ? 'border-actor/70 bg-actor/15' : 'border-grid bg-surface hover:border-actor/50',
              )}
            >
              только WW
            </button>
          </>
        )}

        {/* Легенда покрытия объясняет цвета, которых при выключенном слое
            на экране нет: серая клетка тогда значит «не спрашивали»,
            а не «не закрыто». */}
        <span className="ml-auto flex flex-wrap items-center gap-3">
          {coverageOn ? (
            <>
              <Legend className="border-attack-confirmed/60 bg-attack-confirmed/15">
                подтверждено
              </Legend>
              <Legend className="border-attack-suggested/60 bg-attack-suggested/15">
                предложено моделью
              </Legend>
              <Legend className="border-grid bg-surface">не закрыто</Legend>
              <Legend className="border-actor bg-surface">красная рамка — разрыв</Legend>
            </>
          ) : (
            <span>закрытость техник цветом не показывается: слой покрытия выключен</span>
          )}
          <span className="inline-flex items-center gap-1.5">
            <span className="font-mono text-risk-high">VM</span>
            <span className="font-mono text-kind-3">AD</span>— счётчики в ячейке
          </span>
        </span>
      </div>

      {overlay && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded border border-actor/30 bg-actor/5 px-3 py-2 text-[11px] text-text-secondary">
          <span className="font-semibold text-text">
            {coverageOn
              ? 'Незакрытое — по распространённости атаки:'
              : 'Заливка — по распространённости атаки:'}
          </span>
          {[1, 2, 3, 4].map((level) => (
            <span key={level} className="inline-flex items-center gap-1.5">
              <span
                className="inline-block h-3 w-3 rounded-sm border border-actor/60"
                style={{ backgroundColor: fill(level) }}
                aria-hidden
              />
              {LEVEL_WORD[level]}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5">
            <span className="inline-block h-3 w-3 rounded-sm border border-grid bg-surface" aria-hidden />
            данных нет
          </span>

          {/* Главное число экрана: сколько из замеченного каждым источником
              мы закрываем. Ради него наложение и включают. */}
          <span className="w-full border-t border-actor/20 pt-1.5 text-text">
            <span className="font-mono text-kind-2">РФ</span> — замечено в выгрузке:{' '}
            {data.ru_source ? (
              <>
                <span className="font-mono">{ruScore.seen}</span> техник
                {/* Без слоя покрытия «закрыто» считать не из чего:
                    ноль здесь читался бы как «не закрыто ничего». */}
                {coverageOn && (
                  <>
                    , закрыто <span className="font-mono">{ruScore.covered}</span>, не закрыто{' '}
                    <span className="font-mono text-actor">{ruScore.seen - ruScore.covered}</span>
                  </>
                )}
                .
              </>
            ) : (
              <span className="text-text-secondary">выгрузка не загружена — раздел «РФ TTP».</span>
            )}{' '}
            <span className="font-mono text-actor">WW</span> — в мировых данных MITRE:{' '}
            <span className="font-mono">{wwScore.seen}</span> техник
            {coverageOn && (
              <>
                , закрыто <span className="font-mono">{wwScore.covered}</span>, не закрыто{' '}
                <span className="font-mono text-actor">{wwScore.seen - wwScore.covered}</span>
              </>
            )}
            .
          </span>
          <span className="w-full text-text-secondary">
            Зачёркнутая метка значит «источник об этом молчит», а не «не применяют»:
            зачёркнутое РФ у техники, которую видит мир, — это не отсутствие угрозы,
            а отсутствие отчёта.
          </span>
          {/* Закрытое остаётся своим цветом намеренно: вопрос экрана —
              что делать дальше, а по закрытой технике делать нечего. */}
          <span className="w-full text-text-secondary">
            Закрытые техники сохраняют свой цвет. Данные ретроспективные,
            а не оперативные: группировки и кампании — по разметке MITRE, телеметрия CTID —
            за {data.sightings_window ?? '2021–2023'}, США и обрабатывающая
            промышленность в ней преобладают.
          </span>
        </div>
      )}

      {/* Матрица шире экрана всегда: пятнадцать тактик — поэтому прокрутка
          вбок своя. По высоте она растёт как есть, а прокручивается вся
          страница: `flex-1` здесь схлопывал её в ноль. */}
      <div className="overflow-x-auto rounded border border-grid">
        <div className="flex w-max items-start gap-px bg-grid p-px">
          {data.tactics.map((tactic) => {
            const cells = tactic.techniques.filter((c) => {
              const covered = cellCovered(c)
              return (
                (!filterCovered || covered) &&
                (!filterUncovered || !covered) &&
                (!onlyExposed || cellExposed(c)) &&
                (!filterGaps || cellGap(c)) &&
                (!onlyRu || c.ru !== null) &&
                (!onlyWw || c.actor_groups > 0 || c.campaigns > 0)
              )
            })
            const coveredHere = tactic.techniques.filter(cellCovered).length
            const gapsHere = tactic.techniques.filter(cellGap).length
            // Тактика без единого правила — не пробел, а пропущенный шаг
            // атаки целиком. У разведки и подготовки ресурсов это норма:
            // они происходят вне периметра, правил на них не бывает.
            // Без включённого покрытия это утверждение непроверяемо: правил
            // не видно не потому, что их нет, а потому, что их не спросили.
            const blind =
              coverageOn && overlay && tactic.observable && tactic.techniques.length > 0 && coveredHere === 0
            return (
              <div key={tactic.shortname} className="flex w-40 shrink-0 flex-col gap-px">
                <div className={cn('sticky top-0 z-10 px-2 py-2', blind ? 'bg-actor/20' : 'bg-surface')}>
                  <div className="text-[11px] font-semibold text-text">
                    {tacticLabel(tactic.shortname)}
                  </div>
                  <div className="font-mono text-[10px] text-text-secondary">
                    {coverageOn
                      ? `${coveredHere} / ${tactic.techniques.length}`
                      : `${tactic.techniques.length} техник`}
                  </div>
                  {gapsHere > 0 && (
                    <div className="font-mono text-[10px] text-actor">разрывов {gapsHere}</div>
                  )}
                  {blind && (
                    <div className="mt-0.5 text-[10px] font-semibold text-actor">
                      ни одного правила
                    </div>
                  )}
                </div>
                {cells.map((cell) => (
                  <Cell
                    key={cell.technique_id}
                    cell={cell}
                    layers={shownExposure}
                    covered={cellCovered(cell)}
                    coverageOn={coverageOn}
                    status={cellStatus(cell)}
                    gap={cellGap(cell)}
                    overlay={overlay}
                    ruLoaded={data.ru_source !== null}
                    onSelect={() => setSelected(cell.technique_id)}
                  />
                ))}
                {cells.length === 0 && (
                  <div className="bg-surface px-2 py-3 text-[11px] text-text-secondary">
                    под фильтр ничего не попало
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <TechniqueDrawer
        techniqueId={selected}
        layers={layers}
        onClose={() => setSelected(null)}
      />
    </div>
  )
}

function Cell({
  cell,
  layers,
  covered,
  coverageOn,
  status,
  gap,
  overlay,
  ruLoaded,
  onSelect,
}: {
  cell: AttackMatrixCell
  /** Только включённые слои экспозиции: счётчик показывает то, что спросили. */
  layers: LayerMeta[]
  covered: boolean
  /** Спрашивали ли правила вообще: без этого «правил нет» сказать нельзя. */
  coverageOn: boolean
  status: 'confirmed' | 'suggested'
  gap: boolean
  overlay: boolean
  ruLoaded: boolean
  onSelect: () => void
}) {
  // Цвет покрытия главнее: если техника закрыта, вопрос «насколько часто
  // её применяют» вторичен — работа по ней уже сделана. Наложение
  // раскрашивает именно незакрытое, ради чего и включается.
  const paint = overlay && !covered && cell.level > 0
  //: Слои, которым есть что сказать про эту технику. Пустая строка
  //: счётчиков не рисуется вовсе: она занимала бы место в каждой ячейке.
  const counted = layers.flatMap((layer) => {
    const layerCell = cell.layers[layer.id]
    return layerCell ? [{ layer, count: layerCell.count }] : []
  })
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'border-l-2 px-2 py-1 text-left text-[11px] leading-snug',
        'cell-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
        paint ? 'text-text' : CELL_STYLE[covered ? status : 'unmapped'],
        gap && 'ring-1 ring-inset ring-actor',
      )}
      style={
        paint
          ? { backgroundColor: fill(cell.level), borderLeftColor: 'var(--color-actor)' }
          : undefined
      }
      title={describe(cell, layers, covered, coverageOn, gap, overlay, ruLoaded)}
    >
      {cell.name_ru ?? cell.name}
      {cell.subtechnique_count > 0 && (
        <span className="ml-1 font-mono text-text-secondary">·{cell.subtechnique_count}</span>
      )}
      {/* Счётчики слоёв и галочки источников, а не заливка: цвет клетки
          занят покрытием, и перекрашивать его значит подменять ответ
          на вопрос «сделана ли работа» ответом на другой вопрос. */}
      {(overlay || counted.length > 0) && (
        <span className="mt-1 flex flex-wrap gap-x-2 font-mono text-[10px]">
          {counted.map(({ layer, count }) => (
            <span
              key={layer.id}
              className={LAYER_TONE[layer.id] ?? 'text-text-secondary'}
              title={`${layer.title}: ${plural(count, layer.unit)}`}
            >
              {layer.id.toUpperCase()} {count}
            </span>
          ))}
          {/* Пока выгрузки нет, галочки РФ нет вовсе: снятая читалась бы
              как «здесь не применяют», хотя никто не спрашивал. */}
          {overlay && ruLoaded && <Tick on={cell.ru !== null} label="РФ" tone="text-kind-2" />}
          {overlay && (
            <Tick on={cell.actor_groups > 0 || cell.campaigns > 0} label="WW" tone="text-actor" />
          )}
        </span>
      )}
    </button>
  )
}

/** Метка источника: замечена ли техника там.
 *
 *  Незамеченный источник показывается наравне с замеченным — зачёркнутым,
 *  а не спрятанным. «Источник об этом молчит» — такой же ответ, как
 *  «источник это видел», и прятать его значит оставлять человека гадать,
 *  спросили источник или нет. Зачёркивание, а не только цвет: цвет
 *  никогда не единственный носитель смысла. */
function Tick({ on, label, tone }: { on: boolean; label: string; tone: string }) {
  return <span className={on ? tone : 'text-text-secondary/50 line-through'}>{label}</span>
}

/** Подсказка словами: цвет никогда не единственный носитель смысла. */
function describe(
  cell: AttackMatrixCell,
  layers: LayerMeta[],
  covered: boolean,
  coverageOn: boolean,
  gap: boolean,
  overlay: boolean,
  ruLoaded: boolean,
): string {
  const lines = [`${cell.technique_id} — ${cell.name_ru ?? cell.name}`]
  // «Правил нет» — утверждение о базе правил, а не о текущем виде экрана:
  // с выключенным слоем покрытия его сказать не о чем.
  lines.push(!coverageOn ? COVERAGE_OFF : covered ? 'закрыта правилом' : 'правил нет')
  for (const layer of layers) {
    const layerCell = cell.layers[layer.id]
    if (layerCell) lines.push(`${layer.title}: ${plural(layerCell.count, layer.unit)}`)
  }
  if (gap) lines.push('разрыв: экспозиция есть, правил нет')
  if (overlay) {
    // Про РФ молчим, пока выгрузки нет: пустая галочка означала бы
    // «здесь не применяют», хотя никто не спрашивал.
    lines.push(
      !ruLoaded
        ? 'РФ: выгрузка не загружена'
        : cell.ru
          ? `РФ: ${ruWords(cell.ru)}`
          : 'РФ: в выгрузке не встречается',
    )
    lines.push(
      cell.actor_groups > 0 || cell.campaigns > 0
        ? `WW: группировок ${cell.actor_groups}, кампаний ${cell.campaigns}` +
            (cell.sightings > 0 ? `, наблюдений ${cell.sightings}` : '')
        : 'WW: в мировых данных не встречается',
    )
  }
  return lines.join('\n')
}

function Legend({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn('inline-block h-3 w-3 rounded-sm border', className)} aria-hidden />
      {children}
    </span>
  )
}
