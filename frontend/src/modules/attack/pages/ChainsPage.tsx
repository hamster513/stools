import { useState } from 'react'
import { ChevronDown, ChevronRight, Crosshair } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAttackChains } from '@/modules/attack/api/queries'
import { ruWords, tacticLabel, type AttackChain, type ChainStep } from '@/modules/attack/api/types'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'campaign', label: 'Кампания', width: 256 },
  { key: 'when', label: 'Когда', width: 144 },
  { key: 'steps', label: 'Цепочка шагов', width: 420, flex: true },
  { key: 'blind', label: 'Мимо правил', width: 112 },
  { key: 'uncovered', label: 'Не закрыто техник', width: 144 },
]

/**
 * Цепочки реальных кампаний и наши пробелы в них.
 *
 * Матрица отвечает «что не закрыто», цепочка — «такой путь уже проходили,
 * и вот здесь мы бы его не увидели». Пробел, попавший на шаг случившейся
 * кампании, весит больше пробела вообще.
 *
 * Порядок шагов — порядок тактик матрицы. Своего порядка техник ATT&CK
 * не хранит, и выдумывать его нельзя, но и алфавитный за ход атаки
 * выдавать тоже.
 */
export function ChainsPage() {
  const chains = useAttackChains()
  const [open, setOpen] = useState<string | null>(null)
  const [onlyGaps, setOnlyGaps] = useState(true)
  const [onlyExposed, setOnlyExposed] = useState(false)
  const cols = useColumnWidths('attack-chains-columns', COLUMNS)

  if (chains.isLoading) return <FullPageSpinner />
  if (chains.isError || !chains.data) {
    const message =
      chains.error instanceof ApiRequestError ? chains.error.message : 'Не удалось загрузить цепочки'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => chains.refetch()} />
      </div>
    )
  }

  const data = chains.data
  // Техники, которые в этой инфраструктуре есть чем выполнить. Непокрытый
  // шаг, попавший сюда, — не абстрактный пробел: путь уже проходили,
  // средство для него здесь есть, а правила на него нет.
  const exposed = new Set(data.exposed)
  const hasExposed = (chain: AttackChain) =>
    chain.steps.some((s) => s.uncovered.some((t) => exposed.has(t.technique_id)))
  const withGaps = data.items.filter((c) => c.blind_steps > 0)
  const withExposure = data.items.filter(hasExposed)
  const shown = data.items.filter(
    (c) => (!onlyGaps || c.blind_steps > 0) && (!onlyExposed || hasExposed(c)),
  )

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 overflow-y-auto p-6">
      <div>
        <h1 className="text-base font-semibold text-text">Цепочки кампаний</h1>
        <p className="max-w-3xl text-xs text-text-secondary">
          Матрица отвечает «что не закрыто», цепочка — «такой путь уже проходили, и вот здесь
          мы бы его не увидели».
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-text-secondary">
        <span>
          кампаний <span className="font-mono text-text">{data.items.length}</span>, из них с
          шагом мимо всех правил <span className="font-mono text-actor">{withGaps.length}</span>, с
          экспозицией <span className="font-mono text-actor">{withExposure.length}</span>
        </span>
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={onlyGaps}
            onChange={(e) => setOnlyGaps(e.target.checked)}
            className="accent-primary"
          />
          <span>только с пробелами</span>
        </label>
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={onlyExposed}
            onChange={(e) => setOnlyExposed(e.target.checked)}
            className="accent-primary"
          />
          <span>только с экспозицией</span>
        </label>
        <span className="ml-auto flex flex-wrap items-center gap-3">
          <Legend className="bg-actor">мимо правил</Legend>
          <Legend className="bg-attack-suggested/60">закрыто частично</Legend>
          <Legend className="bg-attack-confirmed/70">закрыто</Legend>
          <Legend className="bg-grid">вне поля зрения сенсоров</Legend>
          <span className="inline-flex items-center gap-1.5">
            <Crosshair className="h-3 w-3 text-actor" aria-hidden />
            есть чем выполнить здесь
          </span>
        </span>
      </div>

      {/* Кампании отстают от жизни, и это надо сказать прямо, а не дать
          принять их за оперативные данные. */}
      <p className="max-w-4xl text-xs leading-relaxed text-text-secondary">
        Кампании ATT&CK {data.attack_version} — то, что уже случилось. Шаги идут в порядке тактик
        матрицы: своего порядка техник ATT&CK не хранит. Данные ретроспективные, последняя
        кампания — {data.latest_seen?.slice(0, 7) || '—'}. Разведка и подготовка ресурсов
        пробелом не считаются: они происходят вне периметра, и правил на них не бывает.
      </p>

      {shown.length === 0 ? (
        <p className="rounded border border-attack-confirmed/40 bg-attack-confirmed/5 px-3 py-2.5 text-xs text-text">
          {/* Причина пустоты — та комбинация фильтров, которая её дала:
              иначе экран объясняет не то, что человек только что включил. */}
          {emptyReason(data.items.length, onlyGaps, onlyExposed)}
        </p>
      ) : (
        <div className="overflow-x-auto rounded border border-grid">
          <table className="w-full border-collapse text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="sticky top-0 bg-surface">
              <tr className="text-left text-text-secondary">
                <ResizableHeader cols={cols} className="px-2.5 py-2" />
              </tr>
            </thead>
            <tbody>
              {shown.map((chain) => (
                <Row
                  key={chain.id}
                  chain={chain}
                  exposed={exposed}
                  open={open === chain.id}
                  onToggle={() => setOpen(open === chain.id ? null : chain.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** Почему список пуст. Каждая комбинация фильтров говорит своё: «пробелов
 *  нет» и «пробел не совпал с экспозицией» — разные новости, и выдавать
 *  одну за другую нельзя. */
function emptyReason(total: number, onlyGaps: boolean, onlyExposed: boolean): string {
  if (total === 0) return 'Кампаний в матрице нет.'
  if (onlyGaps && onlyExposed)
    return `Ни в одной из ${total} кампаний нет одновременно шага мимо всех правил и непокрытой техники, которую в инфраструктуре есть чем выполнить.`
  if (onlyExposed)
    return `Ни в одной из ${total} кампаний непокрытый шаг не совпал с тем, что в инфраструктуре есть чем выполнить.`
  return `Ни в одной из ${total} кампаний нет шага, который прошёл бы мимо всех правил. Это не значит, что детект сработает, — только что правило на такой шаг есть.`
}

function Row({
  chain,
  exposed,
  open,
  onToggle,
}: {
  chain: AttackChain
  /** Техники, которые в этой инфраструктуре есть чем выполнить. */
  exposed: Set<string>
  open: boolean
  onToggle: () => void
}) {
  const Icon = open ? ChevronDown : ChevronRight
  const observable = chain.steps.filter((s) => s.observable).length
  return (
    <>
      <tr
        className={cn('border-t border-grid align-top', open ? 'bg-row-selected' : 'hover:bg-row-hover')}
      >
        <td className="px-2.5 py-2">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            className="flex items-start gap-1.5 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <Icon size={13} className="mt-0.5 shrink-0 text-text-secondary" aria-hidden />
            <span className="font-medium text-balance text-text">{chain.name}</span>
          </button>
        </td>
        <td className="truncate px-2.5 py-2 text-text-secondary">
          {chain.first_seen?.slice(0, 7) ?? '—'}
          {chain.last_seen && chain.last_seen !== chain.first_seen
            ? ` — ${chain.last_seen.slice(0, 7)}`
            : ''}
        </td>
        <td className="px-2.5 py-2">
          {/* Полоса шагов с подписями: цвет никогда не единственный
              носитель смысла — под каждым блоком стоит имя тактики. */}
          <div className="flex gap-px">
            {chain.steps.map((step) => (
              <Segment key={step.tactic} step={step} />
            ))}
          </div>
        </td>
        <td className="truncate px-2.5 py-2">
          <span className={chain.blind_steps > 0 ? 'text-actor' : 'text-text-secondary'}>
            {chain.blind_steps}
          </span>
          <span className="text-text-secondary"> из {observable}</span>
        </td>
        <td className="truncate px-2.5 py-2 text-text-secondary">
          {chain.uncovered_count} из {chain.technique_count}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-grid bg-row-selected">
          <td colSpan={5} className="px-2.5 pt-1 pb-3">
            <ul className="flex flex-col gap-1.5">
              {chain.steps.map((step) => (
                <li key={step.tactic} className="flex flex-wrap items-baseline gap-x-2 text-xs">
                  <span
                    className={cn(
                      'w-44 shrink-0 font-medium',
                      !step.observable
                        ? 'text-text-secondary'
                        : step.blind
                          ? 'text-actor'
                          : 'text-text',
                    )}
                  >
                    {tacticLabel(step.tactic)}
                  </span>
                  <span className="w-28 shrink-0 text-text-secondary">
                    {!step.observable ? 'не наблюдается' : `закрыто ${step.covered} из ${step.total}`}
                  </span>
                  {step.observable && step.uncovered.length > 0 && (
                    <span className="min-w-0 flex-1 text-text-secondary">
                      {/* Замеченное здесь идёт первым и помечено: пробел
                          на технике, которую применяют против таких же,
                          весит больше пробела из чужого отчёта. */}
                      {step.uncovered.map((t) => (
                        <span
                          key={t.technique_id}
                          className="mr-2.5 inline-block"
                          title={t.ru ? ruWords(t.ru) : undefined}
                        >
                          {/* Экспозиция: технику здесь есть чем выполнить —
                              такой пробел весит больше пробела вообще. */}
                          {exposed.has(t.technique_id) && (
                            <Crosshair
                              className="mr-0.5 inline h-3 w-3 align-[-2px] text-actor"
                              role="img"
                              aria-label="есть чем выполнить здесь"
                            />
                          )}
                          <span className="font-mono text-actor">{t.technique_id}</span> {t.name}
                          {t.ru && (
                            <span className="ml-1 font-mono text-[9px] font-semibold text-kind-2">
                              РФ
                            </span>
                          )}
                        </span>
                      ))}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </td>
        </tr>
      )}
    </>
  )
}

function Segment({ step }: { step: ChainStep }) {
  const tone = !step.observable
    ? 'bg-grid'
    : step.blind
      ? 'bg-actor'
      : step.covered === step.total
        ? 'bg-attack-confirmed/70'
        : 'bg-attack-suggested/60'
  return (
    <span
      className="min-w-0 flex-1"
      title={`${tacticLabel(step.tactic)} — ${
        !step.observable ? 'вне поля зрения сенсоров' : `закрыто ${step.covered} из ${step.total}`
      }`}
    >
      <span className={cn('block h-2 rounded-[1px]', tone)} aria-hidden />
      <span className="mt-0.5 block truncate text-[10px] text-text-secondary">
        {tacticLabel(step.tactic)}
      </span>
    </span>
  )
}

function Legend({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn('inline-block h-2.5 w-4 rounded-[1px]', className)} aria-hidden />
      {children}
    </span>
  )
}
