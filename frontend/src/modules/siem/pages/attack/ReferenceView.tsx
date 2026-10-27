import { useState } from 'react'
import { ArrowLeftRight, CircleCheck, TriangleAlert } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useApplyReference, useReferenceCompare } from '@/modules/siem/api/queries'
import type { ReferenceItem, ReferenceVerdict } from '@/modules/siem/api/types'
import { AttackStateBadge, attackDisplayState } from '@/modules/attack/components/AttackStateBadge'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

/**
 * Сверка нашей разметки с чужой таблицей «правило → техника».
 *
 * Нужна затем, что качество разметки иначе обсуждается примерами. Число
 * говорит, стало лучше или хуже; список расхождений говорит, где именно.
 *
 * Эталон нашу разметку не подменяет: подменив, мы потеряли бы то, ради
 * чего его грузят.
 */
const VERDICT: Record<ReferenceVerdict, { label: string; hint: string; tone: string }> = {
  same: {
    label: 'совпало',
    hint: 'Тот же набор техник',
    tone: 'border-attack-confirmed/60 bg-attack-confirmed/10 text-attack-confirmed',
  },
  reference_finer: {
    label: 'эталон точнее',
    hint: 'То же семейство, но человек назвал подтехнику, а мы остановились на технике',
    tone: 'border-kind-3/60 bg-kind-3/10 text-kind-3',
  },
  reference_coarser: {
    label: 'мы точнее',
    hint: 'То же семейство, но подтехнику назвали мы',
    tone: 'border-kind-4/60 bg-kind-4/10 text-kind-4',
  },
  partial: {
    label: 'частично',
    hint: 'Часть семейств совпала, часть нет',
    tone: 'border-kind-2/60 bg-kind-2/10 text-kind-2',
  },
  different: {
    label: 'расхождение',
    hint: 'Ни одного общего семейства техник',
    tone: 'border-kind-1/60 bg-kind-1/10 text-kind-1',
  },
  no_markup: {
    label: 'у нас нет разметки',
    hint: 'Эталон говорит, мы молчим',
    tone: 'border-grid bg-surface text-text-secondary',
  },
}

const ORDER: ReferenceVerdict[] = [
  'different',
  'partial',
  'no_markup',
  'reference_finer',
  'reference_coarser',
  'same',
]

const COLUMNS: ColumnDef[] = [
  { key: 'rule', label: 'Правило', width: 320, flex: true },
  { key: 'ours', label: 'Наша разметка', width: 200 },
  { key: 'theirs', label: 'Эталон', width: 160 },
  { key: 'verdict', label: 'Итог', width: 160 },
  { key: 'actions', label: 'Действие', width: 96, resizable: false },
]

export function ReferenceView({ snapshotId }: { snapshotId: number }) {
  const compare = useReferenceCompare(snapshotId)
  const apply = useApplyReference()
  const [filter, setFilter] = useState<ReferenceVerdict | 'all'>('all')
  // Сама сверка — чтение, и она нужна всем; принятие эталона записывает разметку из
  // справочника — это настройка модуля, она у его администратора.
  const { admin } = useCan()
  const cols = useColumnWidths('siem-attack-reference-columns', COLUMNS)

  if (compare.isLoading) return <FullPageSpinner />
  if (compare.isError || !compare.data) {
    const message =
      compare.error instanceof ApiRequestError ? compare.error.message : 'Не удалось загрузить сверку'
    return <ErrorState message={message} onRetry={() => compare.refetch()} />
  }

  const data = compare.data

  if (!data.loaded) {
    return (
      <div className="flex flex-col items-start gap-3 rounded border border-dashed border-grid p-6">
        <p className="max-w-2xl text-sm text-text">
          Эталон — ваша собственная таблица «правило → техника ATT&amp;CK». С ней сверка покажет
          числом, где наша разметка совпадает с вашей, а где спорит.
        </p>
        <p className="max-w-2xl text-xs text-text-secondary">
          Таблица загружается в настройках, вместе с остальными файлами продукта.{' '}
          <a
            href="/samples/attack-reference-sample.csv"
            download
            className="text-primary underline underline-offset-2 hover:text-text"
          >
            Скачать образец таблицы
          </a>{' '}
          — его можно отдать аналитику или вендору для заполнения.
        </p>
        <Link
          to="/settings/siem"
          className="text-sm text-primary underline underline-offset-2 hover:text-text"
        >
          Настройки модуля →
        </Link>
      </div>
    )
  }

  const shown = filter === 'all' ? data.items : data.items.filter((i) => i.verdict === filter)
  const agreed = (data.counts.same ?? 0) + (data.counts.reference_coarser ?? 0)

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3 rounded border border-grid bg-surface px-3 py-2.5 text-xs">
        <span className="text-text">
          <span className="font-mono">{data.source}</span> — {data.compared} правил
        </span>
        {data.imported_by && (
          <span className="text-text-secondary">
            загрузил {data.imported_by}
            {data.imported_at ? `, ${new Date(data.imported_at).toLocaleString('ru')}` : ''}
          </span>
        )}
        <Link
          to="/settings/siem"
          className="ml-auto text-text-secondary underline underline-offset-2 hover:text-primary"
        >
          заменить или убрать — в настройках
        </Link>
      </div>

      {/* Пробелы сверки — тоже результат. Молчать о том, что треть правил
          сверить не с чем, значит выдавать частичную картину за полную. */}
      {(data.rules_without_reference > 0 || data.unmatched.length > 0) && (
        <div className="flex gap-2 rounded border border-kind-3/40 bg-kind-3/5 px-3 py-2 text-xs leading-relaxed text-text-secondary">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-kind-3" aria-hidden />
          <div>
            {data.rules_without_reference > 0 && (
              <>
                Правил в выгрузке, которых нет в таблице:{' '}
                <span className="font-mono text-text">{data.rules_without_reference}</span> — их
                разметку сверить не с чем.{' '}
              </>
            )}
            {data.unmatched.length > 0 && (
              <>
                Строк таблицы, которым не нашлось правила:{' '}
                <span className="font-mono text-text">{data.unmatched.length}</span> (
                {data.unmatched.map((u) => u.source_key).join(', ')}).
              </>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1.5">
        <Chip active={filter === 'all'} onClick={() => setFilter('all')} tone="border-grid bg-surface text-text">
          Все · {data.compared}
        </Chip>
        {ORDER.filter((v) => data.counts[v]).map((v) => (
          <Chip key={v} active={filter === v} onClick={() => setFilter(v)} tone={VERDICT[v].tone} title={VERDICT[v].hint}>
            {VERDICT[v].label} · {data.counts[v]}
          </Chip>
        ))}
        <span className="ml-auto inline-flex items-center gap-1.5 text-xs text-text-secondary">
          <CircleCheck size={13} aria-hidden />
          сходится с эталоном: {agreed} из {data.compared}
        </span>
      </div>

      {/* Принятие эталона — явное решение человека, а не побочное действие
          загрузки файла: подменив разметку молча, продукт лишил бы себя
          того, ради чего эталон и грузят. */}
      {admin && (
      <div className="flex flex-wrap items-center gap-2 rounded border border-grid bg-surface px-3 py-2 text-xs">
        <span className="text-text-secondary">
          Эталон — работа ваших аналитиков, и она точнее модели. Принятое записывается
          подтверждённым: следующий прогон модели его не тронет.
        </span>
        <span className="ml-auto flex items-center gap-2">
          <Button
            variant="ghost"
            loading={apply.isPending}
            disabled={!(data.counts.no_markup || data.counts.different || data.counts.partial)}
            onClick={() =>
              apply.mutate({
                snapshot_id: snapshotId,
                verdicts: ['no_markup', 'different', 'partial'],
              })
            }
            title="Там, где мы молчим или спорим. Совпадающее и уточнённое нами не трогается"
          >
            <ArrowLeftRight size={14} aria-hidden />
            Принять там, где расходимся
          </Button>
          <Button
            variant="primary"
            loading={apply.isPending}
            onClick={() => apply.mutate({ snapshot_id: snapshotId })}
            title={`Записать эталон разметкой всем ${data.compared} сверенным правилам`}
          >
            Принять весь эталон
          </Button>
        </span>
        {apply.isSuccess && (
          <span className="w-full text-text">
            Принято правил: <span className="font-mono">{apply.data.applied}</span> из{' '}
            {apply.data.considered} рассмотренных.
          </span>
        )}
        {apply.isError && (
          <span className="w-full text-kind-1">
            {apply.error instanceof ApiRequestError ? apply.error.message : 'Не удалось принять'}
          </span>
        )}
      </div>
      )}

      {/* Высоту не ограничиваем: прокручивается страница целиком.
          `flex-1` внутри прокручиваемой страницы схлопывает блок в ноль. */}
      <div className="overflow-x-auto rounded border border-grid">
        <table className="w-full border-collapse text-xs" style={cols.tableStyle}>
          <ColGroup cols={cols} />
          <thead className="sticky top-0 bg-surface">
            <tr className="text-left text-text-secondary">
              <ResizableHeader cols={cols} className="px-2.5 py-2" content={{ actions: <span className="sr-only">Действие</span> }} />
            </tr>
          </thead>
          <tbody>
            {shown.map((item) => (
              <Row
                key={item.uuid}
                item={item}
                onApply={
                  admin
                    ? () => apply.mutate({ snapshot_id: snapshotId, rule_uuid: item.uuid })
                    : undefined
                }
                busy={apply.isPending}
              />
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <p className="px-3 py-4 text-xs text-text-secondary">Таких правил нет.</p>
        )}
      </div>
    </div>
  )
}

function Row({
  item,
  onApply,
  busy,
}: {
  item: ReferenceItem
  /** Не задан — принимать нечем: без права строка остаётся только чтением. */
  onApply?: () => void
  busy: boolean
}) {
  const meta = VERDICT[item.verdict]
  return (
    <tr className="border-t border-grid align-top hover:bg-row-hover">
      <td className="px-2.5 py-1.5 break-words">
        <div className="font-mono text-text">{item.name}</div>
        <div className="text-text-secondary">
          <span className="font-mono">{item.source_key}</span>
          {item.note && ` · ${item.note.slice(0, 90)}`}
        </div>
      </td>
      <td className="px-2.5 py-1.5 break-words">
        <div className="flex flex-wrap items-center gap-1">
          <AttackStateBadge state={attackDisplayState(item.status, false)} />
          {/* Унаследованная разметка ничего не утверждает об этом правиле,
              и расхождение с ней говорит о группе, а не о правиле. */}
          {item.inherited && <span className="text-kind-2">не уточнена для правила</span>}
        </div>
        <div className="mt-0.5 font-mono text-text">{item.ours.join(', ') || '—'}</div>
      </td>
      <td className="px-2.5 py-1.5 font-mono break-words text-text">
        {item.theirs.join(', ') || '—'}
        {/* Перенос отозванной техники показывается, а не применяется молча. */}
        {item.original.join() !== item.theirs.join() && (
          <div className="text-text-secondary" title="Отозвано MITRE, перенесено на замену">
            было {item.original.join(', ')}
          </div>
        )}
      </td>
      <td className="overflow-hidden px-2.5 py-1.5">
        <span
          className={cn('inline-block rounded border px-1.5 py-0.5 whitespace-nowrap', meta.tone)}
          title={meta.hint}
        >
          {meta.label}
        </span>
      </td>
      <td className="px-2.5 py-1.5 text-right">
        {onApply && item.verdict !== 'same' && (
          <Button variant="ghost" disabled={busy} onClick={onApply} title="Записать эталон разметкой этого правила">
            Принять
          </Button>
        )}
      </td>
    </tr>
  )
}

function Chip({
  active,
  onClick,
  tone,
  title,
  children,
}: {
  active: boolean
  onClick: () => void
  tone: string
  title?: string
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        'rounded border px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
        tone,
        active ? 'ring-1 ring-focus-ring' : 'opacity-70 hover:opacity-100',
      )}
      aria-pressed={active}
    >
      {children}
    </button>
  )
}
