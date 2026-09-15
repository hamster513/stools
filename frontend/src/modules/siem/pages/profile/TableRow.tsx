import { useState } from 'react'
import { ChevronDown, ChevronRight, FileCheck2, FileWarning, FileX2 } from 'lucide-react'
import { useTableReaders, useTableValues } from '@/modules/siem/api/queries'
import type { TableRankingEntry } from '@/modules/siem/api/types'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

const STATE_META = {
  missing: { icon: FileX2, label: 'Нет в выгрузке', color: 'var(--color-kind-1)' },
  empty: { icon: FileWarning, label: 'Пуст', color: 'var(--color-kind-3)' },
  filled: { icon: FileCheck2, label: 'Наполнен', color: 'var(--color-kind-accepted)' },
} as const

function tableState(t: TableRankingEntry): keyof typeof STATE_META {
  if (!t.exists) return 'missing'
  if (t.is_empty) return 'empty'
  return 'filled'
}

/**
 * Строка табличного списка с раскрытием.
 *
 * Раскрытие нужно не для красоты: решить, ограничивает список область
 * действия правил или обогащает событие, по имени невозможно. Перечень
 * критичных узлов и справочник соответствий называются одинаково
 * безлико, а следствия у отметки разные.
 *
 * Состав запрашивается только при раскрытии: содержимое списков — это
 * инвентарь внутренней инфраструктуры, и грузить его заранее не следует.
 */
export function TableRow({
  snapshotId,
  entry,
  scoping,
  onToggle,
}: {
  snapshotId: number
  entry: TableRankingEntry
  scoping: boolean
  onToggle: () => void
}) {
  const [open, setOpen] = useState(false)
  const values = useTableValues(open ? entry.name : undefined, snapshotId)
  const readers = useTableReaders(open ? entry.name : undefined, snapshotId)
  // Отметку аудитор видит, но не ставит: она — решение о профиле.
  const { write } = useCan()

  const state = tableState(entry)
  const meta = STATE_META[state]
  const Icon = meta.icon

  return (
    <div className="py-1.5 first:pt-0 last:pb-0">
      <div className="flex items-center gap-3 text-xs">
        <input
          type="checkbox"
          checked={scoping}
          onChange={onToggle}
          disabled={!write}
          className="accent-primary"
          aria-label={`${entry.name}: ограничивает область действия правил`}
        />
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex min-w-0 flex-1 items-center gap-2 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          aria-expanded={open}
          title="Показать состав списка и правила, которые его читают"
        >
          {open ? (
            <ChevronDown size={13} className="shrink-0 text-text-secondary" aria-hidden />
          ) : (
            <ChevronRight size={13} className="shrink-0 text-text-secondary" aria-hidden />
          )}
          <Icon size={14} style={{ color: meta.color }} aria-hidden className="shrink-0" />
          <span className="min-w-0 truncate font-mono text-text" title={entry.name}>
            {entry.name}
          </span>
        </button>
        <span className="w-24 shrink-0 text-text-secondary">{meta.label}</span>
        <span className="w-24 shrink-0 text-right font-mono tabular-nums text-text-secondary">
          {entry.dependant_count} правил
        </span>
        <span
          className={cn(
            'w-40 shrink-0 text-right',
            scoping ? 'text-kind-accepted' : 'text-text-secondary',
          )}
        >
          {scoping ? 'ограничивает область' : 'обогащает событие'}
        </span>
      </div>

      {open && (
        <div className="mt-2 ml-7 grid gap-3 rounded border border-grid bg-app-bg p-3 lg:grid-cols-[2fr_1fr]">
          <div className="min-w-0">
            <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              Что лежит в списке
            </div>
            {values.isLoading && <p className="text-xs text-text-secondary">загрузка…</p>}
            {values.isError && (
              <p className="text-xs text-kind-3">
                Списка нет в выгрузке — правила ссылаются на него, но сам он не поставлен.
                Читающие его правила не сработают ни на чём.
              </p>
            )}
            {values.data && values.data.total === 0 && (
              <p className="text-xs text-kind-3">
                Список пуст. Правила, которые его читают, не сработают ни на чём — это тихая
                точка отказа, а не безобидная мелочь.
              </p>
            )}
            {values.data && values.data.total > 0 && (
              <>
                {/* Таблицей, а не свалкой: в списке рядом лежат
                    идентификатор, имя узла и комментарий, написанный
                    человеком для себя. Слитые в одну колонку, они не
                    говорят ничего — а решают по ним разное. */}
                <div className="max-h-56 overflow-auto">
                  <table className="w-max min-w-full text-xs">
                    <thead className="sticky top-0 bg-app-bg">
                      <tr>
                        {values.data.columns.map((c) => (
                          <th
                            key={c}
                            className={cn(
                              'px-1.5 py-1 text-left font-mono text-[11px] font-medium',
                              values.data.comment_columns.includes(c)
                                ? 'text-text-secondary/70'
                                : 'text-text-secondary',
                            )}
                          >
                            {c}
                            {values.data.comment_columns.includes(c) && (
                              <span className="ml-1 font-sans">— комментарий</span>
                            )}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {values.data.rows.map((row, i) => (
                        <tr key={i} className="border-t border-grid/50">
                          {values.data!.columns.map((c) => (
                            <td
                              key={c}
                              className={cn(
                                'max-w-[22rem] truncate px-1.5 py-0.5 font-mono',
                                values.data!.comment_columns.includes(c)
                                  ? 'text-text-secondary'
                                  : 'text-text',
                              )}
                              title={row[c] ?? ''}
                            >
                              {row[c] ?? ''}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {values.data.total > values.data.shown && (
                  <p className="mt-1 text-xs text-text-secondary">
                    показано {values.data.shown} строк из {values.data.total}
                  </p>
                )}
              </>
            )}
          </div>

          <div className="min-w-0">
            <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              Кто его читает ({readers.data?.total ?? '…'})
            </div>
            {/* Отметка касается всех этих правил разом: она объявляет, что
                каждое из них работает не шире содержимого списка. */}
            <ul className="max-h-48 overflow-y-auto">
              {readers.data?.items.map((r) => (
                <li key={r.uuid} className="truncate" title={r.name}>
                  <Link
                    to={`/siem/snapshots/${snapshotId}/rules?q=${encodeURIComponent(r.name)}`}
                    className="font-mono text-xs text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                  >
                    {r.name}
                  </Link>
                </li>
              ))}
            </ul>
            {readers.data?.total === 0 && (
              <p className="text-xs text-text-secondary">
                Список не читает ни одно правило. Отмечать его нечем — он ни на что не влияет.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
