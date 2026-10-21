import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Copy, FileCheck2, FileWarning, FileX2 } from 'lucide-react'
import { useTableReaders, useTableValues } from '@/modules/siem/api/queries'
import type { TableRankingEntry } from '@/modules/siem/api/types'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

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
  // Колонки у каждого списка свои — и ширины помнятся по списку. Резиновая —
  // первая колонка-комментарий (там длинный текст), без неё — последняя.
  const valueColumns = useMemo<ColumnDef[]>(() => {
    const names = values.data?.columns ?? []
    const flex = names.find((c) => values.data?.comment_columns.includes(c)) ?? names[names.length - 1]
    return names.map((c) => ({ key: c, label: c, width: 176, flex: c === flex }))
  }, [values.data])
  const cols = useColumnWidths(`siem-profile-values-${entry.name}`, valueColumns)

  // Имя копируют, чтобы найти список в SIEM: набирать его руками долго
  // и легко ошибиться в одном символе длинного имени.
  const nameRef = useRef<HTMLSpanElement>(null)
  const [copied, setCopied] = useState<'copied' | 'selected' | null>(null)
  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(null), 1500)
    return () => window.clearTimeout(timer)
  }, [copied])

  async function copyName() {
    try {
      await navigator.clipboard.writeText(entry.name)
      setCopied('copied')
    } catch {
      // Буфер бывает закрыт (нет https, отказ в разрешении) — тогда хотя бы
      // выделяем имя, чтобы его скопировали руками.
      const el = nameRef.current
      const selection = window.getSelection()
      if (el && selection) {
        const range = document.createRange()
        range.selectNodeContents(el)
        selection.removeAllRanges()
        selection.addRange(range)
        setCopied('selected')
      }
    }
  }

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
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex shrink-0 items-center gap-2 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            aria-expanded={open}
            aria-label={`${entry.name}: показать состав списка и правила, которые его читают`}
            title="Показать состав списка и правила, которые его читают"
          >
            {open ? (
              <ChevronDown size={13} className="shrink-0 text-text-secondary" aria-hidden />
            ) : (
              <ChevronRight size={13} className="shrink-0 text-text-secondary" aria-hidden />
            )}
            <Icon size={14} style={{ color: meta.color }} aria-hidden className="shrink-0" />
          </button>
          {/* Имя вне кнопки раскрытия: текст внутри кнопки не выделяется,
              а выделение мышью не должно раскрывать строку. */}
          <span
            ref={nameRef}
            className="min-w-0 cursor-text truncate font-mono text-text select-text"
            title={entry.name}
          >
            {entry.name}
          </span>
          <span className="relative shrink-0">
            <button
              type="button"
              onClick={copyName}
              className="rounded p-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              aria-label="Скопировать имя списка"
              title="Скопировать имя списка"
            >
              <Copy size={12} aria-hidden />
            </button>
            {/* Поверх соседних колонок, а не в потоке: иначе подсказка сжимает
                имя до нуля, и выделенное при отказе буфера не видно. */}
            {copied && (
              <span
                className="absolute top-1/2 left-full z-10 ml-1 -translate-y-1/2 rounded border border-grid bg-surface px-1.5 py-0.5 whitespace-nowrap text-kind-accepted"
                role="status"
              >
                {copied === 'copied' ? 'скопировано' : 'выделено — скопируйте вручную'}
              </span>
            )}
          </span>
        </div>
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
                  <table className="w-full text-xs" style={cols.tableStyle}>
                    <ColGroup cols={cols} />
                    <thead className="sticky top-0 bg-app-bg">
                      <tr>
                        <ResizableHeader
                          cols={cols}
                          className="px-1.5 py-1 text-left font-mono text-[11px] text-text-secondary"
                          content={Object.fromEntries(
                            values.data.comment_columns.map((c) => [
                              c,
                              <span key={c} className="text-text-secondary/70">
                                {c}
                                <span className="ml-1 font-sans">— комментарий</span>
                              </span>,
                            ]),
                          )}
                        />
                      </tr>
                    </thead>
                    <tbody>
                      {values.data.rows.map((row, i) => (
                        <tr key={i} className="border-t border-grid/50">
                          {values.data!.columns.map((c) => (
                            <td
                              key={c}
                              className={cn(
                                'truncate px-1.5 py-0.5 font-mono',
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
