import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { ResizeHandle } from './ResizeHandle'
import type { ColumnWidths } from './useColumnWidths'

const ALIGN = { left: 'justify-start text-left', right: 'justify-end text-right', center: 'justify-center text-center' }

/**
 * Ячейки заголовка по `cols.columns`: подпись, ручка у каждой изменяемой колонки и «сбросить», пока ширины изменены.
 * Рендерит только ячейки — строку (`<tr>` или div с `cols.gridStyle`) ставит вызывающий. `as="th"` — для `<table>`,
 * `as="div"` — для списка на сетке. `content` — своё содержимое вместо подписи (галочка «все», скрытая подпись);
 * `className` — отступы ячеек; «сбросить» — в колонке `resetIn`, по умолчанию в резиновой (там больше места),
 * иначе в последней изменяемой.
 */
export function ResizableHeader<C extends string>({ cols, as: Cell = 'th', className, content, resetIn }: {
  cols: ColumnWidths<C>
  as?: 'th' | 'div'
  className?: string
  content?: Partial<Record<C, ReactNode>>
  resetIn?: C
}) {
  const resizable = cols.columns.filter((c) => c.resizable !== false)
  const resetCol = resetIn ?? cols.columns.find((c) => c.flex && c.resizable !== false)?.key ?? resizable[resizable.length - 1]?.key
  const last = cols.columns[cols.columns.length - 1]?.key
  return (
    <>
      {cols.columns.map((c) => (
        <Cell key={c.key} scope={Cell === 'th' ? 'col' : undefined} className={cn('relative font-semibold', className)}>
          <div className={cn('flex min-w-0 items-center gap-2', ALIGN[c.align ?? 'left'])}>
            <span className="min-w-0 break-words">{content?.[c.key] ?? c.label}</span>
            {c.key === resetCol && cols.customized && (
              <button type="button" onClick={cols.reset} className="shrink-0 rounded font-normal tracking-normal text-text-secondary normal-case hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title="Вернуть ширины колонок по умолчанию">сбросить</button>
            )}
          </div>
          {c.resizable !== false && <ResizeHandle cols={cols} col={c.key} label={c.label} edge={c.key === last} />}
        </Cell>
      ))}
    </>
  )
}

/** Ширины колонок `<table>` с `cols.tableStyle`, все в px (у резиновой — посчитанная по контейнеру). */
export function ColGroup<C extends string>({ cols }: { cols: ColumnWidths<C> }) {
  return (
    <colgroup>
      {cols.columns.map((c) => <col key={c.key} style={{ width: cols.width(c.key) }} />)}
    </colgroup>
  )
}
