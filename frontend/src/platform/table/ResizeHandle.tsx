import { useLayoutEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'
import type { ColumnWidths } from './useColumnWidths'

/**
 * Ручка на правой границе ячейки заголовка (у ячейки — `position: relative`). Тонкий разделитель виден всегда, чтобы
 * было понятно, за что хвататься; зона захвата — 12 px поверх границы, при наведении и фокусе граница подсвечивается,
 * при перетаскивании от неё вниз через весь список идёт направляющая — до низа ближайшего `<table>` или
 * `[data-col-resize-root]`. `edge` — у последней колонки: зона целиком внутри ячейки, чтобы не вылезать за таблицу.
 * Ручка резиновой колонки ещё и меряет контейнер списка — родителя `<table>` или строки заголовка сетки — и сообщает
 * его ширину в `cols.setContainerWidth`: по ней считается ширина резиновой колонки по умолчанию.
 */
export function ResizeHandle<C extends string>({ cols, col, label, edge = false }: { cols: ColumnWidths<C>; col: C; label?: string; edge?: boolean }) {
  const [guide, setGuide] = useState(0)
  const ref = useRef<HTMLDivElement>(null)
  const props = cols.handleProps(col, label)
  const active = cols.dragging === col
  const measures = cols.columns.find((c) => c.flex)?.key === col
  const { setContainerWidth } = cols
  useLayoutEffect(() => {
    // Список — таблица или строка заголовка сетки (ручка → ячейка → строка); его родитель — блок шириной с место под список.
    const list = ref.current?.closest('table') ?? ref.current?.parentElement?.parentElement
    const box = list?.parentElement
    if (!measures || !list || !box) return
    const measure = () => {
      const s = getComputedStyle(box)
      // Ширина содержимого: без рамок, полосы прокрутки и отступов; дробная, чтобы не вылезти за край на полпикселя.
      let w = box.getBoundingClientRect().width - (box.offsetWidth - box.clientWidth) - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight)
      const max = parseFloat(getComputedStyle(list).maxWidth) // `max-w-*` у таблицы: заполнять до него, не дальше
      if (!Number.isNaN(max)) w = Math.min(w, max)
      setContainerWidth(w)
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(box)
    return () => observer.disconnect()
  }, [measures, setContainerWidth])
  return (
    <>
      <span aria-hidden className="pointer-events-none absolute top-1.5 right-0 bottom-1.5 w-px bg-border" />
      <div
        {...props}
        ref={ref}
        onMouseDown={(e) => {
          const cell = e.currentTarget.parentElement
          const root = e.currentTarget.closest('table, [data-col-resize-root]')
          setGuide(cell && root ? Math.max(0, Math.round(root.getBoundingClientRect().bottom - cell.getBoundingClientRect().top)) : 0)
          props.onMouseDown(e)
        }}
        className={cn('group absolute top-0 z-10 h-full w-3 cursor-col-resize select-none focus-visible:outline-none', edge ? 'right-0' : '-right-1.5')}
      >
        <span aria-hidden className={cn('pointer-events-none absolute inset-y-0 w-0.5 bg-primary', edge ? 'right-0' : 'left-1/2 -translate-x-1/2', active ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100')} />
        {active && guide > 0 && <span aria-hidden className={cn('pointer-events-none absolute top-0 w-px bg-primary/40', edge ? 'right-0' : 'left-1/2')} style={{ height: guide }} />}
      </div>
    </>
  )
}
