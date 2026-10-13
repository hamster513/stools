import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'

/**
 * Перетаскиваемые границы колонок — общий примитив для всех списков.
 *   import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
 *   import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
 *
 * Таблица (`<table>`):
 *   const COLUMNS: ColumnDef<'name' | 'note'>[] = [{ key: 'name', label: 'Имя', width: 200 }, { key: 'note', label: 'Заметка', width: 240, flex: true }]
 *   const cols = useColumnWidths('module-page-columns', COLUMNS)          // COLUMNS — константа модуля, ключ — уникальный
 *   <table className="w-full text-xs" style={cols.tableStyle}>           // table-layout: fixed + width = сумма ширин
 *     <ColGroup cols={cols} />
 *     <thead><tr><ResizableHeader cols={cols} className="px-3 py-2" /></tr></thead>   // ячейки <th> с ручками и «сбросить»
 *
 * Список на сетке (div):
 *   const cols = useColumnWidths('module-list-columns', COLUMNS)
 *   <div data-col-resize-root className="overflow-auto">                  // по нему считается высота направляющей при перетаскивании
 *     <div className="grid sticky top-0 …" style={cols.gridStyle}><ResizableHeader cols={cols} as="div" className="px-2 py-2" /></div>
 *     {rows.map((r) => <div key={r.id} className="grid …" style={cols.gridStyle}>{…ячейки в порядке COLUMNS…}</div>)}
 *
 * Правила:
 * - Порядок ячеек в строках совпадает с порядком COLUMNS. Колонка, которая показывается не всегда (по роли, переключателю), —
 *   два массива-константы и выбор между ними; массив, собранный в рендере, — через useMemo.
 * - `flex: true` — одна «резиновая» колонка (обычно самая текстовая): по умолчанию её ширина дополняет список до ширины
 *   контейнера (родителя таблицы или строки заголовка; не меньше её `width`) и следует за ним при изменении окна.
 *   Это только значение по умолчанию: у всех колонок ширина в px, и граница, которую тянут, — единственная, что
 *   движется (колонки правее сдвигаются целиком). Поставленная пользователем ширина резиновой колонки хранится как у
 *   остальных. Сумма меньше контейнера — справа пусто, больше — прокрутка обёртки. Контейнер меряет ручка резиновой колонки.
 * - Ячейки сетки — с `min-w-0`, иначе длинное содержимое распирает колонку. Ячейки заголовка — без `overflow-hidden`:
 *   зона захвата заходит на 6 px в соседнюю колонку.
 * - `resizable: false` — колонка без ручки (галочка, кнопки действий): её ширина не меняется и не хранится.
 * - `min`/`max` — пределы перетаскивания (по умолчанию 48 px или ширина колонки, если она меньше, и 2000 px).
 * - Ячейки таблицы с фиксированной раскладкой не раздвигаются содержимым: длинный текст — `truncate` (с `title`) или `break-all`.
 * - Ширины — удобство пользователя на этом устройстве (localStorage), не состояние: отсутствие хранилища ничего не ломает.
 */
export interface ColumnDef<C extends string = string> {
  key: C
  /** Подпись в заголовке и в aria-label ручки. */
  label: string
  /** Ширина по умолчанию, px; у `flex`-колонки — минимальная (по умолчанию она дополняет список до ширины контейнера). */
  width: number
  flex?: boolean
  min?: number
  max?: number
  /** false — колонка фиксированной ширины без ручки. */
  resizable?: boolean
  /** Выравнивание подписи в заголовке. */
  align?: 'left' | 'right' | 'center'
}

export interface ColumnWidths<C extends string = string> {
  columns: readonly ColumnDef<C>[]
  /** Текущая ширина колонки, px. */
  width: (col: C) => number
  /** Свойства ручки (роль, aria, мышь, двойной клик, клавиши). Обычно не нужны напрямую — их ставит `ResizeHandle`. */
  handleProps: (col: C, label?: string) => HandleProps
  /** Все ширины по умолчанию. */
  reset: () => void
  /** Одна колонка по умолчанию. */
  resetColumn: (col: C) => void
  /** Есть ли изменённые ширины — тогда в заголовке показывается «сбросить». */
  customized: boolean
  /** Колонка, которую сейчас тянут мышью. */
  dragging: C | null
  /** Для списка на сетке: `{ gridTemplateColumns, minWidth }`, все колонки в px. */
  gridStyle: CSSProperties
  /** Для `<table>`: `{ tableLayout: 'fixed', width }` — ширина таблицы равна сумме колонок; ширины задаёт `<ColGroup>`. */
  tableStyle: CSSProperties
  /** Доступная ширина контейнера списка, px — от неё считается резиновая колонка. Вызывает ручка резиновой колонки. */
  setContainerWidth: (px: number) => void
}

export interface HandleProps {
  role: 'separator'
  'aria-orientation': 'vertical'
  'aria-label': string
  'aria-valuenow': number
  'aria-valuemin': number
  'aria-valuemax': number
  tabIndex: number
  title: string
  onMouseDown: (e: React.MouseEvent<HTMLElement>) => void
  onDoubleClick: (e: React.MouseEvent<HTMLElement>) => void
  onKeyDown: (e: React.KeyboardEvent<HTMLElement>) => void
  onClick: (e: React.MouseEvent<HTMLElement>) => void
}

const MIN_WIDTH = 48
const MAX_WIDTH = 2000
const KEY_STEP = 16

function load(storageKey: string): Record<string, number> {
  try {
    const raw = localStorage.getItem(storageKey)
    const parsed: unknown = raw ? JSON.parse(raw) : null
    if (!parsed || typeof parsed !== 'object') return {}
    return Object.fromEntries(Object.entries(parsed as Record<string, unknown>).filter((e): e is [string, number] => typeof e[1] === 'number' && e[1] > 0))
  } catch {
    return {}
  }
}

/** Ширина ячейки заголовка, на правой границе которой ручка. */
function renderedWidth(handle: HTMLElement): number | null {
  const cell = handle.parentElement
  return cell ? Math.round(cell.getBoundingClientRect().width) : null
}

/**
 * Ширины колонок с перетаскиваемыми границами (см. пример в начале файла). Выбранные ширины хранятся в localStorage
 * под `storageKey`. Ручка: мышь тянет, двойной клик и Enter/Пробел возвращают ширину по умолчанию, стрелки ←/→ с фокуса —
 * ±16 px. `columns` — константа модуля (новый массив на каждый рендер пересчитывает всё зря).
 */
export function useColumnWidths<C extends string>(storageKey: string, columns: readonly ColumnDef<C>[]): ColumnWidths<C> {
  const [custom, setCustom] = useState<Record<string, number>>(() => load(storageKey))
  const [loadedKey, setLoadedKey] = useState(storageKey)
  const [dragging, setDragging] = useState<C | null>(null)
  const [container, setContainer] = useState(0)
  // Сумма остальных колонок для ширины резиновой по умолчанию — снимок, а не живое значение: иначе расширение соседней
  // колонки сжимало бы резиновую, и граница под мышью стояла бы на месте. Снимается заново при новом наборе колонок,
  // после «сбросить» и сброса самой резиновой колонки; изменение контейнера меняет только `container`.
  const [fillBase, setFillBase] = useState<{ columns: readonly ColumnDef<C>[]; others: number } | null>(null)
  const endDrag = useRef<(() => void) | null>(null)
  const byKey = useMemo(() => new Map(columns.map((c) => [c.key, c])), [columns])

  // Другой ключ — другие сохранённые ширины (подстройка состояния в рендере, без лишнего кадра со старыми).
  if (loadedKey !== storageKey) {
    setLoadedKey(storageKey)
    setCustom(load(storageKey))
    setFillBase(null)
  }

  // В хранилище — не на каждое движение мыши, а когда перетаскивание закончено (и сразу — после клавиш, двойного клика, «сбросить»).
  useEffect(() => {
    if (dragging !== null) return
    try {
      if (Object.keys(custom).length === 0) localStorage.removeItem(storageKey)
      else localStorage.setItem(storageKey, JSON.stringify(custom))
    } catch {
      // хранилище недоступно (приватное окно) — ширины живут до перезагрузки
    }
  }, [custom, dragging, storageKey])

  // Размонтирование посреди перетаскивания: снять слушатели и вернуть курсор.
  useEffect(() => () => endDrag.current?.(), [])

  const bounds = useCallback((col: C): [number, number] => {
    const c = byKey.get(col)
    return [c?.min ?? Math.min(MIN_WIDTH, c?.width ?? MIN_WIDTH), c?.max ?? MAX_WIDTH]
  }, [byKey])
  /** Сохранённая ширина или ширина по умолчанию, без заполнения контейнера. */
  const ownWidth = useCallback((col: C) => {
    const def = byKey.get(col)
    const stored = def?.resizable === false ? undefined : custom[col]
    if (stored === undefined) return def?.width ?? MIN_WIDTH
    const [min, max] = bounds(col)
    return Math.min(max, Math.max(min, stored))
  }, [byKey, custom, bounds])
  const others = columns.reduce((sum, c) => (c.flex ? sum : sum + ownWidth(c.key)), 0)
  if (fillBase === null || fillBase.columns !== columns) setFillBase({ columns, others })
  const fill = container - (fillBase?.others ?? others)
  const width = useCallback((col: C) => {
    const def = byKey.get(col)
    if (!def?.flex || (def.resizable !== false && custom[col] !== undefined)) return ownWidth(col)
    return Math.max(def.width, Math.min(bounds(col)[1], fill))
  }, [byKey, custom, ownWidth, bounds, fill])
  const set = useCallback((col: C, px: number) => {
    const [min, max] = bounds(col)
    setCustom((prev) => ({ ...prev, [col]: Math.min(max, Math.max(min, Math.round(px))) }))
  }, [bounds])
  const reset = useCallback(() => { setCustom({}); setFillBase(null) }, [])
  const resetColumn = useCallback((col: C) => {
    setCustom((prev) => { const next = { ...prev }; delete next[col]; return next })
    if (byKey.get(col)?.flex) setFillBase(null)
  }, [byKey])
  const setContainerWidth = useCallback((px: number) => setContainer(Math.max(0, Math.floor(px))), [])

  /** Слушатели документа — только на время перетаскивания. */
  function startDrag(col: C, startX: number, startWidth: number) {
    endDrag.current?.()
    const onMove = (e: MouseEvent) => set(col, startWidth + e.clientX - startX)
    const stop = () => {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', stop)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      endDrag.current = null
      setDragging(null)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', stop)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    endDrag.current = stop
    setDragging(col)
  }

  function handleProps(col: C, label?: string): HandleProps {
    const [min, max] = bounds(col)
    return {
      role: 'separator',
      'aria-orientation': 'vertical',
      'aria-label': `Ширина колонки «${label ?? byKey.get(col)?.label ?? col}»`,
      'aria-valuenow': width(col),
      'aria-valuemin': min,
      'aria-valuemax': max,
      tabIndex: 0,
      title: 'Потяните, чтобы изменить ширину; двойной клик — по умолчанию',
      onMouseDown: (e) => {
        if (e.button !== 0) return
        e.preventDefault()
        e.stopPropagation()
        // Отсчёт от видимой ширины — от того, что на экране.
        startDrag(col, e.clientX, renderedWidth(e.currentTarget) ?? width(col))
      },
      onDoubleClick: (e) => { e.preventDefault(); e.stopPropagation(); resetColumn(col) },
      onKeyDown: (e) => {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault()
          e.stopPropagation()
          set(col, (renderedWidth(e.currentTarget) ?? width(col)) + (e.key === 'ArrowRight' ? KEY_STEP : -KEY_STEP))
        }
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); resetColumn(col) }
      },
      // Заголовок бывает кликабельным (сортировка) — щелчок по ручке до него не доходит.
      onClick: (e) => e.stopPropagation(),
    }
  }

  const total = columns.reduce((sum, c) => sum + width(c.key), 0)
  const gridStyle: CSSProperties = {
    gridTemplateColumns: columns.map((c) => `${width(c.key)}px`).join(' '),
    minWidth: total,
  }
  const tableStyle: CSSProperties = { tableLayout: 'fixed', width: total }
  // Сохранённые ширины колонок, которых больше нет, «сбросить» не показывают.
  const customized = Object.keys(custom).some((k) => { const c = byKey.get(k as C); return !!c && c.resizable !== false })

  return { columns, width, handleProps, reset, resetColumn, customized, dragging, gridStyle, tableStyle, setContainerWidth }
}
