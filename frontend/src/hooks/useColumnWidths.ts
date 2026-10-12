import { useCallback, useEffect, useRef, useState } from 'react'

const MIN_WIDTH = 48
const KEY_STEP = 16

function load(storageKey: string): Record<string, number> {
  try {
    const raw = localStorage.getItem(storageKey)
    const parsed: unknown = raw ? JSON.parse(raw) : null
    if (!parsed || typeof parsed !== 'object') return {}
    return Object.fromEntries(Object.entries(parsed as Record<string, unknown>).filter((e): e is [string, number] => typeof e[1] === 'number' && e[1] >= MIN_WIDTH))
  } catch {
    return {}
  }
}

/**
 * Ширины колонок таблицы с перетаскиваемыми границами. `defaults` — ширина каждой колонки в пикселях; выбранные
 * пользователем ширины хранятся в localStorage под `storageKey` (удобство на этом устройстве, не состояние).
 * `handleProps(col)` — свойства ручки на правой границе заголовка: мышь тянет, стрелки ←/→ с фокуса меняют на 16 px,
 * Enter/Пробел возвращают ширину по умолчанию; `reset()` — все ширины по умолчанию.
 */
export function useColumnWidths<C extends string>(storageKey: string, defaults: Record<C, number>) {
  const [custom, setCustom] = useState<Record<string, number>>(() => load(storageKey))
  const drag = useRef<{ col: C; startX: number; startWidth: number } | null>(null)

  useEffect(() => {
    try {
      if (Object.keys(custom).length === 0) localStorage.removeItem(storageKey)
      else localStorage.setItem(storageKey, JSON.stringify(custom))
    } catch {
      // хранилище недоступно (приватное окно) — ширины живут до перезагрузки
    }
  }, [custom, storageKey])

  const width = useCallback((col: C) => custom[col] ?? defaults[col], [custom, defaults])
  const set = useCallback((col: C, px: number) => setCustom((prev) => ({ ...prev, [col]: Math.max(MIN_WIDTH, Math.round(px)) })), [])
  const reset = useCallback(() => setCustom({}), [])

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!drag.current) return
      set(drag.current.col, drag.current.startWidth + e.clientX - drag.current.startX)
    }
    function onUp() {
      if (!drag.current) return
      drag.current = null
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
    return () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp) }
  }, [set])

  function handleProps(col: C, label: string) {
    return {
      role: 'separator' as const,
      'aria-orientation': 'vertical' as const,
      'aria-label': `Ширина колонки «${label}»`,
      'aria-valuenow': width(col),
      tabIndex: 0,
      onMouseDown: (e: React.MouseEvent) => {
        e.preventDefault()
        e.stopPropagation()
        drag.current = { col, startX: e.clientX, startWidth: width(col) }
        document.body.style.cursor = 'col-resize'
        document.body.style.userSelect = 'none'
      },
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') { e.preventDefault(); set(col, width(col) + (e.key === 'ArrowRight' ? KEY_STEP : -KEY_STEP)) }
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCustom((prev) => { const next = { ...prev }; delete next[col]; return next }) }
      },
      onClick: (e: React.MouseEvent) => e.stopPropagation(),
      className: 'absolute top-0 right-0 h-full w-2 cursor-col-resize select-none hover:bg-primary/40 focus-visible:bg-primary/40 focus-visible:outline-none',
    }
  }

  return { width, handleProps, reset, customized: Object.keys(custom).length > 0 }
}
