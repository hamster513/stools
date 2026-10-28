import { useEffect, useRef, useState } from 'react'
import { ChevronDown, Download } from 'lucide-react'
import { cn } from '@/lib/cn'

/** Потолок XLSX на сервере (api/platform/export.py, XLSX_MAX_ROWS): дальше — строка-предупреждение и обрыв. */
const XLSX_MAX_ROWS = 100_000

const ITEM = 'block rounded px-2 py-1.5 text-xs text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Правило платформы для каждого списка: кнопка «Экспорт» рядом с «Фильтры»
 * выгружает список с текущими фильтрами и сортировкой (без страницы) в CSV
 * или XLSX. Выгрузку собирает сервер — `href(format)` даёт адрес ручки
 * `…/export?format=` с теми же параметрами, что у списка. Ссылка `download`:
 * браузер скачивает файл, страница остаётся на месте. Пока список грузится,
 * фильтр ещё не применён — кнопка неактивна.
 */
export function ExportButton({ href, total, disabled, title = 'Выгрузить список с текущими фильтрами' }: {
  href: (fmt: 'csv' | 'xlsx') => string
  total?: number | null
  disabled?: boolean
  title?: string
}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)

  // Пока список грузится, выгрузка недоступна; меню закрывается, чтобы не открыться само после загрузки.
  useEffect(() => { if (disabled) setOpen(false) }, [disabled])

  useEffect(() => {
    if (!open) return
    function onPointer(e: PointerEvent) { if (!root.current?.contains(e.target as Node)) setOpen(false) }
    // Esc закрывает меню и не доходит до обработчиков списка (те сворачивают карточку).
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') { e.stopPropagation(); setOpen(false) } }
    document.addEventListener('pointerdown', onPointer)
    document.addEventListener('keydown', onKey, true)
    return () => { document.removeEventListener('pointerdown', onPointer); document.removeEventListener('keydown', onKey, true) }
  }, [open])

  const capped = total != null && total > XLSX_MAX_ROWS
  return (
    <div ref={root} className="relative">
      <button type="button" onClick={() => setOpen((v) => !v)} disabled={disabled} aria-haspopup="menu" aria-expanded={open}
        title={title}
        className={cn('flex items-center gap-1.5 rounded border border-border px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:cursor-not-allowed disabled:opacity-50', open ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text')}>
        <Download size={13} aria-hidden /> Экспорт <ChevronDown size={12} aria-hidden />
      </button>
      {open && !disabled && (
        <div role="menu" className="absolute top-full left-0 z-30 mt-1 w-56 rounded border border-border bg-surface p-1 shadow-lg">
          <a role="menuitem" href={href('csv')} download className={ITEM} onClick={() => setOpen(false)}>CSV</a>
          <a role="menuitem" href={href('xlsx')} download className={ITEM} onClick={() => setOpen(false)}>
            XLSX
            {capped && <span className="mt-0.5 block text-[11px] text-text-secondary">будут выгружены первые 100 000 строк</span>}
          </a>
        </div>
      )}
    </div>
  )
}
