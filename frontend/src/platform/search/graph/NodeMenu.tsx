import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { EyeOff, GitBranch } from 'lucide-react'
import type { GraphNode, Point } from './model'
export interface MenuState { node: GraphNode; point: Point; trigger: Element }
export function NodeMenu({ menu, canExpand, canHide, onExpand, onHide, onClose }: { menu: MenuState; canExpand: boolean; canHide: boolean; onExpand: () => void; onHide: () => void; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const previous = menu.trigger
    const focusTarget = ref.current?.querySelector<HTMLButtonElement>('button:not(:disabled)') ?? ref.current
    focusTarget?.focus({ preventScroll: true })
    const pointer = (event: PointerEvent) => { if (!ref.current?.contains(event.target as Node)) onClose() }
    const dismiss = () => onClose()
    document.addEventListener('pointerdown', pointer)
    window.addEventListener('resize', dismiss)
    window.addEventListener('scroll', dismiss, true)
    return () => {
      document.removeEventListener('pointerdown', pointer); window.removeEventListener('resize', dismiss); window.removeEventListener('scroll', dismiss, true)
      if (previous.isConnected && previous instanceof Element && 'focus' in previous) (previous as HTMLElement).focus({ preventScroll: true })
    }
  }, [menu.trigger, onClose])
  return createPortal(<div ref={ref} role="menu" tabIndex={-1} aria-label={`Действия: ${menu.node.title}`} className="fixed z-50 w-48 rounded border border-border bg-surface p-1 shadow-xl" style={{ left: Math.max(8, Math.min(menu.point.x, window.innerWidth - 200)), top: Math.max(8, Math.min(menu.point.y, window.innerHeight - 110)) }}
    onKeyDown={e => {
      if (e.key === 'Escape' || e.key === 'Tab') { if (e.key === 'Escape') e.preventDefault(); onClose() }
      if (['ArrowDown','ArrowUp','Home','End'].includes(e.key)) {
        e.preventDefault()
        const items = [...(ref.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])]
        if (!items.length) return
        const index = items.findIndex(item => item === document.activeElement)
        const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : (index + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length
        items[next]?.focus()
      }
    }}>
    <button role="menuitem" disabled={!canExpand} onClick={onExpand} className="flex min-h-11 w-full items-center gap-2 rounded px-3 text-left text-sm hover:bg-row-hover focus-visible:bg-row-selected focus-visible:outline-none disabled:opacity-40"><GitBranch size={16} aria-hidden />Раскрыть</button>
    <button role="menuitem" disabled={!canHide} onClick={onHide} className="flex min-h-11 w-full items-center gap-2 rounded px-3 text-left text-sm hover:bg-row-hover focus-visible:bg-row-selected focus-visible:outline-none disabled:opacity-40"><EyeOff size={16} aria-hidden />Скрыть</button>
  </div>, document.body)
}
