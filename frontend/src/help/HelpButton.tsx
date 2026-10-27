import type { Ref } from 'react'
import { CircleHelp } from 'lucide-react'
import { cn } from '@/lib/cn'
import { HELP_PANEL_ID } from './panelId'

// Тот же класс фокуса, что в рейке модулей (platform/ModuleRail.tsx).
const FOCUS =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-inset'

/** Вопросик в правом верхнем углу окна: открывает и закрывает панель справки. */
export function HelpButton({ open, onToggle, buttonRef }: { open: boolean; onToggle: () => void; buttonRef: Ref<HTMLButtonElement> }) {
  return (
    <button
      ref={buttonRef}
      type="button"
      onClick={onToggle}
      aria-label="Справка"
      title="Справка по этой странице"
      aria-pressed={open}
      aria-expanded={open}
      aria-controls={HELP_PANEL_ID}
      className={cn(
        'fixed top-3 right-3 z-50 flex h-8 w-8 items-center justify-center rounded-full border border-grid bg-surface text-text-secondary hover:bg-row-hover hover:text-text',
        open && 'bg-row-selected text-text',
        FOCUS,
      )}
    >
      <CircleHelp size={18} aria-hidden />
    </button>
  )
}
