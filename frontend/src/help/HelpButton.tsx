import type { Ref } from 'react'
import { CircleHelp } from 'lucide-react'
import { cn } from '@/lib/cn'
import { HELP_PANEL_ID } from './layout'

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
        // Закрыта панель: над затемнением дровера (z-30), под самим дровером (z-40), чтобы его крестик оставался доступен.
        // Открыта: над панелью (z-[60]), чтобы вопросик закрывал её.
        'fixed top-3 right-3 flex h-8 w-8 items-center justify-center rounded-full border border-grid bg-surface text-text-secondary hover:bg-row-hover hover:text-text',
        open ? 'z-[60] bg-row-selected text-text' : 'z-[35]',
        FOCUS,
      )}
    >
      <CircleHelp size={18} aria-hidden />
    </button>
  )
}
