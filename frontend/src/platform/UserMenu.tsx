import { useEffect, useRef, useState, type Ref } from 'react'
import { CircleHelp, LogOut, Moon, Sun } from 'lucide-react'
import { useLogout, useMe } from '@/api/auth'
import { useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { useThemeChoice } from '@/lib/useThemeChoice'
import { HELP_PANEL_ID } from '@/help/layout'

const FOCUS =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-inset'
const ITEM =
  'flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Меню пользователя внизу рейки: логин — кнопка, по нажатию справа всплывает
 * маленькое меню с тем, что относится к сидящему за экраном, а не к модулю:
 * подсказка по текущей странице, тема и выход. Тема — не настройка
 * администратора, менять её надо там, где сидишь. Закрывается по клику вне,
 * `Esc` и после выбора пункта.
 */
export function UserMenu({
  helpOpen,
  onHelp,
  helpButtonRef,
}: {
  helpOpen: boolean
  onHelp: () => void
  /** Кнопка-логин: панель справки возвращает на неё фокус при закрытии. */
  helpButtonRef: Ref<HTMLButtonElement>
}) {
  const { data: me } = useMe()
  const { navigate } = useRouter()
  const logout = useLogout()
  const appearance = useThemeChoice()
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onPointer(e: PointerEvent) {
      if (!root.current?.contains(e.target as Node)) setOpen(false)
    }
    // Esc закрывает меню и не доходит до обработчиков страницы (те сворачивают карточку).
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setOpen(false)
      }
    }
    document.addEventListener('pointerdown', onPointer)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('pointerdown', onPointer)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  const dark = appearance.theme === 'dark'
  return (
    <div ref={root} className="relative w-full">
      <button
        ref={helpButtonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Меню пользователя ${me?.login ?? ''}`.trim()}
        title={me?.display_name ?? me?.login}
        className={cn(
          'flex w-full justify-center rounded px-1 py-1.5 font-mono text-[10px] text-text-secondary hover:bg-row-hover hover:text-text',
          open && 'bg-row-selected text-text',
          FOCUS,
        )}
      >
        <span className="max-w-full truncate">{me?.login ?? '—'}</span>
      </button>
      {open && (
        <div
          role="menu"
          aria-label="Меню пользователя"
          className="absolute bottom-0 left-full z-30 ml-1 w-48 rounded border border-border bg-surface p-1 shadow-lg"
        >
          <button
            role="menuitem"
            type="button"
            aria-controls={HELP_PANEL_ID}
            aria-expanded={helpOpen}
            onClick={() => {
              setOpen(false)
              onHelp()
            }}
            className={ITEM}
          >
            <CircleHelp size={14} aria-hidden />
            {helpOpen ? 'Закрыть справку' : 'Справка по странице'}
          </button>
          <button
            role="menuitem"
            type="button"
            onClick={() => {
              setOpen(false)
              appearance.choose(dark ? 'light' : 'dark')
            }}
            className={ITEM}
          >
            {dark ? <Sun size={14} aria-hidden /> : <Moon size={14} aria-hidden />}
            {dark ? 'Светлая тема' : 'Тёмная тема'}
          </button>
          <button
            role="menuitem"
            type="button"
            onClick={() => {
              setOpen(false)
              logout.mutate(undefined, { onSuccess: () => navigate('/login', { replace: true }) })
            }}
            className={ITEM}
          >
            <LogOut size={14} aria-hidden />
            Выйти
          </button>
        </div>
      )}
    </div>
  )
}
