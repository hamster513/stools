import { useRef, useState } from 'react'
import { Shield } from 'lucide-react'
import { Link } from '@/lib/router'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-inset'
const ITEM = `block rounded px-2 py-1.5 text-xs text-text hover:bg-row-hover ${FOCUS}`

export function AppSwitcher({ home, irp }: { home: string; irp: boolean }) {
  const [open, setOpen] = useState(false)
  const trigger = useRef<HTMLButtonElement>(null)

  return (
    <div
      className="relative border-b border-grid"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false)
      }}
      onKeyDown={(event) => {
        if (open && event.key === 'Escape') {
          event.stopPropagation()
          setOpen(false)
          trigger.current?.focus()
        }
      }}
    >
      <button
        ref={trigger}
        type="button"
        className={`flex h-14 w-full flex-col items-center justify-center gap-0.5 text-primary hover:bg-row-hover ${FOCUS}`}
        aria-label="Переключить приложение"
        aria-expanded={open}
        title="Переключить приложение"
        onClick={() => setOpen(!open)}
      >
        <Shield size={22} strokeWidth={2} aria-hidden />
        <span className="text-[10px] font-semibold tracking-wide text-text">STools</span>
      </button>
      {open && (
        <div className="absolute left-full top-0 z-30 ml-1 w-36 rounded border border-border bg-surface p-1 shadow-lg">
          <Link to={home} className={ITEM} onNavigate={() => setOpen(false)}>STools</Link>
          {irp && <a href="/irp/" className={ITEM}>IRP</a>}
        </div>
      )}
    </div>
  )
}
