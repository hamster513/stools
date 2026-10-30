import { useEffect, useRef, useState } from 'react'
import { ChevronDown, X } from 'lucide-react'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useHostDetail, useHosts } from '../../api/queries'

export function HostPicker({ snapshotId, value, onChange }: { snapshotId: number; value?: string; onChange: (id: string | undefined) => void }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const q = useDebouncedValue(search, 250)
  const root = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const button = useRef<HTMLButtonElement>(null)
  const selected = useHostDetail(snapshotId, value)
  const hosts = useHosts(open ? snapshotId : undefined, { q: q || undefined })
  useEffect(() => {
    if (!open) return
    input.current?.focus()
    const outside = (event: MouseEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', outside)
    return () => document.removeEventListener('mousedown', outside)
  }, [open])
  const close = () => { setOpen(false); button.current?.focus() }
  const label = value ? selected.data?.name || value : 'Все хосты'
  return <div ref={root} className="relative flex items-center gap-1" onKeyDown={e => { if (e.key === 'Escape' && open) { e.stopPropagation(); close() } }}>
    <button ref={button} type="button" aria-expanded={open} aria-haspopup="dialog" onClick={() => setOpen(!open)} className="flex max-w-64 items-center gap-2 rounded border border-border px-2 py-1.5 text-xs text-text hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-focus-ring">
      <span className="truncate">Хост: {label}</span><ChevronDown size={12} aria-hidden />
    </button>
    {value && <button type="button" aria-label="Снять фильтр хоста" onClick={() => onChange(undefined)} className="rounded p-1 text-text-secondary hover:text-text focus-visible:ring-2 focus-visible:ring-focus-ring"><X size={14} aria-hidden /></button>}
    {open && <div role="dialog" aria-label="Выбор хоста" className="absolute top-full left-0 z-30 mt-1 w-80 max-w-[calc(100vw-2rem)] rounded border border-border bg-surface p-2 shadow-lg">
      <input ref={input} aria-label="Поиск хоста" placeholder="Имя или адрес хоста" value={search} onChange={e => setSearch(e.target.value)} className="mb-2 w-full rounded border border-border bg-app-bg px-2 py-1.5 text-xs text-text focus-visible:ring-2 focus-visible:ring-focus-ring" />
      <div className="max-h-64 overflow-y-auto text-xs">
        {(hosts.isLoading || hosts.isPlaceholderData) && <p className="p-2 text-text-secondary" role="status">Загрузка хостов…</p>}
        {hosts.isError && <button type="button" onClick={() => hosts.refetch()} className="p-2 text-risk-medium">Не удалось загрузить хосты. Повторить</button>}
        {!hosts.isPlaceholderData && !hosts.isError && hosts.data?.pages.flatMap(p => p.items).map(host => <button key={host.host_id} type="button" onClick={() => { onChange(host.host_id); close() }} className="block w-full rounded p-2 text-left text-text hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-focus-ring">
          <span className="block break-all">{host.name || host.host_id}</span><span className="text-text-secondary">{host.ip || 'Адрес не получен'}</span>
        </button>)}
        {hosts.data?.pages[0]?.total === 0 && <p className="p-2 text-text-secondary">Хосты не найдены</p>}
        {hosts.hasNextPage && <button type="button" onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage} className="w-full rounded p-2 text-primary focus-visible:ring-2 focus-visible:ring-focus-ring">{hosts.isFetchingNextPage ? 'Загрузка…' : 'Показать ещё'}</button>}
      </div>
    </div>}
  </div>
}
