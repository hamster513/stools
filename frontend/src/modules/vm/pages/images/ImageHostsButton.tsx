import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useInfiniteQuery } from '@tanstack/react-query'
import { Server, X } from 'lucide-react'
import { api, ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import type { ImageItem } from '@/modules/vm/api/types'

type Host = {
  hostname: string; ip: string; asset_id: number | null; host_updated_at: string;
  containers: { id: string; name: string; status: string }[]
}
type Response = {
  items: Host[]; total: number; count: number | null; state: string;
  collected_at: string | null; warning: string; mapping_error: string; offset: number; limit: number
}
const reasons: Record<string, string> = {
  mapping_missing: 'Для этого образа ещё не получены хеши сопоставления. Запустите синхронизацию Harbor; учётной записи нужен доступ к чтению образов (pull).',
  snapshot_missing: 'Снимок Docker из MaxPatrol VM ещё не получен. Запустите синхронизацию MaxPatrol VM.',
}

/** Portal avoids clipping by the virtual table's transformed rows. */
export function ImageHostsButton({ image }: { image: Pick<ImageItem, 'id' | 'name' | 'running_host_count' | 'artifact_kind'> }) {
  const [open, setOpen] = useState(false)
  const trigger = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLElement>(null)
  const close = useRef<HTMLButtonElement>(null)
  const { read: assetsRead } = useCan('assets')
  const query = useInfiniteQuery<Response, ApiRequestError>({
    queryKey: ['vm-image-hosts', image.id], initialPageParam: 0, enabled: open,
    queryFn: ({ pageParam }) => api.get(`/api/vm/images/${image.id}/hosts?limit=100&offset=${pageParam}`),
    getNextPageParam: (last) => last.offset + last.items.length < last.total ? last.offset + last.items.length : undefined,
  })
  useEffect(() => {
    if (!open) return
    close.current?.focus()
    const button = trigger.current
    return () => button?.focus()
  }, [open])
  const data = query.data?.pages[0]
  const count = image.running_host_count
  if (image.artifact_kind === 'helm' || image.artifact_kind === 'other') return <span className="text-text-secondary" title="Артефакт не запускается как контейнер">Не применяется</span>
  return <>
    <button ref={trigger} type="button"
      className="inline-flex min-h-8 items-center gap-1.5 rounded px-2 font-mono tabular-nums text-text underline decoration-dotted underline-offset-4 hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
      aria-label={`Хосты с запущенным образом ${image.name}: ${count ?? 'нет данных'}`}
      title="Хосты с запущенными контейнерами — открыть список"
      onClick={(event) => { event.stopPropagation(); setOpen(true) }}
      onKeyDown={(event) => event.stopPropagation()}>
      <Server size={13} aria-hidden />{count ?? '—'}
    </button>
    {open && createPortal(<div className="fixed inset-0 z-50" onClick={(event) => event.stopPropagation()}
      onKeyDown={(event) => {
        event.stopPropagation()
        if (event.key === 'Escape') { event.preventDefault(); setOpen(false); return }
        if (event.key !== 'Tab') return
        const controls = panel.current?.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], [tabindex="0"]')
        if (!controls?.length) return
        const first = controls[0], last = controls[controls.length - 1]
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
        if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
      }}>
      <div className="absolute inset-0 bg-black/50" aria-hidden onClick={() => setOpen(false)} />
      <aside ref={panel} role="dialog" aria-modal="true" aria-label="Хосты с запущенными контейнерами"
        className="absolute inset-y-0 right-0 flex w-[560px] max-w-full flex-col border-l border-grid bg-surface shadow-xl">
        <div className="flex items-start justify-between gap-3 border-b border-grid p-4">
          <div className="min-w-0"><h2 className="text-base font-semibold">Где запущен образ</h2><p className="mt-1 break-all font-mono text-xs text-text-secondary">{image.name}</p></div>
          <button ref={close} type="button" className="rounded p-2 text-text-secondary hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Закрыть список хостов" onClick={() => setOpen(false)}><X size={18} aria-hidden /></button>
        </div>
        <div className="flex-1 space-y-4 overflow-y-auto p-4 text-sm">
          <p className="text-text-secondary">Уникальные хосты, на которых MaxPatrol VM обнаружил контейнеры этого образа в состоянии running.</p>
          {query.isPending && <p role="status">Загрузка хостов…</p>}
          {query.isError && <p role="alert">{query.error.message} <Button onClick={() => query.refetch()}>Повторить</Button></p>}
          {data && <>
            {data.collected_at && <p className="text-xs text-text-secondary">Снимок MP VM: {new Date(data.collected_at).toLocaleString('ru-RU')}</p>}
            {data.warning && <p role="alert" className="rounded border border-risk-medium/40 p-3 text-risk-medium">Последний сбор не выполнен. Показаны прежние данные: {data.warning}</p>}
            {data.state !== 'ready' ? <p>{reasons[data.state] || 'Нет данных для сопоставления.'}</p>
              : <p>Хостов: <strong>{data.count}</strong>{data.count === 0 && '. В полученном снимке запущенных контейнеров с подтверждённым хешем образа не найдено.'}</p>}
            {query.data?.pages.flatMap((page) => page.items).map((host) => <section key={host.asset_id ?? `${host.hostname}|${host.ip}`} className="rounded border border-grid p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                {assetsRead && host.asset_id !== null
                  ? <Link className="break-all font-medium text-text underline" to={`/assets/list?asset=${host.asset_id}`} onNavigate={() => setOpen(false)}>{host.hostname}</Link>
                  : <span className="break-all font-medium">{host.hostname}</span>}
                <span className="font-mono text-xs text-text-secondary">{host.ip}</span>
              </div>
              {assetsRead && host.asset_id === null && <p className="mt-1 text-xs text-text-secondary">Хост ещё не сопоставлен с активом. Выполните синхронизацию активов.</p>}
              <ul className="mt-2 space-y-1 text-xs">{host.containers.map((container) => <li key={container.id} className="flex items-center justify-between gap-3"><span className="break-all font-mono" title={container.id}>{container.name || container.id}</span><span className="text-text-secondary">Запущен</span></li>)}</ul>
            </section>)}
            {query.hasNextPage && <Button loading={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}>Показать ещё</Button>}
          </>}
        </div>
        {assetsRead && <div className="border-t border-grid p-4 text-sm"><Link className="text-text underline" to={`/assets/container-images?source=harbor&image=${image.id}`} onNavigate={() => setOpen(false)}>Открыть образ в активах</Link></div>}
      </aside>
    </div>, document.body)}
  </>
}
