import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useQuery } from '@tanstack/react-query'
import { Box, X } from 'lucide-react'
import { api, ApiRequestError } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { AssetLink } from '../../AssetLink'
import { RegistryBadge } from './RegistryBadge'
import { CONTAINER_STATES, SOURCES, STATES, sizeText, when, type Detail, type Image } from './types'

export type ImageRef = Pick<Image, 'source' | 'id' | 'title'> & Partial<Pick<Image, 'collected_at' | 'display_title'>>

function ImageDetail({ image }: { image: ImageRef }) {
  const { read: vmRead } = useCan('vm')
  const query = useQuery<Detail, ApiRequestError>({
    queryKey: ['assets-container-image', image.source, image.id, image.collected_at],
    queryFn: () => api.get(`/api/assets/container-images/${image.source}/${image.id}`),
  })
  if (query.isPending) return <p role="status">Загрузка сведений…</p>
  if (query.isError) return <ErrorState message={query.error.message} onRetry={() => query.refetch()} />
  const detail = query.data
  return <div className="space-y-4">
    {(detail.registry_origin === 'external' || detail.registry_origin === 'mixed') && <p className="rounded border border-risk-medium/40 bg-risk-medium/5 p-3 text-xs text-risk-medium">
      {detail.registry_origin === 'mixed' ? 'У образа есть ссылки на корпоративный и внешние реестры.' : 'У образа указан реестр вне корпоративного Harbor.'}
      {' '}Внешние реестры: <span className="break-all font-mono">{detail.external_registries.join(', ')}</span>.
    </p>}
    <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-[max-content_1fr]">
      <dt className="text-text-secondary">Источник</dt><dd className="break-all">{SOURCES[detail.source]}{detail.source_address && detail.source_address !== SOURCES[detail.source] ? ` · ${detail.source_address}` : ''}</dd>
      <dt className="text-text-secondary">{detail.hash_kind}</dt><dd className="select-all break-all font-mono">{detail.image_id || 'Не передан источником'}</dd>
      <dt className="text-text-secondary">Реестр</dt><dd><RegistryBadge origin={detail.registry_origin} external={detail.external_registries} /><div className="mt-1 break-all font-mono text-text-secondary">{detail.registries?.join(", ") || "Адрес не передан"}</div></dd>
      <dt className="text-text-secondary">Получено в STools</dt><dd>{when(detail.collected_at)}</dd>
      <dt className="text-text-secondary">Платформа</dt><dd>{detail.platforms.join(', ') || '—'}</dd>
      <dt className="text-text-secondary">Размер</dt><dd>{sizeText(detail.size)}</dd>
      {detail.source === 'harbor' && <><dt className="text-text-secondary">Загружен в Harbor</dt><dd>{when(detail.pushed_at)}</dd></>}
    </dl>
    {!!detail.references.length && <div className="flex flex-wrap gap-2" aria-label="Имена и теги образа">
      {detail.references.map((r, i) => <span className="max-w-full break-all rounded border border-grid px-2 py-1 font-mono text-xs" key={i}>
        {[r.registry, r.repo].filter(Boolean).join('/')}{r.tag ? `:${r.tag}` : ''}
      </span>)}
    </div>}
    {detail.source === 'harbor' && <div className="space-y-2 text-xs text-text-secondary">
      <p>Harbor сообщает о наличии образа в реестре. Сведений о запуске на серверах у этого источника нет.</p>
      {detail.sync_error && <p role="alert">Ошибка последнего обновления: {detail.sync_error}</p>}
      {vmRead && <Link className="text-text underline" to={`/vm/images/${image.id}`}>Уязвимости и сканирование образа</Link>}
    </div>}
    {detail.hosts.map((host) => <section key={`${host.hostname}|${host.ip}`} className="rounded border border-grid bg-surface p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <h3 className="font-semibold">{host.hostname}</h3><span className="font-mono text-text-secondary">{host.ip}</span>
        <AssetLink source="vm" hostKey={`${host.hostname}|${host.ip}`} />
        <span className="ml-auto">{STATES[host.status]}</span>
      </div>
      <p className="mt-1 text-xs text-text-secondary">{host.os_name ? `${host.os_name} · ` : ''}Хост обновлён в MP VM: {when(host.host_updated_at)}</p>
      {!host.containers.length && <p className="mt-3 text-xs text-text-secondary">{host.status === 'unused'
        ? 'Образ есть на сервере; в полученном снимке использующих его контейнеров нет.'
        : 'На сервере есть контейнеры с неопределённым образом. Использование этого образа установить нельзя.'}</p>}
      {!!host.containers.length && <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-xs">
        <thead className="text-xs text-text-secondary"><tr><th className="p-2">Контейнер / ID</th><th className="p-2">Состояние</th><th className="p-2">Создан / запущен</th><th className="p-2">Порты сервера → контейнера</th></tr></thead>
        <tbody>{host.containers.map((c) => <tr key={c.id} className="border-t border-grid align-top">
          <td className="p-2"><div>{c.name || 'Без имени'}</div><div className="max-w-80 select-all break-all font-mono text-xs text-text-secondary">{c.id}</div></td>
          <td className="p-2"><div>{CONTAINER_STATES[c.status] || c.status || 'Нет данных'}</div>{c.status && <div className="font-mono text-xs text-text-secondary">{c.status}</div>}</td>
          <td className="whitespace-nowrap p-2"><div>{when(c.created_at)}</div><div className="text-text-secondary">{when(c.started_at)}</div></td>
          <td className="p-2 font-mono text-xs">{c.ports.length ? c.ports.map((p, i) => <div key={i}>{p.host_ports || '—'} → {p.container_port || '—'}{p.protocol ? `/${p.protocol}` : ''}</div>) : '—'}</td>
        </tr>)}</tbody>
      </table></div>}
    </section>)}
  </div>
}

export function ImageDrawer({ image, onClose }: { image: ImageRef; onClose: () => void }) {
  const close = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLElement>(null)
  const body = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
    close.current?.focus()
    return () => { if (previous?.isConnected) previous.focus() }
  }, [])
  useEffect(() => { body.current?.scrollTo({ top: 0 }) }, [image.source, image.id])
  return createPortal(<div onKeyDown={(event) => {
    event.stopPropagation()
    if (event.key === 'Escape') { event.preventDefault(); onClose() }
    if (event.key === 'Tab') {
      const controls = panel.current?.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], [tabindex="0"]')
      if (!controls?.length) return
      const first = controls[0], last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
  }}>
    <div className="fixed inset-0 z-30 bg-black/50" onClick={onClose} aria-hidden />
    <aside ref={panel} role="dialog" aria-modal="true" aria-label="Образ контейнера" className="fixed top-0 right-0 z-40 flex h-full w-[600px] max-w-full flex-col border-l border-grid bg-surface">
      <div className="flex items-center justify-between gap-2 border-b border-grid px-4 py-3">
        <div className="flex min-w-0 items-center gap-2"><Box size={16} className="shrink-0 text-text-secondary" aria-hidden /><span className="truncate text-sm text-text" title={image.display_title || image.title}>{image.display_title || image.title}</span></div>
        <button ref={close} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
      </div>
      <div ref={body} className="flex-1 overflow-y-auto px-4 py-3 text-xs"><ImageDetail image={image} /></div>
    </aside>
  </div>, document.body)
}
