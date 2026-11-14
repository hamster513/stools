import { useEffect, useRef, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Package, X } from 'lucide-react'
import { api, buildQuery, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { Link } from '@/lib/router'
import { useCan } from '@/lib/can'
import { PAGE_SIZE, SoftwarePager } from './SoftwarePager'

interface Version { version: string; host_count: number }
interface Host { host_key: string; asset_id: number | null; name: string; versions: string[]; server_id: number; host_id: string; collected_at: string }
export const productName = (key: string) => key.startsWith('@unnamed:') ? 'Без названия' : key.replaceAll('_', ' ')
const versionName = (version: string) => version || 'Версия не указана'

export function SoftwareProductDrawer({ vendorKey, productKey, onClose }: { vendorKey: string; productKey: string; onClose: () => void }) {
  const av = useCan('ksc')
  const [version, setVersion] = useState<string | null>(null)
  const [versionsOffset, setVersionsOffset] = useState(0)
  const [hostsOffset, setHostsOffset] = useState(0)
  const closeRef = useRef<HTMLButtonElement>(null)
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    const previous = document.activeElement
    closeRef.current?.focus()
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') { event.preventDefault(); close.current() } }
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('keydown', escape); if (previous instanceof HTMLElement && previous.isConnected) previous.focus() }
  }, [])
  const keys = { vendor_key: vendorKey, product_key: productKey }
  const versions = useQuery<{ items: Version[]; total: number }>({
    queryKey: ['assets-software-versions', vendorKey, productKey, versionsOffset],
    queryFn: () => api.get(`/api/assets/software/versions${buildQuery({ ...keys, limit: PAGE_SIZE, offset: versionsOffset })}`),
    placeholderData: keepPreviousData,
  })
  const hosts = useQuery<{ items: Host[]; total: number }>({
    queryKey: ['assets-software-hosts', vendorKey, productKey, version, hostsOffset],
    // Empty version is a real group. buildQuery omits empty strings, so append it explicitly.
    queryFn: () => api.get(`/api/assets/software/hosts${buildQuery({ ...keys, limit: PAGE_SIZE, offset: hostsOffset })}${version === null ? '' : `&version=${encodeURIComponent(version)}`}`),
    placeholderData: keepPreviousData,
  })
  function selectVersion(value: string | null) { setVersion(value); setHostsOffset(0) }
  return <>
    <div className="fixed inset-0 z-30 bg-black/50" onClick={onClose} aria-hidden />
    <aside role="dialog" aria-label="Установки ПО" className="fixed top-0 right-0 z-40 flex h-full w-[960px] max-w-[calc(100vw-2rem)] flex-col border-l border-grid bg-surface text-text">
      <header className="flex items-start justify-between gap-3 border-b border-grid p-4">
        <div className="min-w-0"><h2 className="flex items-center gap-2 break-all text-sm font-semibold"><Package size={16} aria-hidden />{productName(productKey)}</h2><p className="mt-1 text-xs text-text-secondary">{vendorKey.replaceAll('_', ' ') || 'Издатель неизвестен'}</p></div>
        <Button ref={closeRef} aria-label="Закрыть ПО" variant="ghost" onClick={onClose}><X size={16} aria-hidden /></Button>
      </header>
      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4 text-xs">
        <section aria-label="Версии ПО" className="space-y-2">
          <h3 className="font-semibold">Версии{versions.data ? ` · ${versions.data.total}` : ''}</h3>
          <Button variant={version === null ? 'primary' : 'secondary'} aria-pressed={version === null} onClick={() => selectVersion(null)}>Все версии</Button>
          {versions.isError ? <ErrorState message={errorText(versions.error, 'Не удалось загрузить версии') ?? 'Не удалось загрузить версии'} onRetry={() => versions.refetch()} /> : !versions.data ? <Spinner /> : <>
            {versions.isFetching && <p role="status">Обновление версий…</p>}
            <div className="max-h-52 overflow-auto rounded border border-grid">
              {versions.data.items.map((item) => <button key={item.version} type="button" aria-pressed={version === item.version} onClick={() => selectVersion(item.version)} className={`flex w-full items-center justify-between gap-3 border-b border-grid p-2 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${version === item.version ? 'bg-row-selected' : ''}`}>
                <span className="break-all font-mono">{versionName(item.version)}</span><span className="shrink-0 text-text-secondary">Хостов: {item.host_count}</span>
              </button>)}
              {versions.data.total === 0 && <p className="p-3 text-text-secondary">В актуальных инвентарях этот продукт больше не найден.</p>}
            </div>
            <SoftwarePager label="Страницы версий" offset={versionsOffset} total={versions.data.total} busy={versions.isFetching} onChange={setVersionsOffset} />
          </>}
        </section>
        <section aria-label="Хосты с ПО" className="space-y-2">
          <h3 className="font-semibold">Хосты · {version === null ? 'Все версии' : versionName(version)}</h3>
          <p className="text-text-secondary">Один хост показан один раз. Для нескольких источников KSC версии объединены; дата — последний сбор среди этих источников.</p>
          {hosts.isError ? <ErrorState message={errorText(hosts.error, 'Не удалось загрузить хосты') ?? 'Не удалось загрузить хосты'} onRetry={() => hosts.refetch()} /> : !hosts.data ? <Spinner /> : <>
            {hosts.isFetching && <p role="status">Обновление хостов…</p>}
            <div className="overflow-x-auto"><table className="w-full text-left text-xs">
              <caption className="sr-only">Хосты, где установлено ПО</caption>
              <thead className="text-text-secondary"><tr>{['Хост', 'Установленные версии', 'Последний сбор'].map((label) => <th key={label} scope="col" className="p-2 font-medium">{label}</th>)}</tr></thead>
              <tbody>{hosts.data.items.map((host) => <tr key={host.host_key} className="border-t border-grid align-top">
                <td className="break-words p-2">{host.asset_id !== null ? <Link className="underline" to={`/assets/list?asset=${host.asset_id}`}>{host.name}</Link> : av.read ? <Link className="underline" to={`/ksc/servers/${host.server_id}/hosts?host=${encodeURIComponent(host.host_id)}`}>{host.name} · AV</Link> : host.name}{host.asset_id === null && <p className="mt-1 text-text-secondary">Нет связанной карточки в Хостах · KSC #{host.server_id}</p>}</td>
                <td className="break-all p-2 font-mono">{host.versions.map(versionName).join(', ')}</td>
                <td className="p-2 text-text-secondary">{new Date(host.collected_at).toLocaleString('ru-RU')}</td>
              </tr>)}</tbody>
            </table></div>
            {hosts.data.total === 0 && <p className="text-text-secondary">Хостов с выбранной версией в последних инвентарях нет.</p>}
            <SoftwarePager label="Страницы хостов с ПО" offset={hostsOffset} total={hosts.data.total} busy={hosts.isFetching} onChange={setHostsOffset} />
          </>}
        </section>
      </div>
    </aside>
  </>
}
