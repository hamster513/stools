import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, errorText } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { HostSoftwarePanel } from '@/platform/software/HostSoftwarePanel'
import { inventoryEmptyText, type InventoryStatus } from './softwareState'

interface Source {
  server_id: number; snapshot_id: number | null; host_id: string; host_name: string;
  collected_at: string | null; status: InventoryStatus; error: string | null;
}
const key = (source: Source) => `${source.server_id}:${source.host_id}`

export function SoftwareInventory({ assetId }: { assetId: number }) {
  const { read } = useCan('assets')
  const [selected, setSelected] = useState('')
  const query = useQuery<{ inventories: Source[] }>({
    queryKey: ['assets-software', assetId, 'sources'],
    queryFn: () => api.get(`/api/assets/assets/${assetId}/software?limit=1`),
    enabled: read,
  })
  if (!read) return null
  if (query.isError) return <ErrorState message={errorText(query.error, 'Не удалось загрузить источники ПО') ?? 'Не удалось загрузить источники ПО'} onRetry={() => query.refetch()} />
  if (!query.data) return <div className="flex justify-center py-8"><Spinner /></div>
  const sources = query.data.inventories
  const source = sources.find((item) => key(item) === selected) ?? sources[0]
  if (!source) return <p role="status" className="text-text-secondary">{inventoryEmptyText([], false)} Нужен актуальный источник KSC с инвентаризацией ПО.</p>
  return <div className="space-y-3">
    {sources.length > 1 ? <label className="block text-text-secondary">Источник инвентаря ПО
      <select className={`${FIELD} mt-1 w-full`} value={key(source)} onChange={(e) => setSelected(e.target.value)}>
        {sources.map((item) => <option key={key(item)} value={key(item)}>KSC #{item.server_id} · {item.host_name || item.host_id}{item.collected_at ? ` · ${new Date(item.collected_at).toLocaleString('ru-RU')}` : ''}</option>)}
      </select>
      <span className="mt-1 block">У хоста несколько источников KSC. Сводка и CVE относятся к выбранному источнику.</span>
    </label> : <p className="text-text-secondary">KSC #{source.server_id} · {source.host_name || source.host_id}</p>}
    <HostSoftwarePanel key={`${key(source)}:${source.snapshot_id}`} endpoint={`/api/assets/assets/${assetId}/software/assessment`} source={{ server_id: source.server_id, host_id: source.host_id }} />
  </div>
}
