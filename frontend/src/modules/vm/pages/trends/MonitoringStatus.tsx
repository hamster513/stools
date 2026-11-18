import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Link } from '@/lib/router'
import { TREND_BASE, when } from '../../api/trends'
import { useMonitoring } from '../../api/trendMonitoring'

export function MonitoringStatus() {
  const [open, setOpen] = useState(false)
  return <details className="text-xs text-text-secondary" onToggle={e => setOpen(e.currentTarget.open)}>
    <summary>Состояние мониторинга</summary>{open && <MonitoringDetails />}
  </details>
}

function MonitoringDetails() {
  const local = useQuery({ queryKey: ['vm-trends', 'status'], queryFn: () => api.get<{
    mode: 'online' | 'offline'; cursor: number; received_at: string | null;
    processing: Record<string, number>; rebuilding: boolean
  }>(TREND_BASE + '/status'), refetchInterval: 15000 })
  const collector = useMonitoring(local.data?.mode === 'online')
  return <div className="mt-2 space-y-1">
    {local.data?.mode === 'offline' ? <p>Offline · данные загружаются из архивов. Опрос сборщика отключён.</p>
      : local.data?.mode === 'online' && (collector.error
        ? <p>Сборщик недоступен: {collector.error.message}</p>
        : <p>Сборщик: {collector.data?.info.last_seq ?? '—'} событий · {collector.data?.settings.collection_enabled ? 'опрос включён' : 'опрос выключен'}</p>)}
    {local.error && <p>Не удалось получить локальный статус: {local.error.message}</p>}
    <p>STools: принято до {local.data?.cursor ?? '—'} · {when(local.data?.received_at)} · ожидает анализа {local.data?.processing.pending ?? 0} · ошибок {local.data?.processing.error ?? 0}{local.data?.rebuilding ? ' · перечитывается история' : ''}</p>
    <Link className="underline" to="/settings/vm#trends">Источники и диагностика</Link>
  </div>
}
