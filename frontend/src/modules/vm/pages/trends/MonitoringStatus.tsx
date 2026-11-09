import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Link } from '@/lib/router'
import { TREND_BASE, when } from '../../api/trends'
import { useMonitoring } from '../../api/trendMonitoring'
export function MonitoringStatus() {
  const collector = useMonitoring()
  const local = useQuery({ queryKey: ['vm-trends', 'status'], queryFn: () => api.get<{ cursor: number; received_at: string | null; processing: Record<string, number>; rebuilding: boolean }>(TREND_BASE + '/status'), refetchInterval: 15000 })
  return <details className="text-xs text-text-secondary"><summary>Состояние мониторинга</summary><div className="mt-2 space-y-1">{collector.error ? <p>Сборщик недоступен: {collector.error.message}</p> : <p>Сборщик: {collector.data?.info.last_seq ?? '—'} событий · {collector.data?.settings.collection_enabled ? 'опрос включён' : 'опрос выключен'}</p>}<p>STools: принято до {local.data?.cursor ?? 0} · {when(local.data?.received_at)} · ожидает анализа {local.data?.processing.pending ?? 0} · ошибок {local.data?.processing.error ?? 0}{local.data?.rebuilding ? ' · перечитывается история' : ''}</p><Link className="underline" to="/settings/vm#trends">Источники и диагностика</Link></div></details>
}
