import { Server } from 'lucide-react'
import { useAssetLookup } from '@/modules/assets/api/queries'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

/**
 * Ссылка «в Assets» у хоста модуля антивируса или VM. Актив ищется по ключу наблюдения
 * (KSC — `server_id:host_id`, VM — `hostname|ip`); хост не сопоставлен — ссылки нет.
 */
export function AssetLink({ source, hostKey, onNavigate, className }: { source: 'ksc' | 'vm'; hostKey: string | null; onNavigate?: () => void; className?: string }) {
  const lookup = useAssetLookup(source, hostKey)
  if (!lookup.data) return null
  return (
    <Link to={`/assets/list?asset=${lookup.data.asset_id}`} onNavigate={onNavigate} className={cn('inline-flex items-center gap-1 text-text underline', className)} title="Карточка актива в реестре Assets">
      <Server size={12} aria-hidden /> в Assets
    </Link>
  )
}
