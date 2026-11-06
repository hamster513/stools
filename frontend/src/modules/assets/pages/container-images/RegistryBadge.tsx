import { TriangleAlert } from 'lucide-react'
import { cn } from '@/lib/cn'
import type { RegistryOrigin } from './types'

const LABELS: Record<RegistryOrigin, string> = {
  corporate: 'Корпоративный', external: 'Внешний реестр', mixed: 'Есть внешние', unknown: 'Не определён',
}

export function RegistryBadge({ origin = 'unknown', external = [] }: { origin?: RegistryOrigin; external?: string[] }) {
  const warning = origin === 'external' || origin === 'mixed'
  const hint = warning ? `Внешние реестры: ${external.join(', ')}`
    : origin === 'unknown' ? 'Реестр не определён: не хватает адресов источника или данных корпоративного Harbor.'
    : 'Корпоративный Harbor'
  return <span title={hint} className={cn('inline-flex max-w-full items-center gap-1 truncate text-[11px]', warning ? 'rounded border border-risk-medium/40 bg-risk-medium/10 px-1.5 py-0.5 text-risk-medium' : 'text-text-secondary')}>
    {warning && <TriangleAlert size={12} className="shrink-0" aria-hidden />}
    <span className="truncate">{LABELS[origin]}</span>
  </span>
}
