import { CheckCircle2, Copy, Fingerprint, Hash, ListX, Network } from 'lucide-react'
import type { FindingKind } from '@/modules/siem/api/types'
import { FINDING_KIND_LABELS } from '@/modules/siem/api/types'
import { cn } from '@/lib/cn'
import { tint } from '@/lib/tint'

/**
 * Класс находки — цвет, форма (иконка) и слово одновременно. Цвет один
 * никогда не несёт смысл: колонка должна читаться и в градациях серого.
 */
const KIND_META: Record<FindingKind, { icon: typeof Copy; color: string; short: string }> = {
  '1': { icon: Copy, color: 'var(--color-kind-1)', short: 'Дублирует список' },
  '2': { icon: Network, color: 'var(--color-kind-2)', short: 'IP / CIDR / FQDN' },
  '3': { icon: ListX, color: 'var(--color-kind-3)', short: 'not in_list 3+' },
  '4': { icon: Fingerprint, color: 'var(--color-kind-4)', short: 'Доменный SID' },
  '5': { icon: Hash, color: 'var(--color-kind-5)', short: 'Одиночный литерал' },
}

export function KindBadge({ kind, className }: { kind: FindingKind; className?: string }) {
  const meta = KIND_META[kind]
  const Icon = meta.icon
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
        className,
      )}
      style={{ color: meta.color, borderColor: tint(meta.color, 33), backgroundColor: tint(meta.color, 8) }}
      title={FINDING_KIND_LABELS[kind]}
    >
      <Icon size={12} strokeWidth={2.25} aria-hidden />
      {meta.short}
    </span>
  )
}

export function AcceptedBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
        className,
      )}
      style={{ color: 'var(--color-kind-accepted)', borderColor: 'var(--color-kind-accepted)55', backgroundColor: 'var(--color-kind-accepted)14' }}
    >
      <CheckCircle2 size={12} strokeWidth={2.25} aria-hidden />
      Принято как норма
    </span>
  )
}
