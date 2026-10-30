import { Check, X, ListOrdered, Globe, Monitor, Server, EyeOff, TriangleAlert } from 'lucide-react'
import type { NetRuleItem } from '../../api/types'
import { cn } from '@/lib/cn'
import { inactiveLabel, portsText, scopeTokens } from './model'

export function ActionCell({ action }: { action: string }) {
  const allow = action === 'разрешить'; const deny = action === 'запретить'; const app = action === 'по правилам программ'
  const Icon = allow ? Check : deny ? X : app ? ListOrdered : null
  return <span className={cn('inline-flex items-start gap-1.5', allow ? 'text-kind-accepted' : deny ? 'text-kind-1' : app ? 'text-risk-medium' : 'text-text-secondary')}>
    {Icon && <Icon size={14} className="mt-0.5 shrink-0" aria-hidden />}{action || '—'}
  </span>
}

export function ScopeChips({ item }: { item: Pick<NetRuleItem, 'scope' | 'addresses'> }) {
  return <div className="flex flex-wrap gap-1">
    {scopeTokens(item.scope, item.addresses).map((token, index) => {
      const Icon = token.kind === 'network' ? Globe : token.kind === 'host' ? Server : token.kind === 'hidden' ? EyeOff : token.kind === 'warning' ? TriangleAlert : Monitor
      return <span key={index} title={token.title} className={cn('inline-flex max-w-full items-start gap-1 rounded border border-grid px-1.5 py-0.5', token.kind === 'warning' ? 'text-risk-medium' : 'text-text-secondary')}>
        <Icon size={12} className="mt-0.5 shrink-0" aria-hidden /><span className="min-w-0 break-all">{token.text}</span>
      </span>
    })}
  </div>
}

export function PortsCell({ item }: { item: NetRuleItem }) {
  return <div className="space-y-1 font-mono text-text-secondary">
    <div className="break-all"><span className="font-sans">лок. </span>{portsText(item.scope, 'local_ports', item.local_ports)}</div>
    <div className="break-all"><span className="font-sans">уд. </span>{portsText(item.scope, 'remote_ports', item.remote_ports)}</div>
  </div>
}

export function RuleFlags({ item }: { item: NetRuleItem }) {
  const shadow = item.shadowed_by
  const inactive = inactiveLabel(item.overridden_reason)
  return <div className="mt-1 flex flex-wrap gap-1">
    {shadow && <span className="rounded border border-risk-medium/40 px-1 text-risk-medium" title={`Правило №${shadow.position} «${shadow.name}» полностью покрывает это правило; действие ${shadow.same_action ? 'то же' : 'другое'}.`}>
      {shadow.same_action ? 'дублирует' : 'в тени'} №{shadow.position}
    </span>}
    {!item.enabled && <span className="rounded border border-grid px-1 text-text-secondary">выключено</span>}
    {inactive && <span className="rounded border border-grid px-1 text-text-secondary">{inactive}</span>}
  </div>
}
