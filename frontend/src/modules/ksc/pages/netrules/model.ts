import type { NetRuleAddress, NetRuleScope, NetRuleSection, NetRulesQuery, FirewallProfileMode } from '../../api/types'

export const MODE_LABELS: Record<FirewallProfileMode, string> = { auto: 'Авто: обе модели', merge: 'Профиль дополняет список', replace: 'Профиль заменяет список' }
export type Section = NetRuleSection & { total: number }
export const sectionKey = (s: Pick<NetRuleSection, 'layer' | 'policy_id' | 'profile'>) => JSON.stringify([s.layer, s.policy_id, s.profile])

/** База задаёт порядок и знаменатели; фильтр не удаляет полосы пустых секций. */
export function mergeSections(base: NetRuleSection[], filtered: NetRuleSection[]): Section[] {
  const matches = new Map(filtered.map(s => [sectionKey(s), s]))
  return base.map(s => ({ ...s, ...matches.get(sectionKey(s)), rules: matches.get(sectionKey(s))?.rules ?? 0, shadowed: matches.get(sectionKey(s))?.shadowed ?? 0, comparison: s.comparison ? { ...s.comparison, differences: matches.get(sectionKey(s))?.comparison?.differences ?? 0 } : s.comparison, total: s.rules }))
}

export function inactiveLabel(reason?: string, by?: string): string {
  if (reason === 'replaced') return by ? `Заменено профилем «${by}»` : 'Заменено другим набором правил'
  if (reason === 'unlocked') return 'Список профиля без замка — не применяется'
  if (reason === 'inactive') return 'Политика не действует у выбранного хоста'
  return reason ? 'Не действует у выбранного хоста' : ''
}

export interface ScopeToken { text: string; kind: 'address' | 'network' | 'host' | 'hidden' | 'warning'; title?: string }
const UNREAD_LABELS: Record<string, string> = { direction: 'направление', protocol: 'протокол', networks: 'тип сети', mask: 'маска адреса', ports: 'порты', icmp_type: 'тип ICMP' }
const ZONES: Record<number, string> = { 0: 'доверенные сети', 1: 'локальные сети', 2: 'публичные сети' }
function address(a: NetRuleAddress, local: boolean): ScopeToken {
  const prefix = local ? 'лок. ' : ''
  if (a.hidden) return { text: `${prefix}адрес ${a.hidden === 'secret' ? 'скрыт' : 'не прочитан'}`, kind: 'hidden' }
  if (a.host) return { text: prefix + a.host, kind: 'host', title: a.ips.map(ip => ip.hidden ? 'адрес скрыт' : ip.ip + (ip.mask === null ? '' : `/${ip.mask}`)).join(', ') || 'Разрешённые адреса не получены' }
  if (!a.ip) return { text: prefix + 'адрес не определён', kind: 'warning' }
  return { text: prefix + a.ip + (a.mask === null ? '' : `/${a.mask}`), kind: a.mask === null ? 'address' : 'network' }
}

/** У записи без имени адреса могут быть только внутри hostNameIPs → ips. */
function addressTokens(a: NetRuleAddress, local: boolean): ScopeToken[] {
  if (!a.hidden && !a.host && !a.ip && a.ips.length) return a.ips.flatMap(ip => addressTokens(ip, local))
  return [address(a, local)]
}

export function scopeTokens(scope: NetRuleScope | null, fallback: string): ScopeToken[] {
  if (!scope) return [{ text: fallback || 'Критерии адресов не получены', kind: fallback ? 'address' : 'warning' }]
  const tokens: ScopeToken[] = []
  if (scope.networks !== null) tokens.push({ text: ZONES[scope.networks] ?? `зона ${scope.networks}`, kind: 'network' })
  tokens.push(...scope.remote.flatMap(a => addressTokens(a, false)), ...scope.local.flatMap(a => addressTokens(a, true)))
  if (!tokens.length && !scope.unread.some(k => ['networks', 'local', 'remote', 'address', 'mask'].includes(k))) tokens.push({ text: 'любые адреса', kind: 'address' })
  if (scope.unread.length) tokens.push({ text: 'Часть критериев не прочитана', kind: 'warning', title: `Не удалось прочитать: ${scope.unread.map(k => UNREAD_LABELS[k] ?? k).join(', ')}` })
  return tokens
}

export function portsText(scope: NetRuleScope | null, side: 'local_ports' | 'remote_ports', fallback: string): string {
  if (!scope) return fallback || '—'
  const text = scope[side].map(([start, end]) => start === end ? String(start) : `${start}–${end}`).join(', ')
  if (scope.unread.includes('ports') || scope.unread.includes(side)) return text ? `${text} (прочитано не полностью)` : 'не прочитаны'
  return text || 'любые'
}

export type Filters = Pick<NetRulesQuery, 'q' | 'policy_id' | 'action' | 'direction' | 'enabled' | 'host_id'>
export function readFilters(search: string): Filters {
  const p = new URLSearchParams(search)
  const ids = p.getAll('policy_id').filter(v => /^\d+$/.test(v)).map(Number).filter(n => n > 0 && Number.isSafeInteger(n))
  const list = (key: string) => p.getAll(key).length ? p.getAll(key).map(v => v === '-' ? '' : v) : undefined
  return { q: p.get('q') || undefined, host_id: p.get('host_id') || undefined, policy_id: ids.length ? ids : undefined,
    action: list('action'), direction: list('direction'), enabled: p.get('enabled') === 'true' ? true : p.get('enabled') === 'false' ? false : undefined }
}
export function writeFilters(search: string, filters: Filters): string {
  const p = new URLSearchParams(search)
  for (const key of ['q', 'host_id', 'policy_id', 'action', 'direction', 'enabled'] as const) {
    p.delete(key)
    const value = filters[key]
    if (value === undefined || value === '') continue
    for (const v of Array.isArray(value) ? value : [value]) p.append(key, String(v))
  }
  return p.toString()
}
export function readOpenSections(raw: string | null): string[] {
  try { const parsed: unknown = JSON.parse(raw ?? 'null'); return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [] } catch { return [] }
}


export interface ProfileGroup { key: string; members: Section[] }
export interface PolicyLayer { layer: string; base?: Section; groups: ProfileGroup[]; unlocked: ProfileGroup[] }
export interface PolicyGroup { id: number; name: string; hosts: number; layers: PolicyLayer[] }

/** Совпадение содержимого не объединяет разные политики, слои и режим замка. */
export function groupPolicies(sections: Section[]): PolicyGroup[] {
  const policies = new Map<number, PolicyGroup>()
  for (const s of sections) {
    let policy = policies.get(s.policy_id)
    if (!policy) { policy = { id: s.policy_id, name: s.policy_name, hosts: s.hosts, layers: [] }; policies.set(s.policy_id, policy) }
    let layer = policy.layers.find(l => l.layer === s.layer)
    if (!layer) { layer = { layer: s.layer, groups: [], unlocked: [] }; policy.layers.push(layer) }
    if (!s.profile) { layer.base = s; continue }
    const bucket = s.locked === false ? layer.unlocked : layer.groups
    const key = JSON.stringify([s.policy_id, s.layer, s.locked === false, s.content_key ?? sectionKey(s)])
    let group = bucket.find(g => g.key === key)
    if (!group) { group = { key, members: [] }; bucket.push(group) }
    group.members.push(s)
  }
  return [...policies.values()]
}

export function comparisonText(c: import('../../api/types').NetRuleComparison | null | undefined): string {
  if (!c?.base_known) return 'Базовый список не получен — сравнение неполное'
  const parts = [[c.added, 'добавлено'], [c.removed, 'нет в профиле'], [c.changed, 'изменено'], [c.moved, 'переставлено']] as const
  const changes = parts.filter(([count]) => count > 0).map(([count, label]) => `${count} ${label}`)
  return changes.length ? changes.join(' · ') : 'Состав и порядок совпадают с политикой'
}
