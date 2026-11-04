import type { FirewallCheckInput, FirewallCheckResult, FirewallProtocol, FirewallVerdict } from '../../api/firewall'

export interface CheckForm {
  source: string; destinationKind: 'address' | 'host'; address: string; host: string
  protocol: FirewallProtocol; port: string; icmpType: string
}
export const VERDICTS: Record<FirewallVerdict, string> = {
  allow: 'Разрешено правилами', deny: 'Запрещено правилами', app: 'Зависит от программы',
  depends: 'Зависит от условий', not_applied: 'Firewall-правила не применяются', undetermined: 'Недостаточно данных',
}
export const STEP_LABELS = { hit: 'Решающее правило', no: 'Не подходит', maybe: 'Возможно подходит', disabled: 'Выключено', skipped: 'Пропущено для ответа', not_checked: 'После решающего — не проверялось' }
export const MATCH_LABELS = { yes: 'Совпало', no: 'Не совпало', maybe: 'Не определено' }

export function buildCheck(form: CheckForm): { input: FirewallCheckInput; error?: never } | { input?: never; error: string } {
  if (!form.source) return { error: 'Выберите исходный хост.' }
  if (form.destinationKind === 'host' && !form.host) return { error: 'Выберите хост назначения.' }
  if (form.destinationKind === 'address' && !form.address.trim()) return { error: 'Укажите IP-адрес назначения.' }
  const ports = form.protocol === 'tcp' || form.protocol === 'udp'
  const icmp = form.protocol === 'icmp' || form.protocol === 'icmpv6'
  const value = (ports ? form.port : icmp ? form.icmpType : '').trim()
  const max = ports ? 65535 : 255
  if (value && (!/^\d+$/.test(value) || Number(value) > max)) return { error: ports ? 'Порт должен быть целым числом от 0 до 65535.' : 'Тип ICMP должен быть целым числом от 0 до 255.' }
  return { input: {
    source_host_id: form.source,
    destination: form.destinationKind === 'host' ? { host_id: form.host } : { address: form.address.trim() },
    protocol: form.protocol, port: ports && value ? Number(value) : null, icmp_type: icmp && value ? Number(value) : null,
  } }
}

type Outcome = Pick<FirewallCheckResult, 'overall'> & { source: { verdict: FirewallVerdict }; destination: { verdict: FirewallVerdict } | null }
export function outcomeTitle(result: Outcome): string {
  if (!result.destination) return `Исходящий трафик: ${VERDICTS[result.source.verdict]}`
  if (result.source.verdict === 'not_applied' && result.destination.verdict === 'not_applied') return VERDICTS.not_applied
  return VERDICTS[result.overall]
}
