import { useMutation } from '@tanstack/react-query'
import { api, ApiRequestError } from '@/api/client'

export type FirewallVerdict = 'allow' | 'deny' | 'app' | 'depends' | 'not_applied' | 'undetermined'
export type FirewallProtocol = 'tcp' | 'udp' | 'icmp' | 'icmpv6' | 'any'
export interface FirewallCheckInput {
  source_host_id: string
  destination: { host_id: string } | { address: string }
  protocol: FirewallProtocol
  port: number | null
  icmp_type: number | null
}
export interface FirewallRule {
  row_id: number; position: number; name: string; policy_id: number; profile: string
  action: string; enabled: boolean; layer: string
}
export interface FirewallStep {
  rule: FirewallRule
  status: 'hit' | 'no' | 'maybe' | 'disabled' | 'skipped' | 'not_checked'
  result: 'yes' | 'no' | 'maybe'
  criteria: { name: string; result: 'yes' | 'no' | 'maybe'; text: string }[]
  almost: { name: string; text: string } | null
  assumption: string
}
export interface FirewallBranch {
  assumptions: string[]; verdict: FirewallVerdict; decided_by: FirewallRule | null; layer: string; note: string
  steps: FirewallStep[]; reply_steps: FirewallStep[]; app_candidates: FirewallRule[]
  trust_groups: { name: string; allow: boolean | null }[]
}
export interface FirewallHost { host_id: string; name: string; ip: string }
export interface FirewallSide {
  host: FirewallHost; direction: 'out' | 'in'; verdict: FirewallVerdict; depends_on: string[]
  mode: '' | 'notify_only'; notes: string[]; effective_sources: string[]; branches: FirewallBranch[]
}
export interface FirewallCheckResult {
  source: FirewallSide; destination: FirewallSide | null; destination_hosts: FirewallHost[]
  overall: FirewallVerdict; depends_on: string[]; notes: string[]
}
export function useFirewallCheck(snapshotId: number) {
  return useMutation<FirewallCheckResult, ApiRequestError, FirewallCheckInput>({
    mutationFn: input => api.post(`/api/ksc/snapshots/${snapshotId}/firewall/check`, input),
  })
}
