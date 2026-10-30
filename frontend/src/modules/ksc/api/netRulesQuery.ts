import { buildQuery } from '../../../api/client.ts'
import type { NetRulesQuery } from './types'

/** profile= означает саму политику; общий buildQuery пропускает пустые строки. */
export function netRulesSearch(query: NetRulesQuery): string {
  return buildQuery({ ...query, profile: query.profile === undefined ? undefined : [query.profile] })
}
