import type { ObjectKind } from './graph/model.ts'
export const SECTION_KINDS: Record<string, ObjectKind> = { groups: 'group', members: 'group', hosts: 'host', users: 'user', ad_policies: 'policy', antivirus: 'policy', vulnerabilities: 'cve', observations: 'evidence' }
