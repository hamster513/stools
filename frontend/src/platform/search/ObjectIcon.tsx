import { Bug, FileText, FolderTree, Info, Monitor, ShieldCheck, UserRound, UsersRound } from 'lucide-react'
const ICONS = { host: Monitor, user: UserRound, group: UsersRound, policy: ShieldCheck, cve: Bug, evidence: FileText, category: FolderTree, observations: Info }
export function ObjectIcon({ kind, size = 18, className = '' }: { kind: keyof typeof ICONS; size?: number; className?: string }) {
  const Icon = ICONS[kind]
  return <Icon size={size} aria-hidden className={`shrink-0 ${className}`} />
}
