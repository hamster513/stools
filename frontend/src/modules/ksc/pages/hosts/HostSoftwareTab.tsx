import { HostSoftwarePanel } from '@/platform/software/HostSoftwarePanel'

export function HostSoftwareTab({ snapshotId, hostId }: { snapshotId: number; hostId: string }) {
  return <HostSoftwarePanel endpoint={`/api/ksc/snapshots/${snapshotId}/hosts/${encodeURIComponent(hostId)}/software`} />
}
