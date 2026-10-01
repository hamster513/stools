import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { useJob, useStartSync } from '@/modules/assets/api/queries'
import { Button } from '@/components/ui/Button'
import { Link } from '@/lib/router'

/** Синхронизация с модулями кнопкой: следит за задачей и, когда та закончится, обновляет реестр, обзор и статус. */
export function SyncButton({ label = 'Синхронизировать' }: { label?: string }) {
  const qc = useQueryClient()
  const start = useStartSync()
  const [jobId, setJobId] = useState<number | null>(null)
  const job = useJob(jobId)
  const status = job.data?.status
  useEffect(() => {
    if (status && status !== 'running') {
      for (const key of ['assets-list', 'assets-asset', 'assets-overview', 'assets-sync-status']) qc.invalidateQueries({ queryKey: [key] })
    }
  }, [status, qc])
  const running = start.isPending || status === 'running' || (jobId !== null && !job.data)
  return (
    <div className="flex items-center gap-2">
      {start.error && <span className="text-xs text-kind-1">{start.error.message}</span>}
      {jobId !== null && (
        <span className="text-xs text-text-secondary">
          <Link to="/assets/jobs" className="hover:underline">задача #{jobId}</Link>
          {status === 'done' && job.data?.message && ` · ${job.data.message}`}
          {status === 'failed' && <span className="text-kind-1"> · {job.data?.error ?? 'синхронизация не удалась'}</span>}
        </span>
      )}
      <Button onClick={() => start.mutate(undefined, { onSuccess: (r) => setJobId(r.job_id) })} loading={running} disabled={running}>
        <RefreshCw size={13} aria-hidden /> {label}
      </Button>
    </div>
  )
}
