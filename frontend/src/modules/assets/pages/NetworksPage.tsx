import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Network as NetworkIcon, Plus, Radar, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDeleteNetwork, useJob, useNetworks, useStartScan } from '@/modules/assets/api/queries'
import type { Network, NetworkSchedule } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { NetworkForm } from './NetworkForm'

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : '—'
}

function scheduleText(s: NetworkSchedule | null, scanEnabled: boolean): string {
  if (!s) return scanEnabled ? 'вручную' : 'не сканируется'
  const every = s.interval_hours % 24 === 0 ? `раз в ${s.interval_hours / 24} сут` : `раз в ${s.interval_hours} ч`
  const window = s.window_from && s.window_to ? `, ${s.window_from}–${s.window_to} ${s.tz}` : ''
  if (!s.enabled) return `выключено (${every}${window})`
  return `${every}${window}; следующий ${when(s.next_run_at)}`
}

/** «Сканировать сейчас»: номер задачи, ход и итог; по окончании обновляются сети и реестр. */
function ScanButton({ network }: { network: Network }) {
  const qc = useQueryClient()
  const start = useStartScan()
  const [started, setStarted] = useState<{ jobId: number; icmp: boolean } | null>(null)
  const job = useJob(started?.jobId ?? null)
  const status = job.data?.status
  useEffect(() => {
    if (status && status !== 'running') {
      for (const key of ['assets-networks', 'assets-list', 'assets-asset']) qc.invalidateQueries({ queryKey: [key] })
    }
  }, [status, qc])
  const running = start.isPending || status === 'running' || (started !== null && !job.data)
  return (
    <div className="flex flex-col items-end gap-0.5">
      <Button variant="ghost" loading={running} disabled={running || !network.scan_enabled}
        title={network.scan_enabled ? undefined : 'Сканирование сети выключено — включите его в форме'}
        onClick={() => start.mutate(network.id, { onSuccess: (r) => setStarted({ jobId: r.job_id, icmp: r.icmp }) })}>
        <Radar size={13} aria-hidden /> сканировать
      </Button>
      {start.error && <span className="max-w-56 text-right text-[11px] whitespace-normal text-kind-1">{start.error.message}</span>}
      {started && (
        <span className="max-w-56 text-right text-[11px] whitespace-normal text-text-secondary">
          <Link to="/assets/jobs" className="hover:underline">скан #{started.jobId}</Link>
          {status === 'running' && job.data && ` · ${job.data.processed} из ${job.data.total ?? '…'}`}
          {status === 'done' && ` · ${job.data?.message}`}
          {status === 'failed' && <span className="text-kind-1"> · {job.data?.error ?? 'не удался'}</span>}
          {status === 'cancelled' && ' · отменён'}
          {!started.icmp && status !== 'done' && ' · ICMP недоступен — только порты'}
        </span>
      )}
    </div>
  )
}

function ConfirmDelete({ network, onDone }: { network: Network; onDone: () => void }) {
  const remove = useDeleteNetwork()
  return (
    <div role="dialog" aria-label="Удалить сеть" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">Удалить сеть {network.cidr}?</div>
        <p className="mb-4 text-xs text-text-secondary">
          Активы сети ({network.stats.assets}) перейдут в самую узкую из оставшихся сетей, содержащую их адрес, или останутся без сети;
          привязка вручную к этой сети сбрасывается. Расписание сканов сети удаляется.
        </p>
        {remove.error && <p className="mb-2 text-xs text-kind-1">{remove.error instanceof ApiRequestError ? remove.error.message : 'Не удалось удалить'}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onDone}>Отмена</Button>
          <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(network.id, { onSuccess: onDone })}>Удалить</Button>
        </div>
      </div>
    </div>
  )
}

/** Сети: CIDR, зона, площадка, сколько активов и что нашёл последний скан. Строка — правка сети. */
export function NetworksPage() {
  const { write } = useCan()
  const networks = useNetworks()
  // undefined — форма закрыта, null — новая сеть.
  const [editing, setEditing] = useState<Network | null | undefined>(undefined)
  const [deleting, setDeleting] = useState<Network | null>(null)

  if (networks.isLoading) return <FullPageSpinner />
  if (networks.isError || !networks.data) {
    const msg = networks.error instanceof ApiRequestError ? networks.error.message : 'Не удалось загрузить сети'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => networks.refetch()} /></div>
  }
  const list = networks.data

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start gap-3">
        <div>
          <h1 className="text-base font-semibold text-text">Сети</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Актив привязывается к самой узкой сети, содержащей его адрес; в карточке актива сеть можно задать вручную. Пересечение сетей допустимо.
          </p>
        </div>
        {write && editing === undefined && <Button className="ml-auto shrink-0" onClick={() => setEditing(null)}><Plus size={13} aria-hidden /> Добавить сеть</Button>}
      </div>

      {editing !== undefined && (
        <div className="mb-4">
          <NetworkForm key={editing?.id ?? 'new'} network={editing} onDone={() => setEditing(undefined)} onCancel={() => setEditing(undefined)} />
        </div>
      )}

      {list.length === 0 ? (
        <EmptyState icon={NetworkIcon} title="Сетей ещё нет" description="Опишите сети с зоной и площадкой: активы привяжутся к ним по адресу, а сканер будет знать, что можно сканировать." />
      ) : (
        <table className="w-full rounded border border-grid bg-surface text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr className="border-b border-grid">
              <th className="px-3 py-2 text-left">CIDR</th>
              <th className="px-3 py-2 text-left">Название</th>
              <th className="px-3 py-2 text-left">Зона</th>
              <th className="px-3 py-2 text-left">Площадка</th>
              <th className="px-3 py-2 text-right">Активов</th>
              <th className="px-3 py-2 text-right" title="ответили при последнем скане">Живых</th>
              <th className="px-3 py-2 text-right" title="найдено сканером, нигде не описано">Только сканер</th>
              <th className="px-3 py-2 text-left">Последний скан</th>
              <th className="px-3 py-2 text-left">Расписание</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {list.map((n) => (
              <tr key={n.id} className="border-t border-grid align-top hover:bg-row-hover">
                <td className="px-3 py-2 font-mono text-text">{n.cidr}</td>
                <td className="px-3 py-2 text-text">{n.title || '—'}{n.vlan !== null && <span className="ml-1 text-text-secondary">· VLAN {n.vlan}</span>}</td>
                <td className="px-3 py-2 text-text-secondary">{n.zone ?? '—'}</td>
                <td className="px-3 py-2 text-text-secondary">{n.site || '—'}</td>
                <td className="px-3 py-2 text-right font-mono tabular-nums">
                  <Link to={`/assets/list?network_id=${n.id}`} className="text-text hover:underline">{n.stats.assets}</Link>
                </td>
                <td className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{n.stats.alive_last_scan ?? '—'}</td>
                <td className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">
                  {n.stats.unknown_hosts > 0 ? <Link to={`/assets/list?network_id=${n.id}&code=unknown_host`} className="text-risk-high hover:underline">{n.stats.unknown_hosts}</Link> : 0}
                </td>
                <td className="px-3 py-2 text-text-secondary">{when(n.last_scan_at)}</td>
                <td className="px-3 py-2 text-text-secondary">{scheduleText(n.schedule, n.scan_enabled)}</td>
                <td className="px-3 py-2">
                  {write && (
                    <div className="flex items-start justify-end gap-1 whitespace-nowrap">
                      <ScanButton network={n} />
                      <Button variant="ghost" onClick={() => setEditing(n)}>изменить</Button>
                      <Button variant="ghost" onClick={() => setDeleting(n)} aria-label={`Удалить сеть ${n.cidr}`}><Trash2 size={13} aria-hidden /></Button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {deleting && <ConfirmDelete network={deleting} onDone={() => setDeleting(null)} />}
    </div>
  )
}
