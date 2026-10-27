import type { ReactNode } from 'react'
import { ArrowRight, Server } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDiscrepancySummary, useOverview } from '@/modules/assets/api/queries'
import { CODE_LABELS, CODES, SOURCE_LABELS, SOURCES, type DiscrepancyCode } from '@/modules/assets/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { HELP_SAFE } from '@/help/layout'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { SyncButton } from './SyncButton'

const CARD = 'rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Коды, которые требуют внимания: их ненулевые счётчики выделяются цветом. */
const ALERT: Partial<Record<DiscrepancyCode, string>> = {
  stale: 'text-kind-1',
  conflict: 'text-kind-2',
  no_av: 'text-risk-high',
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : '—'
}

function Counter({ to, label, value, tone }: { to: string; label: string; value: number; tone?: string }) {
  return (
    <Link to={to} className={CARD}>
      <div className="text-[11px] text-text-secondary">{label}</div>
      <div className={cn('mt-1 font-mono text-xl tabular-nums', value > 0 && tone ? tone : 'text-text')}>{value.toLocaleString('ru-RU')}</div>
    </Link>
  )
}

function Block({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded border border-grid bg-surface p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-xs font-semibold tracking-wide text-text-secondary uppercase">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function MoreLink({ to, children }: { to: string; children: ReactNode }) {
  return <Link to={to} className="inline-flex items-center gap-1 text-[11px] text-text-secondary hover:text-text">{children} <ArrowRight size={11} aria-hidden /></Link>
}

/** Обзор реестра: счётчики со ссылками в отфильтрованный список, последние обновления DNS, синхронизация. */
export function OverviewPage() {
  const { write } = useCan()
  const overview = useOverview()
  const summary = useDiscrepancySummary()
  if (overview.isLoading) return <FullPageSpinner />
  if (overview.isError || !overview.data) {
    const msg = overview.error instanceof ApiRequestError ? overview.error.message : 'Не удалось загрузить обзор'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => overview.refetch()} /></div>
  }
  const o = overview.data
  const zones = Object.entries(o.by_zone).filter(([z, n]) => z !== '' && n > 0).sort((a, b) => b[1] - a[1])
  const noZone = o.by_zone[''] ?? 0

  const header = (
    <div className={cn('mb-4 flex items-start justify-between gap-4', HELP_SAFE)}>
      <div>
        <h1 className="text-base font-semibold text-text">Обзор</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Синхронизация с модулями VM, антивируса и AD: {o.sync.running_job_id ? <Link to="/assets/jobs" className="underline">идёт, задача #{o.sync.running_job_id}</Link> : `последняя ${when(o.sync.last_sync_at)}`}.
        </p>
      </div>
      {write && <SyncButton />}
    </div>
  )

  if (o.assets_total === 0) {
    return (
      <div className="h-full overflow-y-auto p-6">
        {header}
        <EmptyState
          icon={Server}
          title="Активов ещё нет"
          description="Активы появятся после синхронизации с модулями VM, антивируса и AD, прохода RackTables или обновления DNS."
          action={<Link to="/assets/networks" className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90">Описать сети <ArrowRight size={13} aria-hidden /></Link>}
        />
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      {header}

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Counter to="/assets/list" label="всего активов" value={o.assets_total} />
        <Counter to="/assets/list?code=any" label="с расхождениями" value={o.codes.any ?? 0} tone="text-risk-high" />
        {CODES.map((c) => <Counter key={c} to={`/assets/list?code=${c}`} label={CODE_LABELS[c]} value={o.codes[c] ?? 0} tone={ALERT[c]} />)}
      </div>
      {/* Плитки считают расхождения с учитываемым статусом; решённые людьми — здесь. */}
      {summary.data && (
        <p className="-mt-2 mb-4 text-xs text-text-secondary">
          Расхождения: принято рисков{' '}
          <Link to="/assets/list?disc_status=risk_accepted" className="font-mono tabular-nums text-text hover:underline">{summary.data.by_status.risk_accepted}</Link>,
          в работе{' '}
          <Link to="/assets/list?disc_status=in_work" className="font-mono tabular-nums text-text hover:underline">{summary.data.by_status.in_work}</Link>.
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Block title="Источники">
          <table className="w-full text-xs">
            <thead className="text-[11px] text-text-secondary">
              <tr><th className="py-1 pr-3 text-left font-normal">Источник</th><th className="py-1 pr-3 text-right font-normal">видит</th><th className="py-1 text-right font-normal">не видит</th></tr>
            </thead>
            <tbody>
              {SOURCES.map((s) => (
                <tr key={s} className="border-t border-grid">
                  <td className="py-1.5 pr-3 text-text">{SOURCE_LABELS[s]}</td>
                  <td className="py-1.5 pr-3 text-right font-mono tabular-nums"><Link to={`/assets/list?source_has=${s}`} className="text-text hover:underline">{o.by_source[s] ?? 0}</Link></td>
                  <td className="py-1.5 text-right font-mono tabular-nums"><Link to={`/assets/list?source_missing=${s}`} className="text-text-secondary hover:text-text hover:underline">{o.assets_total - (o.by_source[s] ?? 0)}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Block>

        <Block title="Зоны и сети" action={<MoreLink to="/assets/networks">сети</MoreLink>}>
          <div className="mb-3 flex flex-wrap gap-2 text-xs">
            {zones.map(([z, n]) => (
              <Link key={z} to={`/assets/list?zone=${encodeURIComponent(z)}`} className="rounded border border-grid px-2 py-1 hover:border-border">
                <span className="text-text">{z}</span> <span className="font-mono tabular-nums text-text-secondary">{n}</span>
              </Link>
            ))}
            <span className="rounded border border-dashed border-grid px-2 py-1 text-text-secondary">без зоны <span className="font-mono tabular-nums">{noZone}</span></span>
          </div>
          <p className="text-xs text-text-secondary">
            Сетей описано <span className="font-mono tabular-nums text-text">{o.networks.total}</span>; активов вне описанных сетей{' '}
            <Link to="/assets/list?code=no_network" className="font-mono tabular-nums text-text underline">{o.networks.no_network_assets}</Link>.
          </p>
        </Block>

        <Block title="Последние обновления DNS" action={<MoreLink to="/settings/assets#dns">DNS-серверы</MoreLink>}>
          {o.last_dns.length === 0 ? (
            <p className="text-xs text-text-secondary">Обновлений через DNS ещё не было: DNS-серверы задаются в настройках модуля.</p>
          ) : (
            <table className="w-full text-xs">
              <tbody>
                {o.last_dns.map((d) => (
                  <tr key={d.dns_id} className="border-t border-grid first:border-t-0">
                    <td className="py-1.5 pr-3 text-text">{d.title}</td>
                    <td className="py-1.5 text-right text-text-secondary">{when(d.last_run_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Block>
      </div>
    </div>
  )
}
