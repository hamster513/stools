import { ArrowRight, ServerCog } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useOverview } from '@/modules/ksc/api/queries'
import { SEVERITIES, SEVERITY_LABELS, type CheckSummary, type Coverage, type Severity } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

const SEV_TEXT: Record<Severity, string> = {
  Critical: 'text-risk-critical',
  High: 'text-risk-high',
  Medium: 'text-risk-medium',
  Low: 'text-risk-low',
  Info: 'text-text-secondary',
}

function worst(c: CheckSummary): Severity | null {
  return SEVERITIES.find((s) => (c.by_severity[s] ?? 0) > 0) ?? null
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function CoverageCard({ title, value, hint, to }: { title: string; value: React.ReactNode; hint?: string; to?: string }) {
  const body = (
    <>
      <div className="text-[11px] text-text-secondary">{title}</div>
      <div className="mt-1 font-mono text-xl tabular-nums text-text">{value}</div>
      {hint && <div className="mt-1 text-[11px] leading-relaxed text-text-secondary">{hint}</div>}
    </>
  )
  return to ? (
    <Link to={to} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
      {body}
    </Link>
  ) : (
    <div className="rounded border border-grid bg-surface p-3">{body}</div>
  )
}

function CoverageSection({ serverId, coverage }: { serverId: number; coverage: Coverage }) {
  const hostsBase = `/ksc/servers/${serverId}/hosts`
  const findingsBase = `/ksc/servers/${serverId}/findings`
  const hasAd = coverage.ad_total !== null
  return (
    <div className="mb-5">
      <div className="mb-2 text-xs font-semibold tracking-wide text-text-secondary uppercase">Покрытие</div>
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
        {hasAd ? (
          <CoverageCard title="Компьютеров в AD" value={coverage.ad_total} />
        ) : (
          <CoverageCard title="нет данных AD" value="—" hint="Загрузите снапшот домена в модуле AD — сверка появится после пересчёта." />
        )}
        <CoverageCard title="Устройств в KSC" value={coverage.ksc_total} />
        <CoverageCard title="С агентом" value={coverage.with_agent} to={`${hostsBase}?agent=alive`} />
        <CoverageCard title="С защитой" value={coverage.with_protection} to={`${hostsBase}?protection=on`} />
        <CoverageCard title="Защита работает" value={coverage.protection_on} />
        <CoverageCard title="Базы свежие" value={coverage.bases_fresh} to={`${hostsBase}?bases=fresh`} />
        {hasAd && (
          <>
            <CoverageCard title="Есть в AD, нет в KSC" value={coverage.ad_only} to={`${findingsBase}?check=COVER_AD_MISSING`} />
            <CoverageCard title="Только в KSC" value={coverage.ksc_only} to={`${hostsBase}?in_ad=ksc_only`} />
          </>
        )}
      </div>
    </div>
  )
}

export function OverviewPage({ serverId }: { serverId: number }) {
  const overview = useOverview(serverId)
  if (overview.isLoading) return <FullPageSpinner />
  if (overview.isError || !overview.data) {
    const msg = overview.error instanceof ApiRequestError ? overview.error.message : 'Не удалось загрузить обзор'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => overview.refetch()} /></div>
  }
  const o = overview.data
  if (!o.snapshot) {
    return (
      <div className="p-6">
        <EmptyState icon={ServerCog} title="Снапшотов ещё нет" description="Загрузите выгрузку скрипта или запустите сбор из KSC в настройках модуля." action={<Link to="/ksc/settings" className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90">Настройки и данные <ArrowRight size={13} aria-hidden /></Link>} />
      </div>
    )
  }
  const snap = o.snapshot
  const base = `/ksc/servers/${serverId}/findings`
  const cmp = o.compared_to
  const withFindings = o.checks.filter((c) => c.total > 0 || c.fixed > 0)
  const clean = o.checks.filter((c) => c.total === 0 && c.fixed === 0)

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">{o.server.name}</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Снапшот #{o.snapshot.id} от {when(o.snapshot.collected_at)}, {o.snapshot.source === 'online' ? 'сбор из KSC' : 'выгрузка скрипта'} ({o.snapshot.collector}), хостов {o.snapshot.hosts.toLocaleString('ru-RU')}.
            {cmp?.previous_id ? ` По сравнению с ${cmp.collected_at ? when(cmp.collected_at) : 'прошлым'}: новых ${cmp.new}, закрыто ${cmp.fixed}.` : ' Это первый снапшот сервера.'}
          </p>
        </div>
      </div>

      {o.coverage && <CoverageSection serverId={serverId} coverage={o.coverage} />}

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {SEVERITIES.map((s) => (
          <Link key={s} to={`${base}?severity=${s}`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
            <div className={cn('text-[11px]', SEV_TEXT[s])}>{SEVERITY_LABELS[s]}</div>
            <div className="mt-1 font-mono text-xl tabular-nums text-text">{(snap.by_severity[s] ?? 0).toLocaleString('ru-RU')}</div>
          </Link>
        ))}
        <Link to={`${base}?status=new`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <div className="text-[11px] text-text-secondary">новых</div>
          <div className="mt-1 font-mono text-xl tabular-nums text-text">{cmp?.new ?? 0}</div>
        </Link>
      </div>

      <div className="mb-2 text-xs font-semibold tracking-wide text-text-secondary uppercase">Проверки</div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {withFindings.map((c) => {
          const w = worst(c)
          return (
            <Link key={c.code} to={`${base}?check=${c.code}`} className="flex flex-col gap-1.5 rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
              <div className="flex items-start justify-between gap-2">
                <span className="text-sm text-text">{c.title}</span>
                <span className={cn('font-mono text-lg tabular-nums', w ? SEV_TEXT[w] : 'text-text-secondary')}>{c.total}</span>
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-secondary">
                {SEVERITIES.filter((s) => (c.by_severity[s] ?? 0) > 0).map((s) => (
                  <span key={s}><span className={SEV_TEXT[s]}>{SEVERITY_LABELS[s]}</span> {c.by_severity[s]}</span>
                ))}
                {c.new > 0 && <span className="text-risk-high">+{c.new} новых</span>}
                {c.fixed > 0 && <span className="text-kind-accepted">−{c.fixed} закрыто</span>}
                {c.accepted > 0 && <span>принято {c.accepted}</span>}
              </div>
              <p className="text-[11px] leading-relaxed text-text-secondary">{c.description}</p>
            </Link>
          )
        })}
      </div>
      {clean.length > 0 && (
        <p className="mt-4 text-xs text-text-secondary">
          Без находок: {clean.map((c) => c.title).join(' · ')}.
        </p>
      )}
    </div>
  )
}
