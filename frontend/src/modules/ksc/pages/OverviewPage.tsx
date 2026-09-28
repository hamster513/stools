import { useOverview } from '@/modules/ksc/api/queries'
import type { Coverage } from '@/modules/ksc/api/types'
import { Link } from '@/lib/router'
import { CollectorOverviewPage } from '@/platform/collector/OverviewPage'

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
        <CoverageCard title="С агентом" value={coverage.with_agent} to={hostsBase} />
        <CoverageCard title="С защитой" value={coverage.with_protection} to={hostsBase} />
        <CoverageCard title="Защита работает" value={coverage.protection_on} to={`${hostsBase}?protection=on`} />
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
  return (
    <CollectorOverviewPage
      overview={overview}
      settingsPath="/ksc/settings"
      emptyDescription="Загрузите выгрузку скрипта или запустите сбор из KSC в настройках модуля."
      findingsPath={`/ksc/servers/${serverId}/findings`}
      title={(o) => o.server.name}
      source={(snap) => (snap.source === 'online' ? 'сбор из KSC' : 'выгрузка скрипта')}
      count={(snap) => `хостов ${snap.hosts.toLocaleString('ru-RU')}`}
      firstNote=" Это первый снапшот сервера."
      extra={(o) => o.coverage && <CoverageSection serverId={serverId} coverage={o.coverage} />}
    />
  )
}
