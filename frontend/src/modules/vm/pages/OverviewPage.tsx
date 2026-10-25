import type { ReactNode } from 'react'
import { AlertTriangle, ArrowRight, Database, ServerCog, ShieldAlert } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useOverview, useVmSettings } from '@/modules/vm/api/queries'
import { LEVEL_LABELS, LEVELS, type Levels, type Overview, type RiskLevel } from '@/modules/vm/api/types'
import { LEVEL_TEXT } from '@/modules/vm/components/RiskBadge'
import { OPEN_STATUSES } from '@/platform/findings/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

const REF_TITLES: Record<string, string> = { epss: 'EPSS', nvd: 'NVD', exploitdb: 'ExploitDB', msf: 'Metasploit', kev: 'CISA KEV' }
const BAR: Record<RiskLevel, string> = {
  low: 'var(--color-risk-low)',
  medium: 'var(--color-risk-medium)',
  high: 'var(--color-risk-high)',
  critical: 'var(--color-risk-critical)',
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded border border-grid bg-surface p-4', className)}>{children}</div>
}

function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-3">
      <div className="text-xs font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      {subtitle && <div className="mt-0.5 text-[11px] text-text-secondary">{subtitle}</div>}
    </div>
  )
}

function Stat({ label, value, to, tone }: { label: string; value: number; to?: string; tone?: string }) {
  const body = (
    <>
      <div className="text-[11px] text-text-secondary">{label}</div>
      <div className={cn('mt-1 font-mono text-2xl tabular-nums', tone ?? 'text-text')}>{value.toLocaleString('ru-RU')}</div>
    </>
  )
  return to ? (
    <Link to={to} className="block rounded border border-grid bg-surface p-4 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
      {body}
    </Link>
  ) : (
    <Card>{body}</Card>
  )
}

function share(part: number, total: number): number {
  return total > 0 ? Math.round((part / total) * 100) : 0
}

function distributionLabel(o: Overview): string {
  return LEVELS.map((l) => `${LEVEL_LABELS[l]}: ${o.distribution[l]}`).join(', ')
}

/** Границы шкалы — из настроек: пороги уровней редактируются, констант в интерфейсе нет. */
function scaleLabel(l: Levels): string {
  return `0–${l.medium - 1} низкий · ${l.medium}–${l.high - 1} средний · ${l.high}–${l.critical - 1} высокий · ${l.critical}–100 критический`
}

function ago(iso: string | null): string {
  if (!iso) return 'не загружен'
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000)
  if (days === 0) return 'сегодня'
  if (days === 1) return 'вчера'
  return `${days} дн. назад`
}

export function OverviewPage() {
  const overview = useOverview()
  // Пороги уровней и подстановка EPSS — только для подписей: обзор показывается и без них.
  const weights = useVmSettings().data?.weights

  if (overview.isLoading) return <FullPageSpinner />
  if (overview.isError || !overview.data) {
    const msg = overview.error instanceof ApiRequestError ? overview.error.message : 'Не удалось загрузить обзор'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => overview.refetch()} /></div>
  }
  const o: Overview = overview.data

  if (o.pairs_all === 0) {
    return (
      <div className="p-6">
        <EmptyState
          icon={ServerCog}
          title="Уязвимостей ещё нет"
          description="Импортируйте хосты и CVE из MaxPatrol VM по API или из файла экспорта — в настройках модуля. Справочники EPSS, NVD, ExploitDB, Metasploit и CISA KEV можно загрузить до или после импорта."
          action={
            <Link to="/settings/vm" className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
              Настроить импорт <ArrowRight size={13} aria-hidden />
            </Link>
          }
        />
      </div>
    )
  }

  const totalPairs = LEVELS.reduce((sum, l) => sum + o.distribution[l], 0)
  const open = OPEN_STATUSES.reduce((sum, st) => sum + o.findings.by_status[st], 0)

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Обзор</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Что чинить первым и чего не хватает данным. Каждое число — ссылка в отфильтрованную таблицу.
          </p>
        </div>
        {o.data.last_import && (
          <div className="text-right text-[11px] text-text-secondary">
            импорт {ago(o.data.last_import.finished_at)}, {o.data.last_import.source === 'vm' ? 'MaxPatrol VM' : o.data.last_import.filename}
          </div>
        )}
      </div>

      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <Stat label="Хостов с уязвимостями" value={o.hosts} to="/vm/vulns?sort=host_asc" />
        <Stat label={o.pairs === o.pairs_all ? 'Пар хост–CVE' : `Пар хост–CVE (всего ${o.pairs_all.toLocaleString('ru-RU')})`} value={o.pairs} to="/vm/vulns" />
        <Stat label="Уникальных CVE" value={o.cves} to="/vm/vulns?sort=cve_asc" />
        <Stat label={`Выше порога ${o.threshold}`} value={o.above_threshold} to="/vm/vulns?sort=risk_desc" tone="text-risk-critical" />
      </div>

      {/* Статусы пар (общий механизм находок): пары, распределение и «выше порога» выше
          считают только учитываемые статусы — принятый риск по умолчанию не в счёт. */}
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <Stat label="Открытые" value={open} to="/vm/vulns" />
        <Stat label="В работе" value={o.findings.by_status.in_work} to="/vm/vulns?status=in_work" />
        <Stat label="Просроченные" value={o.findings.overdue} to="/vm/vulns?overdue=true" tone={o.findings.overdue ? 'text-kind-1' : undefined} />
        <Stat label="Принят риск" value={o.findings.by_status.risk_accepted} to="/vm/vulns?status=risk_accepted" />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
        <Card className="lg:col-span-2">
          <CardHeader title="Распределение по шкале риска" subtitle={weights ? scaleLabel(weights.levels) : 'по порогам уровней из настроек'} />
          {/* Одна полоса на все пары: доли уровней видны сразу, а не по четырём
              полоскам с разным масштабом. Пустой уровень в полосе не рисуется,
              в легенде остаётся с нулём. */}
          <div className="flex h-4 w-full overflow-hidden rounded bg-grid" role="img" aria-label={distributionLabel(o)}>
            {LEVELS.filter((l) => o.distribution[l] > 0).map((l) => (
              <div
                key={l}
                className="h-full"
                style={{ width: `${(o.distribution[l] / totalPairs) * 100}%`, backgroundColor: BAR[l] }}
                title={`${LEVEL_LABELS[l]}: ${o.distribution[l].toLocaleString('ru-RU')} (${share(o.distribution[l], totalPairs)}%)`}
              />
            ))}
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {LEVELS.map((l) => (
              <Link
                key={l}
                to={`/vm/vulns?level=${l}`}
                className="flex items-center gap-2 rounded border border-grid px-3 py-2 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ backgroundColor: BAR[l] }} aria-hidden />
                <span className={cn('text-xs', LEVEL_TEXT[l])}>{LEVEL_LABELS[l]}</span>
                <span className="ml-auto shrink-0 whitespace-nowrap font-mono text-sm tabular-nums text-text">
                  {o.distribution[l].toLocaleString('ru-RU')}
                  <span className="ml-1.5 text-[11px] text-text-secondary">{share(o.distribution[l], totalPairs)}%</span>
                </span>
              </Link>
            ))}
          </div>
          <div className="mt-3 text-xs">
            <Link to="/vm/vulns?kev=true" className="text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
              в каталоге KEV: <span className={cn('font-mono tabular-nums', o.kev_pairs ? 'text-risk-critical' : 'text-text-secondary')}>{o.kev_pairs.toLocaleString('ru-RU')}</span> пар
            </Link>
            <span className="ml-1.5 text-[11px] text-text-secondary">— CVE эксплуатируются в реальных атаках (CISA)</span>
          </div>
        </Card>

        <Card>
          <CardHeader title="CVE, закрывающие больше всего" subtitle="по сумме риска по всем хостам: патч одной снимает больше всего" />
          <table className="w-full text-xs">
            <tbody>
              {o.top_cves.map((c) => (
                <tr key={c.cve_id} className="border-t border-grid/60">
                  <td className="py-1.5 pr-2">
                    <Link to={`/vm/vulns?cve=${c.cve_id}`} className="font-mono text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
                      {c.cve_id}
                    </Link>
                    {c.exploitdb_type && <span className="ml-1.5 text-[10px] text-risk-high">эксплойт</span>}
                  </td>
                  <td className="py-1.5 pr-2 text-right font-mono tabular-nums text-text-secondary">{c.hosts} хост.</td>
                  <td className="py-1.5 pr-2 text-right font-mono tabular-nums text-text-secondary">CVSS {c.cvss ?? '—'}</td>
                  <td className="py-1.5 text-right font-mono tabular-nums text-text">Σ {c.risk_sum.toLocaleString('ru-RU')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card>
          <CardHeader title="Хосты с наибольшим риском" subtitle="по сумме риска всех уязвимостей хоста" />
          <table className="w-full text-xs">
            <tbody>
              {o.top_hosts.map((h) => (
                <tr key={h.host_id} className="border-t border-grid/60">
                  <td className="max-w-[220px] truncate py-1.5 pr-2">
                    <Link to={`/vm/vulns?host_id=${h.host_id}`} className="font-mono text-text hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" title={h.hostname}>
                      {h.hostname}
                    </Link>
                    <span className="ml-1.5 text-[10px] text-text-secondary">{h.zone || 'без зоны'}</span>
                  </td>
                  <td className="py-1.5 pr-2 text-right text-text-secondary">{h.criticality || '—'}</td>
                  <td className="py-1.5 pr-2 text-right font-mono tabular-nums text-text-secondary">{h.pairs} CVE</td>
                  <td className="py-1.5 text-right font-mono tabular-nums text-text">Σ {h.risk_sum.toLocaleString('ru-RU')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Данные" subtitle="из-за чего риск посчитан неточно" />
          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <div className="mb-1.5 flex items-center gap-1.5 text-[11px] text-text-secondary"><Database size={12} aria-hidden /> Справочники</div>
              <ul className="flex flex-col gap-1 text-xs">
                {o.data.refs.map((r) => (
                  <li key={r.name} className="flex items-center justify-between gap-2">
                    <span className="text-text">{REF_TITLES[r.name] ?? r.name}</span>
                    <span className={cn('font-mono text-[11px]', r.stale ? 'text-risk-medium' : 'text-text-secondary')}>
                      {r.records ? `${r.records.toLocaleString('ru-RU')} · ` : ''}{ago(r.loaded_at)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="mb-1.5 flex items-center gap-1.5 text-[11px] text-text-secondary"><AlertTriangle size={12} aria-hidden /> Пропуски</div>
              <ul className="flex flex-col gap-1 text-xs">
                <li className="flex justify-between"><Link to="/vm/vulns?cvss_source=none" className="text-text hover:text-primary">CVE без записи в NVD</Link><span className="font-mono tabular-nums text-text-secondary">{o.data.cves_without_nvd.toLocaleString('ru-RU')}</span></li>
                <li className="flex justify-between"><span className="text-text">CVE без EPSS ({weights ? `взято ${weights.prior_epss.toLocaleString('ru-RU')}` : 'подставлено'})</span><span className="font-mono tabular-nums text-text-secondary">{o.data.cves_without_epss.toLocaleString('ru-RU')}</span></li>
                <li className="flex justify-between"><Link to="/settings/vm#zones" className="text-text hover:text-primary">Зоны без разметки</Link><span className={cn('font-mono tabular-nums', o.data.unmarked_zones ? 'text-risk-medium' : 'text-text-secondary')}>{o.data.unmarked_zones}</span></li>
              </ul>
            </div>
            <div>
              <div className="mb-1.5 flex items-center gap-1.5 text-[11px] text-text-secondary"><ShieldAlert size={12} aria-hidden /> Последний импорт</div>
              {o.data.last_import ? (
                <ul className="flex flex-col gap-1 text-xs text-text-secondary">
                  <li>{new Date(o.data.last_import.finished_at).toLocaleString('ru-RU')}</li>
                  <li>{o.data.last_import.source === 'vm' ? 'MaxPatrol VM по API' : `файл ${o.data.last_import.filename}`}</li>
                  <li className="font-mono tabular-nums">{o.data.last_import.hosts.toLocaleString('ru-RU')} хостов · {o.data.last_import.pairs.toLocaleString('ru-RU')} пар · {o.data.last_import.cves.toLocaleString('ru-RU')} CVE</li>
                </ul>
              ) : (
                <span className="text-xs text-text-secondary">ещё не было</span>
              )}
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}
