import type { ReactNode } from 'react'
import { AlertTriangle, ServerCog, ShieldCheck, ShieldOff } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useKscSettings, useServer, useServers } from '@/modules/ksc/api/queries'
import type { ServerAdmin, ServerCert, ServerData, ServerSecondaryServer, ServerUpdateAgent } from '@/modules/ksc/api/types'
import { SeverityBadge } from '@/modules/ksc/components/SeverityBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'никогда'
}

function FindingBadges({ findings, serverId }: { findings: ServerData['findings']; serverId: number }) {
  if (findings.length === 0) return null
  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {findings.map((f) => (
        <Link key={f.key} to={`/ksc/servers/${serverId}/findings?check=${f.check}`}>
          <SeverityBadge severity={f.severity} />
        </Link>
      ))}
    </div>
  )
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded border border-grid bg-surface p-4">
      <h2 className="mb-3 text-sm font-semibold text-text">{title}</h2>
      {children}
    </section>
  )
}

function TwoFactorBlock({ data, serverId }: { data: ServerData; serverId: number }) {
  const findings = data.findings.filter((f) => f.check === 'KSC_2FA_OFF')
  const value = data.two_factor_required_for_all
  const Icon = value === true ? ShieldCheck : value === false ? ShieldOff : AlertTriangle
  const text = value === true ? 'обязательна для всех' : value === false ? 'не обязательна для всех' : 'нет данных'
  const color = value === true ? 'text-kind-accepted' : value === false ? 'text-risk-high' : 'text-text-secondary'
  return (
    <Block title="Двухэтапная проверка">
      <div className={cn('flex items-center gap-2 text-sm', color)}>
        <Icon size={16} aria-hidden />
        {text}
      </div>
      <FindingBadges findings={findings} serverId={serverId} />
    </Block>
  )
}

function AdminsBlock({ admins, findings, serverId }: { admins: ServerAdmin[]; findings: ServerData['findings']; serverId: number }) {
  const findingsFor = (account: string) => findings.filter((f) => (f.check === 'KSC_INTERNAL_ADMIN' || f.check === 'KSC_ADMINS') && f.target === account)
  return (
    <Block title="Администраторы">
      {admins.length === 0 ? (
        <EmptyState icon={ShieldCheck} title="Держателей административных ролей нет" description="В выгрузке нет ролей Main Administrator / Administrator, либо секция не собрана." />
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 text-left">Учётка</th>
              <th className="py-1.5 pr-3 text-left">Роль</th>
              <th className="py-1.5 pr-3 text-left">Группа</th>
              <th className="py-1.5 text-left">Находки</th>
            </tr>
          </thead>
          <tbody>
            {admins.map((a, i) => (
              <tr key={`${a.account}-${i}`} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">
                  {a.account}
                  {a.internal && <span className="ml-1.5 rounded border border-grid px-1 py-0.5 text-[10px] text-text-secondary">внутренняя</span>}
                </td>
                <td className="py-2 pr-3 text-text-secondary">{a.role}</td>
                <td className="py-2 pr-3 text-text-secondary">{a.group || '—'}</td>
                <td className="py-2"><FindingBadges findings={findingsFor(a.account)} serverId={serverId} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Block>
  )
}

function CertsBlock({ certs, findings, serverId, certDays }: { certs: ServerCert[]; findings: ServerData['findings']; serverId: number; certDays: number }) {
  const findingsFor = (c: ServerCert) => findings.filter((f) => f.check === 'SERVER_CERT' && f.target === `сертификат ${c.function}: ${c.subject}`)
  const daysColor = (days: number) => (days < 0 ? 'text-risk-critical' : days <= certDays ? 'text-risk-high' : 'text-text')
  return (
    <Block title="Сертификаты">
      {certs.length === 0 ? (
        <EmptyState icon={ShieldCheck} title="Сертификатов нет" description="Секция не собрана или сервер не отдал ни одного сертификата." />
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 text-left">Назначение</th>
              <th className="py-1.5 pr-3 text-left">Субъект</th>
              <th className="py-1.5 pr-3 text-left">Истекает</th>
              <th className="py-1.5 pr-3 text-left">Дней осталось</th>
              <th className="py-1.5 text-left">Находки</th>
            </tr>
          </thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.function} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{c.function}</td>
                <td className="py-2 pr-3 font-mono break-all text-text-secondary">{c.subject}</td>
                <td className="py-2 pr-3 text-text-secondary">{when(c.not_after)}</td>
                <td className={cn('py-2 pr-3 font-mono tabular-nums', daysColor(c.days_left))}>{c.days_left}</td>
                <td className="py-2"><FindingBadges findings={findingsFor(c)} serverId={serverId} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Block>
  )
}

function SecondaryServersBlock({ servers, findings, serverId }: { servers: ServerSecondaryServer[]; findings: ServerData['findings']; serverId: number }) {
  const findingsFor = (s: ServerSecondaryServer) => findings.filter((f) => f.check === 'SECONDARY_SERVER_STALE' && f.target === s.name)
  return (
    <Block title="Подчинённые серверы">
      {servers.length === 0 ? (
        <p className="text-xs text-text-secondary">Подчинённых серверов нет — иерархия из одного сервера, либо секция не собрана.</p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 text-left">Сервер</th>
              <th className="py-1.5 pr-3 text-left">Адрес</th>
              <th className="py-1.5 pr-3 text-left">Версия</th>
              <th className="py-1.5 pr-3 text-left">На связи</th>
              <th className="py-1.5 text-left">Находки</th>
            </tr>
          </thead>
          <tbody>
            {servers.map((s, i) => (
              <tr key={`${s.name}-${i}`} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{s.name}</td>
                <td className="py-2 pr-3 font-mono text-text-secondary">{s.address || '—'}</td>
                <td className="py-2 pr-3 text-text-secondary">{s.version || '—'}</td>
                <td className="py-2 pr-3 text-text-secondary">{when(s.last_connected)}</td>
                <td className="py-2"><FindingBadges findings={findingsFor(s)} serverId={serverId} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Block>
  )
}

function UpdateAgentsBlock({ agents }: { agents: ServerUpdateAgent[] }) {
  return (
    <Block title="Точки распространения">
      {agents.length === 0 ? (
        <p className="text-xs text-text-secondary">Точек распространения нет, либо секция не собрана.</p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 text-left">Хост</th>
              <th className="py-1.5 text-left">Группа</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a, i) => (
              <tr key={`${a.host}-${i}`} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{a.host}</td>
                <td className="py-2 text-text-secondary">{a.group || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Block>
  )
}

function WarningsBlock({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null
  return (
    <Block title="Предупреждения сборщика">
      <ul className="flex flex-col gap-1 text-xs text-risk-medium">
        {warnings.map((w, i) => (
          <li key={i} className="flex items-start gap-1.5"><AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden /> {w}</li>
        ))}
      </ul>
    </Block>
  )
}

/** Сервер KSC: 2FA, администраторы, внутренние учётки, сертификаты, иерархия, точки распространения. */
export function ServerPage({ serverId }: { serverId: number }) {
  const servers = useServers()
  const server = servers.data?.find((s) => s.id === serverId)
  const snapshotId = server?.last_snapshot_id ?? undefined
  const data = useServer(snapshotId)
  const settings = useKscSettings()
  const certDays = settings.data?.config.cert_days ?? 60

  if (servers.isLoading) return <FullPageSpinner />
  if (snapshotId === undefined) {
    return <div className="p-6"><EmptyState icon={ServerCog} title="Снапшотов нет" description="Загрузите выгрузку или запустите сбор из KSC в настройках модуля." /></div>
  }
  if (data.isLoading) return <FullPageSpinner />
  if (data.isError || !data.data) {
    const msg = data.error instanceof ApiRequestError ? data.error.message : 'Не удалось загрузить сервер KSC'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => data.refetch()} /></div>
  }
  const d = data.data

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Сервер KSC</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Двухэтапная проверка, административные роли, сертификаты и иерархия серверов снапшота #{snapshotId}.</p>
      </div>
      <div className="flex flex-col gap-4">
        <TwoFactorBlock data={d} serverId={serverId} />
        <AdminsBlock admins={d.admins} findings={d.findings} serverId={serverId} />
        <CertsBlock certs={d.certs} findings={d.findings} serverId={serverId} certDays={certDays} />
        <SecondaryServersBlock servers={d.secondary_servers} findings={d.findings} serverId={serverId} />
        <UpdateAgentsBlock agents={d.update_agents} />
        <WarningsBlock warnings={d.warnings} />
      </div>
    </div>
  )
}
