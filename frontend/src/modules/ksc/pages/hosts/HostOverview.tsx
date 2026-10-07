import { StatusBadge } from '@/platform/findings/StatusBadge'
import { SeverityBadge } from '@/platform/collector/SeverityBadge'
import { AssetLink } from '@/modules/assets/AssetLink'
import { AGENT_LABELS, BASES_LABELS, CPU_ARCH_LABELS, IN_AD_LABELS, PROTECTION_LABELS, RTP_STATE_LABELS, vmTypeLabel, type HostDetail } from '@/modules/ksc/api/types'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

const COMPONENT_STATUS_LABELS: Record<number, string> = {
  0: 'неизвестно',
  1: 'остановлен',
  2: 'приостановлен',
  3: 'запускается',
  4: 'работает',
  9: 'сбой',
  10: 'не установлен',
  11: 'нет лицензии',
}

function edrLabel(code: number): string {
  return code === 0 ? 'нет данных' : `код ${code}`
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'никогда'
}

/** Вкладка «Обзор» панели хоста: карточка, теги, действующие политики, система, компоненты. */
export function HostOverview({ host: h, serverId }: { host: HostDetail; serverId: number }) {
  return (
    <>
      <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">ID в KSC</dt><dd className="font-mono break-all text-text">{h.host_id}</dd>
        <dt className="text-text-secondary">FQDN</dt><dd className="font-mono break-all text-text">{h.fqdn || '—'}</dd>
        <dt className="text-text-secondary">Домен</dt><dd className="font-mono break-all text-text">{h.domain || '—'}</dd>
        <dt className="text-text-secondary">Группа</dt><dd className="text-text">{h.group}</dd>
        <dt className="text-text-secondary">ОС</dt><dd className="text-text">{h.os || '—'}</dd>
        <dt className="text-text-secondary">IP</dt><dd className="font-mono text-text">{h.ip || '—'}</dd>
        <dt className="text-text-secondary">Агент</dt><dd className="text-text">{AGENT_LABELS[h.agent]}{h.agent_version ? ` · версия ${h.agent_version}` : ''}</dd>
        <dt className="text-text-secondary">Виден в сети</dt><dd className="text-text">{when(h.last_seen_at)}</dd>
        <dt className="text-text-secondary">Продукт</dt><dd className="text-text">{h.product || '—'}{h.product_version ? ` · ${h.product_version}` : ''}</dd>
        <dt className="text-text-secondary">Защита</dt><dd className="text-text">{PROTECTION_LABELS[h.protection]}{h.protection === 'off' ? ` · ${RTP_STATE_LABELS[h.rtp_state] ?? h.rtp_state}` : ''}</dd>
        <dt className="text-text-secondary">Базы</dt><dd className="text-text">{when(h.bases_at)} · {BASES_LABELS[h.bases]}</dd>
        <dt className="text-text-secondary">Полный поиск</dt><dd className="text-text">{when(h.last_fullscan_at)}</dd>
        <dt className="text-text-secondary">Статус KSC</dt><dd className="text-text">{h.status === 'ok' ? 'ок' : h.status === 'warning' ? 'предупреждение' : 'критично'}</dd>
        <dt className="text-text-secondary">Угрозы</dt><dd className="text-text">{h.threats}</dd>
        <dt className="text-text-secondary">Без группы</dt><dd className="text-text">{h.unassigned ? 'да' : 'нет'}</dd>
        <dt className="text-text-secondary">AD</dt><dd className="text-text">{h.in_ad ? IN_AD_LABELS[h.in_ad] : 'нет данных'}</dd>
      </dl>
      <AssetLink source="ksc" hostKey={`${serverId}:${h.host_id}`} className="mb-4 text-[11px]" />

      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Теги</div>
      <div className="mb-4 flex flex-wrap gap-1">
        {h.tags === null && <span className="text-text-secondary">не собраны</span>}
        {h.tags?.length === 0 && <span className="text-text-secondary">нет</span>}
        {h.tags?.map((t) => <span key={t} className="rounded bg-row-hover px-1.5 py-0.5 text-[11px] text-text">{t}</span>)}
      </div>

      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Политики ({h.policies.length})</div>
      <ul className="mb-4 flex flex-col gap-0.5">
        {h.policies.length === 0 && <li className="text-text-secondary">нет действующих политик</li>}
        {h.policies.map((p) => (
          <li key={p.id}>
            <Link to={`/ksc/servers/${serverId}/policies/${p.id}`} className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-row-hover">
              <span className="min-w-0 flex-1 truncate text-text" title={p.name}>{p.name}</span>
              <span className="shrink-0 text-[11px] text-text-secondary">{p.product}</span>
              <span className="shrink-0 text-[11px] text-text-secondary">{p.own ? 'своя' : 'унаследована'}</span>
              {!p.active && <span className="shrink-0 text-[11px] text-risk-medium">неактивна</span>}
            </Link>
          </li>
        ))}
      </ul>

      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Система</div>
      <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">Сборка ОС</dt><dd className="font-mono text-text">{h.extra.os_build || '—'}</dd>
        <dt className="text-text-secondary">Архитектура</dt><dd className="text-text">{CPU_ARCH_LABELS[h.extra.cpu_arch] ?? 'неизвестно'}</dd>
        <dt className="text-text-secondary">Виртуализация</dt><dd className="text-text">{vmTypeLabel(h.extra.vm_type)}</dd>
        <dt className="text-text-secondary">Перезагрузка</dt>
        <dd className={cn('text-text', h.extra.reboot_required && 'text-risk-medium')}>
          {h.extra.reboot_required ? `требуется с ${when(h.extra.reboot_requested_at)}` : 'не требуется'}
        </dd>
        <dt className="text-text-secondary">EDR</dt><dd className="text-text">{edrLabel(h.extra.edr_status)}</dd>
      </dl>

      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Компоненты</div>
      <ul className="flex flex-col gap-0.5">
        {h.components.length === 0 && <li className="text-text-secondary">нет данных</li>}
        {h.components.map(([name, code]) => (
          <li key={name} className="flex items-center justify-between gap-2 py-0.5">
            <span className="truncate text-text" title={name}>{name}</span>
            <span className={cn('shrink-0 text-[11px]', code === 4 ? 'text-kind-accepted' : 'text-risk-high')}>{COMPONENT_STATUS_LABELS[code] ?? code}</span>
          </li>
        ))}
      </ul>
    </>
  )
}

/** Вкладка «Находки» панели хоста: находки хоста со статусами, ссылка ведёт в список находок с фильтром по проверке и хосту. */
export function HostFindings({ host: h, serverId }: { host: HostDetail; serverId: number }) {
  return (
    <>
      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Находки хоста ({h.findings_counted !== h.findings.length ? `учитываются ${h.findings_counted} из ${h.findings.length}` : h.findings.length})</div>
      <ul className="flex flex-col gap-1">
        {h.findings.length === 0 && <li className="text-text-secondary">находок нет</li>}
        {h.findings.map((f) => (
          <li key={f.key}>
            <Link to={`/ksc/servers/${serverId}/findings?check=${f.check}&q=${encodeURIComponent(h.name)}`} className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-row-hover">
              <SeverityBadge severity={f.severity} />
              <span className="truncate text-text">{f.check_title}</span>
              <StatusBadge status={f.status} className="ml-auto shrink-0" />
            </Link>
          </li>
        ))}
      </ul>
    </>
  )
}
