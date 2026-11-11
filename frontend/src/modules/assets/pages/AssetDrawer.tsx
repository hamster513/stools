import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Monitor, Pin, PinOff, Trash2, X } from 'lucide-react'
import { SoftwareInventory } from './SoftwareInventory'
import { ApiRequestError } from '@/api/client'
import { useQueryClient } from '@tanstack/react-query'
import { invalidateDiscrepancies, NETWORK_PICK_LIMIT, useAsset, useAssets, useDeleteAsset, useDetachObservation, useMergeAssets, useNetwork, useNetworkSearch, usePatchAsset, usePinField } from '@/modules/assets/api/queries'
import {
  CODE_LABELS,
  CRITICALITIES,
  CLUSTER_LABELS,
  CRITICALITY_LABELS,
  defaultCidr,
  MARK_TEXT,
  placementText,
  SOURCE_LABELS,
  type AssetDetail,
  type Criticality,
  type Discrepancy,
  type HostUser,
  type Observation,
  type PinnableField,
} from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { FindingWorkBlock } from '@/platform/findings/FindingWorkBlock'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const PIN_FIELDS: { field: PinnableField; label: string; mono?: boolean }[] = [
  { field: 'name', label: 'Имя' },
  { field: 'fqdn', label: 'FQDN', mono: true },
  { field: 'domain', label: 'Домен', mono: true },
  { field: 'ip', label: 'IP', mono: true },
  { field: 'os', label: 'ОС' },
]

/** Расхождения о данных источников — тоном «внимание», о покрытии — тоном риска. */
const CODE_TEXT: Record<string, string> = {
  stale: 'text-kind-1',
  conflict: 'text-kind-2',
  no_av: 'text-risk-high',
  ad_inactive: 'text-risk-medium',
  no_network: 'text-risk-medium',
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

function title(a: { id: number; name: string; fqdn: string; ip: string }): string {
  return a.name || a.fqdn || a.ip || `актив #${a.id}`
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <div className="mt-4 mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{children}</div>
}

function Confirm({ label, text, action, danger, pending, onConfirm, onCancel }: { label: string; text: string; action: string; danger?: boolean; pending: boolean; onConfirm: () => void; onCancel: () => void }) {
  return (
    <div role="dialog" aria-label={label} className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">{label}</div>
        <p className="mb-4 text-xs text-text-secondary">{text}</p>
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel}>Отмена</Button>
          <Button variant={danger ? 'danger' : 'primary'} loading={pending} onClick={onConfirm}>{action}</Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Расхождения — находки статусов платформы: у строки статус, щелчок раскрывает «Работу с находкой».
 * Расхождения с неучитываемым статусом (принят риск, ложное) — приглушённо, ниже действующих.
 */
function DiscrepancyList({ a }: { a: AssetDetail }) {
  const qc = useQueryClient()
  const [openKey, setOpenKey] = useState<string | null>(null)
  const active = a.discrepancies.filter((d) => d.counted)
  const decided = a.discrepancies.filter((d) => !d.counted)
  const row = (d: Discrepancy, i: number) => {
    const opened = openKey === d.key
    return (
      <li key={`${d.key}:${i}`} className={cn(!d.counted && 'opacity-60')}>
        <button type="button" onClick={() => setOpenKey(opened ? null : d.key)} aria-expanded={opened}
          className="flex w-full items-start gap-2 rounded px-1 py-0.5 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <span className={cn('shrink-0', CODE_TEXT[d.code])}>{CODE_LABELS[d.code]}</span>
          <span className="min-w-0 flex-1 text-text-secondary">{d.text}</span>
          {d.overdue && <span className="shrink-0 text-kind-1">просрочено</span>}
          <StatusBadge status={d.status} className="shrink-0" />
        </button>
        {opened && (
          <div className="mt-1 mb-2 ml-1 border-l border-grid pl-3">
            <FindingWorkBlock module="assets" scopeId={0} findingKey={d.key} title={`${title(a)}: ${d.text}`} severity=""
              onChanged={() => invalidateDiscrepancies(qc)} />
          </div>
        )}
      </li>
    )
  }
  return (
    <>
      <SectionTitle>Расхождения ({active.length}{decided.length > 0 ? ` · решено ${decided.length}` : ''})</SectionTitle>
      <ul className="flex flex-col gap-1">
        {active.map(row)}
        {decided.map(row)}
      </ul>
    </>
  )
}

function CanonicalCard({ a, write }: { a: AssetDetail; write: boolean }) {
  const pin = usePinField(a.id)
  return (
    <>
      <dl className="grid grid-cols-[auto_1fr_auto] items-center gap-x-3 gap-y-1">
        {PIN_FIELDS.map(({ field, label, mono }) => {
          const pinned = Boolean(a.pinned[field])
          return (
            <span key={field} className="contents">
              <dt className="text-text-secondary">{label}</dt>
              <dd className={cn('break-all text-text', mono && 'font-mono')}>{a[field] || '—'}</dd>
              <dd>
                {write ? (
                  <button
                    type="button"
                    onClick={() => pin.mutate({ field, pinned: !pinned })}
                    disabled={pin.isPending}
                    aria-pressed={pinned}
                    aria-label={pinned ? `Открепить поле «${label}»` : `Закрепить поле «${label}»`}
                    title={pinned ? 'Закреплено: синхронизация не меняет. Открепить' : 'Закрепить текущее значение'}
                    className={cn('rounded p-1 hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', pinned ? 'text-primary' : 'text-text-secondary/50')}
                  >
                    {pinned ? <Pin size={13} aria-hidden /> : <PinOff size={13} aria-hidden />}
                  </button>
                ) : (
                  pinned && <Pin size={13} className="text-text-secondary" aria-label="закреплено" />
                )}
              </dd>
            </span>
          )
        })}
        <dt className="text-text-secondary">Сеть</dt>
        <dd className="col-span-2 text-text">
          {a.network ? (
            <>
              <Link to={`/assets/networks?id=${a.network.id}`} className="font-mono hover:text-primary hover:underline">{a.network.cidr}</Link>
              {a.network.title && ` — ${a.network.title}`}
              {a.network_manual && <span className="text-text-secondary"> (задана вручную)</span>}
            </>
          ) : '—'}
          {/* Адрес не входит ни в одну сеть: создать её тут же; после сохранения актив привяжется сам. */}
          {!a.network && a.ip && write && (
            <Link to={`/assets/networks?new=${encodeURIComponent(defaultCidr(a.ip))}`} className="ml-2 text-[11px] text-primary hover:underline">создать сеть {defaultCidr(a.ip)}</Link>
          )}
        </dd>
        {/* Где хост — по группе его сети: группа и её признаки (расположение, доступ из интернета). */}
        {a.network && (
          <>
            <dt className="text-text-secondary">Группа сети</dt>
            <dd className="col-span-2 text-text">{a.network.zone ? (a.network.zone_title && a.network.zone_title !== a.network.zone ? `${a.network.zone} — ${a.network.zone_title}` : a.network.zone) : 'без группы'}</dd>
            <dt className="text-text-secondary">Расположение</dt>
            <dd className="col-span-2 text-text">{placementText(a.network) || 'не задано'}</dd>
          </>
        )}
        {a.cluster && (
          <>
            <dt className="text-text-secondary">Кластер</dt>
            <dd className="col-span-2 text-text">{CLUSTER_LABELS[a.cluster]}{a.cluster !== 'node' && <span className="text-text-secondary"> — виртуальное имя, не хост: без агента антивируса, входов и своего адреса</span>}</dd>
          </>
        )}
        <dt className="text-text-secondary">Виден</dt>
        <dd className="col-span-2 text-text">впервые {day(a.first_seen)}, последний раз {day(a.last_seen)}</dd>
      </dl>
      {pin.error && <p className="mt-1 text-kind-1">{pin.error.message}</p>}
    </>
  )
}

function Cell({ o, field, mono }: { o: Observation; field: 'name' | 'fqdn' | 'ip'; mono?: boolean }) {
  const mark = o.marks[field]
  return (
    <td className={cn('px-1.5 py-1 break-all', mono && 'font-mono', mark ? cn(MARK_TEXT[mark], 'font-semibold') : 'text-text')} title={mark === 'stale' ? 'устарело' : mark === 'conflict' ? 'расходится с другими источниками' : undefined}>
      {o[field] || '—'}
    </td>
  )
}

// Сумма ширин по умолчанию — 560 px: влезает в содержимое панели (600 px без рамки и отступов, 567 px) без прокрутки.
const SOURCE_COLUMNS: ColumnDef[] = [
  { key: 'source', label: 'Источник', width: 72 },
  { key: 'name', label: 'Имя', width: 80 },
  { key: 'fqdn', label: 'FQDN', width: 112, flex: true },
  { key: 'ip', label: 'IP', width: 88 },
  { key: 'os', label: 'ОС', width: 72 },
  { key: 'seen', label: 'Видел', width: 72 },
]
const DETACH_COLUMNS: ColumnDef[] = [...SOURCE_COLUMNS, { key: 'detach', label: 'Отвязать', width: 64, resizable: false }]

function SourcesTable({ a, write, onDetach }: { a: AssetDetail; write: boolean; onDetach: (o: Observation) => void }) {
  const canDetach = write && a.observations.length > 1
  const cols = useColumnWidths('assets-sources-columns', canDetach ? DETACH_COLUMNS : SOURCE_COLUMNS)
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]" style={cols.tableStyle}>
        <ColGroup cols={cols} />
        <thead className="text-text-secondary">
          <tr>
            <ResizableHeader cols={cols} className="px-1.5 py-1" content={{ detach: <span className="sr-only">Отвязать</span> }} />
          </tr>
        </thead>
        <tbody>
          {a.observations.map((o) => (
            <tr key={o.id} className={cn('border-t border-grid align-top', o.gone_at && 'opacity-50')}>
              <td className="truncate px-1.5 py-1 text-text" title={SOURCE_LABELS[o.source]}>{SOURCE_LABELS[o.source]}</td>
              <Cell o={o} field="name" />
              <Cell o={o} field="fqdn" mono />
              <Cell o={o} field="ip" mono />
              <td className="px-1.5 py-1 break-words text-text-secondary">{o.os || '—'}</td>
              <td className="px-1.5 py-1 break-words text-text-secondary">{day(o.seen_at)}{o.gone_at && <div>пропал {day(o.gone_at)}</div>}</td>
              {canDetach && (
                <td className="px-1.5 py-1">
                  <button type="button" onClick={() => onDetach(o)} className="rounded px-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">отвязать</button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function LinksBlock({ a }: { a: AssetDetail }) {
  const { links } = a
  const ksc = a.observations.find((o) => o.source === 'ksc' && !o.gone_at)
  const components = ksc && Array.isArray(ksc.extra.components) ? (ksc.extra.components as [string, number][]) : []
  const kscTags = ksc && Array.isArray(ksc.extra.tags) ? (ksc.extra.tags as string[]) : []
  const any = links.ad_domain_id !== null || links.ksc_host_id !== null || links.vm_host_id !== null
  return (
    <>
      <SectionTitle>Где засветился</SectionTitle>
      {!any && <p className="text-text-secondary">ни в одном модуле</p>}
      <ul className="flex flex-col gap-1">
        {links.ad_domain_id !== null && (
          <li>
            <Link to={`/ad/domains/${links.ad_domain_id}/findings?q=${encodeURIComponent(links.ad_query ?? '')}`} className="text-text hover:text-primary">
              AD: находок по компьютеру — {links.ad_finding_count ?? 'нет снапшота'}
            </Link>
          </li>
        )}
        {links.ksc_host_id !== null && (
          <li>
            {links.ksc_server_id !== null ? (
              <Link to={`/ksc/servers/${links.ksc_server_id}/hosts`} className="text-text hover:text-primary">Антивирус: хост {ksc?.name || links.ksc_host_id}</Link>
            ) : (
              <span className="text-text">Антивирус: хост {links.ksc_host_id}</span>
            )}
            <div className="text-text-secondary">
              {ksc && <>защита: {String(ksc.extra.protection ?? '—')}, агент {ksc.extra.agent_alive ? 'на связи' : 'не на связи'}</>}
              {components.length > 0 && <> · компонентов {components.length}, работают {components.filter(([, code]) => code === 4).length}</>}
              {kscTags.length > 0 && <> · теги: {kscTags.join(', ')}</>}
            </div>
          </li>
        )}
        {links.vm_host_id !== null && (
          <li>
            <Link to={`/vm/vulns?host_id=${links.vm_host_id}`} className="text-text hover:text-primary">VM: CVE на хосте — {links.vm_cve_count ?? 0}</Link>
          </li>
        )}
      </ul>
    </>
  )
}

function UserLinks({ users }: { users: HostUser[] }) {
  return (
    <ul className="flex flex-col gap-0.5">
      {users.map((u) => (
        <li key={`${u.user_id}:${u.kind}`} className="flex items-baseline gap-2">
          <Link to={`/assets/users?user=${u.user_id}`} className="font-mono text-text hover:text-primary hover:underline">{u.sam || `пользователь #${u.user_id}`}</Link>
          {u.display_name && <span className="min-w-0 truncate text-text-secondary">{u.display_name}</span>}
          {u.local && <span className="shrink-0 rounded border border-grid px-1 text-[10px] text-text-secondary">локальная</span>}
          {u.gone && <span className="shrink-0 text-text-secondary">{u.kind === 'owner' ? 'был владельцем' : u.kind === 'session' ? (u.active ? 'был в системе' : 'заходил раньше') : 'был в локальной группе'}, до {day(u.seen_at)}</span>}
        </li>
      ))}
    </ul>
  )
}

/**
 * Пользователи хоста из последней синхронизации (KSC): в системе на момент сбора, заходившие раньше, владелец;
 * `users: null` — пользователи по хосту не собраны (это не «пусто»). Пропавшие связи — приглушённо, внизу.
 */
function UsersBlock({ a }: { a: AssetDetail }) {
  const live = (a.users ?? []).filter((u) => !u.gone)
  const groups: { label: string; users: HostUser[] }[] = [
    { label: 'В системе на момент сбора', users: live.filter((u) => u.kind === 'session' && u.active) },
    { label: 'Заходили раньше', users: live.filter((u) => u.kind === 'session' && !u.active) },
    { label: 'Владелец по KSC', users: live.filter((u) => u.kind === 'owner') },
    { label: 'В локальных группах', users: live.filter((u) => u.kind === 'local_group') },
  ]
  const gone = (a.users ?? []).filter((u) => u.gone)
  // Одна группа может прийти от нескольких наблюдений KSC: без повторов, «в системе», если так хоть в одном.
  const sessionGroups = new Map<string, { label: string; active: boolean }>()
  for (const g of a.session_groups ?? []) {
    const key = g.sid || g.sam
    sessionGroups.set(key, { label: g.sam || g.sid, active: g.active || (sessionGroups.get(key)?.active ?? false) })
  }
  return (
    <>
      <SectionTitle>Пользователи</SectionTitle>
      {a.users === null && <p className="text-text-secondary">пользователи не собраны — нет снапшота антивируса со сбором пользователей по этому хосту</p>}
      {a.users?.length === 0 && <p className="text-text-secondary">пользователей нет</p>}
      <div className="flex flex-col gap-2">
        {groups.filter((g) => g.users.length > 0).map((g) => (
          <div key={g.label}>
            <div className="mb-0.5 text-text-secondary">{g.label} ({g.users.length})</div>
            <UserLinks users={g.users} />
          </div>
        ))}
        {gone.length > 0 && (
          <div className="opacity-60">
            <div className="mb-0.5 text-text-secondary">Больше не видны ({gone.length})</div>
            <UserLinks users={gone} />
          </div>
        )}
      </div>
      {a.owner_unresolved && <p className="mt-1 text-kind-1">владелец задан в KSC, но его нет в списке пользователей хоста</p>}
      {sessionGroups.size > 0 && (
        <p className="mt-1 text-text-secondary">
          Группы с сеансом: {[...sessionGroups.values()].map((g) => `${g.label}${g.active ? ' (в системе)' : ''}`).join(', ')}
        </p>
      )}
      {/* Фильтр списка по хосту ловит и устаревшие и пропавшие связи — ссылка нужна и когда пользователи не собраны. */}
      {(a.users === null || a.users.length > 0) && <Link to={`/assets/users?host_id=${a.id}`} className="mt-1 inline-block text-primary hover:underline">все пользователи хоста</Link>}
      {/* Локальные группы хоста — из VM, не из KSC: ссылка не зависит от того, собраны ли пользователи. */}
      <Link to={`/assets/groups?host_id=${a.id}`} className="mt-1 ml-3 inline-block text-primary hover:underline">локальные группы хоста</Link>
    </>
  )
}

function ManualFields({ a, write }: { a: AssetDetail; write: boolean }) {
  const patch = usePatchAsset(a.id)
  // Начальные значения — из карточки; после сохранения форма пересоздаётся по updated_at (key у вызова).
  const [criticality, setCriticality] = useState<Criticality | ''>(a.criticality)
  const [tags, setTags] = useState(a.tags.join(', '))
  const [note, setNote] = useState(a.note)
  // '' — сеть по адресу (самая узкая, содержащая IP); иначе id сети, выбранной вручную.
  const currentNetwork = a.network_manual && a.network ? String(a.network.id) : ''
  const [network, setNetwork] = useState(currentNetwork)

  if (!write) {
    return (
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">Критичность</dt><dd className="text-text">{a.criticality ? CRITICALITY_LABELS[a.criticality] : CRITICALITY_LABELS.none}</dd>
        <dt className="text-text-secondary">Теги</dt><dd className="text-text">{a.tags.length ? a.tags.join(', ') : '—'}</dd>
        <dt className="text-text-secondary">Заметка</dt><dd className="whitespace-pre-line text-text">{a.note || '—'}</dd>
      </dl>
    )
  }
  const dirty = criticality !== a.criticality || tags !== a.tags.join(', ') || note !== a.note || network !== currentNetwork
  const networkPatch = network === currentNetwork ? {} : network ? { network_id: Number(network) } : { network_id: null, network_manual: false }
  return (
    <div className="flex flex-col gap-2">
      <label className="block">
        <span className="mb-1 block text-text-secondary">Критичность</span>
        <select value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality | '')} className={cn(FIELD, 'text-xs')}>
          <option value="">{CRITICALITY_LABELS.none}</option>
          {CRITICALITIES.map((c) => <option key={c} value={c}>{CRITICALITY_LABELS[c]}</option>)}
        </select>
      </label>
      <label className="block">
        <span className="mb-1 block text-text-secondary">Теги через запятую</span>
        <input value={tags} onChange={(e) => setTags(e.target.value)} className={cn(FIELD, 'text-xs')} />
      </label>
      <NetworkPicker value={network} onChange={setNetwork} />
      <label className="block">
        <span className="mb-1 block text-text-secondary">Заметка</span>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} className={cn(FIELD, 'text-xs')} />
      </label>
      <div className="flex items-center gap-2">
        <Button variant="primary" disabled={!dirty} loading={patch.isPending} onClick={() => patch.mutate({ criticality, tags: tags.split(',').map((t) => t.trim()).filter(Boolean), note, ...networkPatch })}>Сохранить</Button>
        {patch.error && <span className="text-kind-1">{patch.error.message}</span>}
      </div>
    </div>
  )
}

/**
 * Выбор сети актива: сетей тысячи, поэтому — поиск (адрес, имя, тег, VLAN) и первые совпадения; выбранная сеть
 * подгружается своей карточкой и видна всегда. `value`: '' — по адресу, иначе id сети.
 */
function NetworkPicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [input, setInput] = useState('')
  const q = useDebouncedValue(input.trim(), 250)
  const found = useNetworkSearch(q)
  const chosen = useNetwork(value ? Number(value) : null)
  const items = found.data?.items ?? []
  const label = (n: { cidr: string; title: string; zone: string | null }) => `${n.cidr}${n.title ? ` — ${n.title}` : ''}${n.zone ? ` · ${n.zone}` : ''}`
  return (
    <div className="block">
      <span className="mb-1 block text-text-secondary">Сеть</span>
      <div className="mb-1 flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-text">
          {value ? (chosen.data ? label(chosen.data) : `сеть #${value}`) : 'по адресу — самая узкая сеть, содержащая IP'}
        </span>
        {value && <button type="button" onClick={() => onChange('')} className="shrink-0 rounded px-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">по адресу</button>}
      </div>
      <input value={input} onChange={(e) => setInput(e.target.value)} maxLength={200} placeholder="найти сеть: адрес, CIDR, имя, тег, VLAN" aria-label="Поиск сети" className={cn(FIELD, 'text-xs')} />
      {q && (
        <ul className="mt-1 flex max-h-48 flex-col overflow-y-auto">
          {found.isLoading && <li className="text-text-secondary">поиск…</li>}
          {found.error && <li className="text-kind-1">{found.error.message}</li>}
          {!found.isLoading && !found.error && items.length === 0 && <li className="text-text-secondary">не найдено</li>}
          {items.map((n) => (
            <li key={n.id}>
              <button type="button" onClick={() => { onChange(String(n.id)); setInput('') }} aria-pressed={String(n.id) === value} className={cn('w-full truncate rounded px-1.5 py-1 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', String(n.id) === value ? 'text-primary' : 'text-text')}>
                {label(n)}
              </button>
            </li>
          ))}
          {found.data && found.data.total > items.length && <li className="px-1.5 text-text-secondary">показаны первые {NETWORK_PICK_LIMIT} из {found.data.total} — уточните поиск</li>}
        </ul>
      )}
    </div>
  )
}

/** Поиск второго актива для объединения: наблюдения найденного переедут в этот. */
function MergePicker({ a, onPick }: { a: AssetDetail; onPick: (other: { id: number; label: string }) => void }) {
  const [input, setInput] = useState('')
  const q = useDebouncedValue(input.trim(), 250)
  const found = useAssets({ q: q || undefined })
  const items = (found.data?.pages[0]?.items ?? []).filter((i) => i.id !== a.id).slice(0, 8)
  return (
    <div className="flex flex-col gap-1">
      <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Имя, FQDN или IP второго актива" aria-label="Поиск актива для объединения" className={cn(FIELD, 'text-xs')} />
      {q && (
        <ul className="flex flex-col">
          {found.isLoading && <li className="text-text-secondary">поиск…</li>}
          {!found.isLoading && items.length === 0 && <li className="text-text-secondary">не найдено</li>}
          {items.map((i) => (
            <li key={i.id}>
              <button type="button" onClick={() => onPick({ id: i.id, label: title(i) })} className="flex w-full items-center justify-between gap-2 rounded px-1.5 py-1 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
                <span className="truncate text-text">{title(i)}</span>
                <span className="shrink-0 font-mono text-text-secondary">{i.ip || i.fqdn}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** Карточка актива справа (спека §6): каноническое с закреплением, наблюдения по источникам с подсветкой
 * расхождений, ссылки в модули, ручные поля, объединение и отвязка. */
export function AssetDrawer({ assetId, onClose, onOpenAsset }: { assetId: number | null; onClose: () => void; onOpenAsset: (id: number) => void }) {
  const open = assetId !== null
  const { write } = useCan()
  const detail = useAsset(assetId)
  const merge = useMergeAssets(assetId ?? 0)
  const detach = useDetachObservation()
  const remove = useDeleteAsset()
  const [mergeWith, setMergeWith] = useState<{ id: number; label: string } | null>(null)
  const [detaching, setDetaching] = useState<Observation | null>(null)
  const [deleting, setDeleting] = useState(false)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { if (open) closeRef.current?.focus(); setMergeWith(null); setDetaching(null); setDeleting(false) }, [open, assetId])
  const a = detail.data
  const err = merge.error ?? detach.error ?? remove.error

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Актив" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[600px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {open && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <Monitor size={16} className="shrink-0 text-text-secondary" aria-hidden />
                <span className="truncate text-sm text-text">{a ? title(a) : `актив #${assetId}`}</span>
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {detail.error && <p className="text-kind-1">{detail.error instanceof ApiRequestError ? detail.error.message : 'Не удалось загрузить актив'}</p>}
              {a && (
                <>
                  {a.merged_into !== null && (
                    <p className="mb-3 rounded border border-grid px-3 py-2 text-text-secondary">
                      Актив объединён с <button type="button" className="text-text underline hover:text-primary" onClick={() => { if (a.merged_into !== null) onOpenAsset(a.merged_into) }}>активом #{a.merged_into}</button>.
                    </p>
                  )}
                  <CanonicalCard a={a} write={write && a.merged_into === null} />

                  {a.discrepancies.length > 0 && <DiscrepancyList key={a.id} a={a} />}

                  <SectionTitle>По источникам</SectionTitle>
                  <SourcesTable a={a} write={write && a.merged_into === null} onDetach={setDetaching} />

                  <LinksBlock a={a} />
                  <UsersBlock a={a} />
                  <SoftwareInventory key={a.id} assetId={a.id} />

                  <SectionTitle>Ручные поля</SectionTitle>
                  <ManualFields key={`${a.id}:${a.updated_at}`} a={a} write={write && a.merged_into === null} />

                  {write && a.merged_into === null && (
                    <>
                      <SectionTitle>Объединить с другим активом</SectionTitle>
                      <MergePicker a={a} onPick={setMergeWith} />
                      <SectionTitle>Удалить актив</SectionTitle>
                      <Button variant="ghost" className="text-risk-high" onClick={() => setDeleting(true)}><Trash2 size={13} aria-hidden /> Удалить актив</Button>
                    </>
                  )}
                  {err && <p className="mt-2 text-kind-1">{err.message}</p>}
                </>
              )}
            </div>
          </>
        )}
      </aside>
      {a && mergeWith && (
        <Confirm
          label={`Объединить «${mergeWith.label}» с «${title(a)}»?`}
          text={`Наблюдения «${mergeWith.label}» переедут в этот актив, теги объединятся, заметка допишется; «${mergeWith.label}» исчезнет из списка.`}
          action="Объединить"
          pending={merge.isPending}
          onCancel={() => setMergeWith(null)}
          onConfirm={() => merge.mutate(mergeWith.id, { onSuccess: () => setMergeWith(null) })}
        />
      )}
      {a && deleting && (
        <Confirm
          label={`Удалить «${title(a)}»?`}
          text="Актив исчезнет вместе с наблюдениями источников. Если источник его всё ещё видит, он вернётся при следующей синхронизации — удаление чистит реестр, а не прячет хост."
          action="Удалить"
          danger
          pending={remove.isPending}
          onCancel={() => setDeleting(false)}
          onConfirm={() => remove.mutate(a.id, { onSuccess: () => { setDeleting(false); onClose() } })}
        />
      )}
      {a && detaching && (
        <Confirm
          label={`Отвязать наблюдение ${SOURCE_LABELS[detaching.source]}?`}
          text={`Наблюдение «${detaching.name || detaching.fqdn || detaching.ip || detaching.source_key}» станет отдельным активом и останется им при следующих синхронизациях.`}
          action="Отвязать"
          danger
          pending={detach.isPending}
          onCancel={() => setDetaching(null)}
          onConfirm={() => detach.mutate(detaching.id, { onSuccess: (fresh) => { setDetaching(null); onOpenAsset(fresh.id) } })}
        />
      )}
    </>
  )
}
