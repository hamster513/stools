import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Monitor, Pin, PinOff, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAsset, useAssets, useDetachObservation, useMergeAssets, useNetworks, usePatchAsset, usePinField } from '@/modules/assets/api/queries'
import {
  CODE_LABELS,
  CRITICALITIES,
  CRITICALITY_LABELS,
  defaultCidr,
  MARK_TEXT,
  SOURCE_LABELS,
  type AssetDetail,
  type Criticality,
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
  unreachable: 'text-risk-high',
  unknown_host: 'text-risk-high',
  dns_orphan: 'text-risk-medium',
  no_network: 'text-risk-medium',
}

function day(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString('ru-RU') : '—'
}

function title(a: { id: number; name: string; fqdn: string; ip: string }): string {
  return a.name || a.fqdn || a.ip || `актив #${a.id}`
}

function SectionTitle({ children }: { children: ReactNode }) {
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
          {a.network ? `${a.network.cidr}${a.network.title ? ` — ${a.network.title}` : ''}${a.network.zone ? ` · ${a.network.zone}` : ''}${a.network_manual ? ' (задана вручную)' : ''}` : '—'}
          {/* Адрес не входит ни в одну сеть: создать её тут же; после сохранения актив привяжется сам. */}
          {!a.network && a.ip && write && (
            <Link to={`/assets/networks?new=${encodeURIComponent(defaultCidr(a.ip))}`} className="ml-2 text-[11px] text-primary hover:underline">создать сеть {defaultCidr(a.ip)}</Link>
          )}
        </dd>
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

function SourcesTable({ a, write, onDetach }: { a: AssetDetail; write: boolean; onDetach: (o: Observation) => void }) {
  const canDetach = write && a.observations.length > 1
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead className="text-text-secondary">
          <tr>
            <th className="px-1.5 py-1 font-medium">Источник</th>
            <th className="px-1.5 py-1 font-medium">Имя</th>
            <th className="px-1.5 py-1 font-medium">FQDN</th>
            <th className="px-1.5 py-1 font-medium">IP</th>
            <th className="px-1.5 py-1 font-medium">ОС</th>
            <th className="px-1.5 py-1 font-medium">Видел</th>
            {canDetach && <th className="px-1.5 py-1" />}
          </tr>
        </thead>
        <tbody>
          {a.observations.map((o) => (
            <tr key={o.id} className={cn('border-t border-grid align-top', o.gone_at && 'opacity-50')}>
              <td className="px-1.5 py-1 text-text">{SOURCE_LABELS[o.source]}</td>
              <Cell o={o} field="name" />
              <Cell o={o} field="fqdn" mono />
              <Cell o={o} field="ip" mono />
              <td className="px-1.5 py-1 text-text-secondary">{o.os || '—'}</td>
              <td className="px-1.5 py-1 whitespace-nowrap text-text-secondary">{day(o.seen_at)}{o.gone_at && <div>пропал {day(o.gone_at)}</div>}</td>
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

function ScannerBlock({ a }: { a: AssetDetail }) {
  const scan = a.observations.find((o) => o.source === 'scan' && !o.gone_at) ?? a.observations.find((o) => o.source === 'scan')
  if (!scan) return null
  const ports = Array.isArray(scan.extra.ports) ? (scan.extra.ports as number[]) : []
  const icmp = scan.extra.icmp
  return (
    <>
      <SectionTitle>Сканер</SectionTitle>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">Открытые порты</dt><dd className="font-mono text-text">{ports.length ? ports.join(', ') : 'нет'}</dd>
        <dt className="text-text-secondary">ICMP</dt><dd className="text-text">{icmp === true ? 'отвечает' : icmp === false ? 'не отвечает' : 'не проверялся'}</dd>
        <dt className="text-text-secondary">TTL</dt><dd className="font-mono text-text">{scan.extra.ttl != null ? String(scan.extra.ttl) : '—'}</dd>
        <dt className="text-text-secondary">RTT</dt><dd className="font-mono text-text">{scan.extra.rtt_ms != null ? `${String(scan.extra.rtt_ms)} мс` : '—'}</dd>
      </dl>
    </>
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

function ManualFields({ a, write }: { a: AssetDetail; write: boolean }) {
  const patch = usePatchAsset(a.id)
  // Начальные значения — из карточки; после сохранения форма пересоздаётся по updated_at (key у вызова).
  const [criticality, setCriticality] = useState<Criticality | ''>(a.criticality)
  const [tags, setTags] = useState(a.tags.join(', '))
  const [note, setNote] = useState(a.note)
  const networks = useNetworks()
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
      <label className="block">
        <span className="mb-1 block text-text-secondary">Сеть</span>
        <select value={network} onChange={(e) => setNetwork(e.target.value)} className={cn(FIELD, 'text-xs')}>
          <option value="">по адресу — самая узкая сеть, содержащая IP</option>
          {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.cidr}{n.title ? ` — ${n.title}` : ''}{n.zone ? ` · ${n.zone}` : ''}</option>)}
        </select>
      </label>
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
 * расхождений, сканер, ссылки в модули, ручные поля, объединение и отвязка. */
export function AssetDrawer({ assetId, onClose, onOpenAsset }: { assetId: number | null; onClose: () => void; onOpenAsset: (id: number) => void }) {
  const open = assetId !== null
  const { write } = useCan()
  const detail = useAsset(assetId)
  const merge = useMergeAssets(assetId ?? 0)
  const detach = useDetachObservation()
  const [mergeWith, setMergeWith] = useState<{ id: number; label: string } | null>(null)
  const [detaching, setDetaching] = useState<Observation | null>(null)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { if (open) closeRef.current?.focus(); setMergeWith(null); setDetaching(null) }, [open, assetId])
  const a = detail.data
  const err = merge.error ?? detach.error

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

                  {a.discrepancies.length > 0 && (
                    <>
                      <SectionTitle>Расхождения ({a.discrepancies.length})</SectionTitle>
                      <ul className="flex flex-col gap-1">
                        {a.discrepancies.map((d, i) => (
                          <li key={i} className="flex gap-2">
                            <span className={cn('shrink-0', CODE_TEXT[d.code])}>{CODE_LABELS[d.code]}</span>
                            <span className="text-text-secondary">{d.text}</span>
                          </li>
                        ))}
                      </ul>
                    </>
                  )}

                  <SectionTitle>По источникам</SectionTitle>
                  <SourcesTable a={a} write={write && a.merged_into === null} onDetach={setDetaching} />

                  <ScannerBlock a={a} />
                  <LinksBlock a={a} />

                  <SectionTitle>Ручные поля</SectionTitle>
                  <ManualFields key={`${a.id}:${a.updated_at}`} a={a} write={write && a.merged_into === null} />

                  {write && a.merged_into === null && (
                    <>
                      <SectionTitle>Объединить с другим активом</SectionTitle>
                      <MergePicker a={a} onPick={setMergeWith} />
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
