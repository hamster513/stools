import { useEffect, useRef, useState } from 'react'
import { Network as NetworkIcon, Pencil, Trash2, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useDeleteNetwork, useNetwork, useSaveNetwork, useZones } from '@/modules/assets/api/queries'
import {
  NETWORK_ORIGIN_LABELS,
  num,
  placementText,
  RULE_MATCH_LABELS,
  type Network,
  type NetworkIn,
  type NetworkRef,
  type RuleMatch,
} from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { SectionTitle } from './AssetDrawer'

const LINK_BUTTON = 'text-left text-text hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring rounded'
const TAG = 'rounded border border-grid px-1 text-[10px] text-text-secondary'
/** Значение выбора группы «по правилам»: имя зоны с «/» невозможно (сервер его не принимает). */
const BY_RULES = '/rules'

function dayTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'
}

/** «правило №3: имя начинается с APP_DMZ_». */
function ruleText(rule: { match: RuleMatch; value: string; position: number }): string {
  return `правило №${rule.position}: ${RULE_MATCH_LABELS[rule.match] ?? rule.match} ${rule.value}`
}

/** Почему сеть в этой группе: вручную, каким правилом, по публичному адресу — или не назначена. */
function zoneReason(n: Pick<Network, 'zone_source' | 'zone_rule'>): string {
  if (n.zone_source === 'manual') return 'вручную'
  if (n.zone_source === 'rule') return n.zone_rule ? ruleText(n.zone_rule) : 'по правилу'
  if (n.zone_source === 'racktables') return 'публичный адрес (RackTables)'
  return 'ни одно правило не подошло'
}

function RefList({ refs, onOpen }: { refs: NetworkRef[]; onOpen: (id: number) => void }) {
  return (
    <ul className="flex flex-col gap-0.5">
      {refs.map((r) => (
        <li key={r.id} className="flex items-baseline gap-2">
          <button type="button" className={cn(LINK_BUTTON, 'font-mono')} onClick={() => onOpen(r.id)}>{r.cidr}</button>
          {r.title && <span className="min-w-0 truncate text-text-secondary">{r.title}</span>}
        </li>
      ))}
    </ul>
  )
}

function Tags({ tags }: { tags: string[] }) {
  if (tags.length === 0) return <>—</>
  return <span className="flex flex-wrap gap-1">{tags.map((t) => <span key={t} className={TAG}>{t}</span>)}</span>
}

function Card({ n, onOpen }: { n: Network; onOpen: (id: number) => void }) {
  const traits = placementText(n)
  return (
    <>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-secondary">CIDR</dt><dd className="font-mono break-all text-text">{n.cidr}</dd>
        <dt className="text-text-secondary">Название</dt><dd className="break-words text-text">{n.title || '—'}</dd>
        <dt className="text-text-secondary">Описание</dt><dd className="whitespace-pre-line break-words text-text">{n.description || '—'}</dd>
        <dt className="text-text-secondary">Группа</dt>
        <dd className="text-text">
          {n.zone ? (n.zone_title && n.zone_title !== n.zone ? `${n.zone} — ${n.zone_title}` : n.zone) : 'без группы'}
          <span className="text-text-secondary"> · {zoneReason(n)}</span>
        </dd>
        <dt className="text-text-secondary">Признаки</dt><dd className="text-text">{traits || 'не заданы'}</dd>
        <dt className="text-text-secondary">VLAN</dt><dd className="font-mono text-text">{n.vlan ?? '—'}</dd>
        <dt className="text-text-secondary">Площадка</dt><dd className="break-words text-text">{n.site || '—'}</dd>
        <dt className="text-text-secondary">Владелец</dt><dd className="break-words text-text">{n.owner || '—'}</dd>
        <dt className="text-text-secondary">Теги</dt><dd className="text-text"><Tags tags={n.tags} /></dd>
        <dt className="text-text-secondary">Унаследованные</dt><dd className="text-text"><Tags tags={n.implicit_tags} /></dd>
        <dt className="text-text-secondary">Откуда</dt>
        <dd className="text-text">
          {NETWORK_ORIGIN_LABELS[n.origin] ?? n.origin}
          {n.origin === 'racktables' && <span className="text-text-secondary"> · id {n.origin_key || '—'}, импорт {dayTime(n.origin_seen_at)}</span>}
        </dd>
        <dt className="text-text-secondary">Активов</dt>
        <dd><Link to={`/assets/list?network_id=${n.id}`} className="font-mono text-text hover:text-primary hover:underline">{num(n.assets)}</Link></dd>
      </dl>
      <SectionTitle>Объемлющие сети ({num(n.parents.length)})</SectionTitle>
      {n.parents.length === 0 ? <p className="text-text-secondary">нет</p> : <RefList refs={n.parents} onOpen={onOpen} />}
      <SectionTitle>Вложенные сети ({num(n.children_count)})</SectionTitle>
      {n.children_count === 0 ? <p className="text-text-secondary">нет</p> : (
        <>
          {n.children_count > n.children.length && <p className="mb-1 text-text-secondary">показаны {num(n.children.length)} из {num(n.children_count)}</p>}
          <RefList refs={n.children} onOpen={onOpen} />
        </>
      )}
    </>
  )
}

interface FormState {
  cidr: string
  title: string
  description: string
  /** BY_RULES — группу назначают правила; '' — вручную без группы; иначе имя группы, закреплённой вручную. */
  group: string
  site: string
  owner: string
  vlan: string
  tags: string
}

function toForm(n: Network | null, cidr: string): FormState {
  if (!n) return { cidr, title: '', description: '', group: BY_RULES, site: '', owner: '', vlan: '', tags: '' }
  return {
    cidr: n.cidr, title: n.title, description: n.description, group: n.zone_source === 'manual' ? (n.zone ?? '') : BY_RULES,
    site: n.site, owner: n.owner, vlan: n.vlan === null ? '' : String(n.vlan), tags: n.tags.join(', '),
  }
}

/** Группа уходит всегда явно: «по правилам» — `zone_mode: rules`, иначе `manual` с выбранной группой. */
function toBody(f: FormState): NetworkIn {
  const vlan = f.vlan.trim() === '' ? null : Number(f.vlan)
  return {
    cidr: f.cidr.trim(), title: f.title, description: f.description, site: f.site, owner: f.owner,
    vlan: vlan === null || Number.isNaN(vlan) ? null : vlan,
    tags: f.tags.split(',').map((t) => t.trim()).filter(Boolean),
    ...(f.group === BY_RULES ? { zone: null, zone_mode: 'rules' as const } : { zone: f.group || null, zone_mode: 'manual' as const }),
  }
}

/** Правка и создание сети: поля, группа «по правилам» или вручную. Сеть RackTables — подпись о перезаписи импортом. */
function Editor({ n, initialCidr, onSaved, onCancel }: { n: Network | null; initialCidr: string; onSaved: (saved: Network) => void; onCancel: () => void }) {
  const save = useSaveNetwork()
  const zones = useZones()
  const [f, setF] = useState<FormState>(() => toForm(n, initialCidr))
  const patch = (p: Partial<FormState>) => setF((v) => ({ ...v, ...p }))
  const input = (label: string, key: keyof FormState, props: { mono?: boolean; type?: string; hint?: string } = {}) => (
    <label className="block">
      <span className="mb-1 block text-text-secondary">{label}{props.hint && <span className="ml-1 text-[11px]">· {props.hint}</span>}</span>
      <input value={f[key]} type={props.type} onChange={(e) => patch({ [key]: e.target.value })} spellCheck={false} className={cn(FIELD, 'text-xs', props.mono && 'font-mono')} />
    </label>
  )
  return (
    <div className="flex flex-col gap-2">
      {n?.origin === 'racktables' && (
        <p className="rounded border border-grid px-3 py-2 text-text-secondary">Сеть из RackTables: CIDR, название, описание, VLAN и теги следующий импорт перезапишет. Группа, площадка и владелец — ваши.</p>
      )}
      {input('CIDR', 'cidr', { mono: true, hint: 'например 10.10.0.0/24' })}
      {input('Название', 'title')}
      <label className="block">
        <span className="mb-1 block text-text-secondary">Группа сетей</span>
        <select value={f.group} onChange={(e) => patch({ group: e.target.value })} className={cn(FIELD, 'text-xs')}>
          <option value={BY_RULES}>по правилам{n && n.zone_source !== 'manual' && n.zone ? ` (сейчас ${n.zone})` : ''}</option>
          <option value="">вручную: без группы</option>
          {(zones.data ?? []).map((z) => <option key={z.name} value={z.name}>вручную: {z.title && z.title !== z.name ? `${z.name} — ${z.title}` : z.name}</option>)}
        </select>
        <span className="mt-0.5 block text-[11px] text-text-secondary">Группа, выбранная вручную, главнее правил: правила её не меняют, пока не вернёте «по правилам».</span>
      </label>
      <div className="grid grid-cols-2 gap-2">
        {input('Площадка', 'site')}
        {input('Владелец', 'owner')}
        {input('VLAN', 'vlan', { type: 'number', hint: '1–4094' })}
        {input('Теги через запятую', 'tags')}
      </div>
      <label className="block">
        <span className="mb-1 block text-text-secondary">Описание</span>
        <textarea value={f.description} onChange={(e) => patch({ description: e.target.value })} rows={2} className={cn(FIELD, 'text-xs')} />
      </label>
      <div className="flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.cidr.trim()} onClick={() => save.mutate({ id: n?.id, body: toBody(f) }, { onSuccess: onSaved })}>Сохранить</Button>
        <Button onClick={onCancel}>Отмена</Button>
        {save.error && <span className="text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
      </div>
    </div>
  )
}

function ConfirmDelete({ n, onCancel, onDeleted }: { n: Network; onCancel: () => void; onDeleted: () => void }) {
  const remove = useDeleteNetwork()
  return (
    <div role="dialog" aria-label="Удалить сеть" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">Удалить сеть {n.cidr}?</div>
        <p className="mb-4 text-xs text-text-secondary">
          Активы сети ({num(n.assets)}) перейдут в самую узкую из оставшихся сетей, содержащую их адрес, или останутся без сети;
          привязка вручную к этой сети сбрасывается.{n.origin === 'racktables' && ' Сеть RackTables вернётся при следующем импорте.'}
        </p>
        {remove.error && <p className="mb-2 text-xs text-kind-1">{remove.error instanceof ApiRequestError ? remove.error.message : 'Не удалось удалить'}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel}>Отмена</Button>
          <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(n.id, { onSuccess: onDeleted })}>Удалить</Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Карточка сети справа (спека §6): группа и «почему», признаки, теги явные и унаследованные, откуда сеть, активы,
 * объемлющие и вложенные. Аналитик правит и удаляет; `newCidr` (не null) — создание новой сети с этим CIDR.
 */
export function NetworkDrawer({ networkId, newCidr, onClose, onOpen }: {
  networkId: number | null
  newCidr: string | null
  onClose: () => void
  onOpen: (id: number) => void
}) {
  const creating = newCidr !== null
  const open = networkId !== null || creating
  const { write } = useCan()
  const detail = useNetwork(creating ? null : networkId)
  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const closeRef = useRef<HTMLButtonElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  // Переход в другую сеть из карточки — с начала карточки и без открытой правки.
  useEffect(() => { if (open) { closeRef.current?.focus(); bodyRef.current?.scrollTo({ top: 0 }) } setEditing(false); setDeleting(false) }, [open, networkId, creating])
  const n = creating ? null : detail.data

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Сеть" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[600px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {open && (
          <>
            <div className="flex items-center justify-between gap-2 border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <NetworkIcon size={16} className="shrink-0 text-text-secondary" aria-hidden />
                <span className="truncate font-mono text-sm text-text">{creating ? 'Новая сеть' : n ? n.cidr : `сеть #${networkId}`}</span>
                {n?.title && <span className="truncate text-xs text-text-secondary">{n.title}</span>}
              </div>
              <div className="flex shrink-0 items-center gap-1">
                {write && n && !editing && (
                  <>
                    <Button variant="ghost" onClick={() => setEditing(true)}><Pencil size={13} aria-hidden /> Изменить</Button>
                    <Button variant="ghost" className="text-risk-high" onClick={() => setDeleting(true)} aria-label={`Удалить сеть ${n.cidr}`}><Trash2 size={13} aria-hidden /></Button>
                  </>
                )}
                <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
              </div>
            </div>
            <div ref={bodyRef} className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {creating && <Editor key={`new:${newCidr}`} n={null} initialCidr={newCidr} onSaved={(saved) => onOpen(saved.id)} onCancel={onClose} />}
              {!creating && detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {!creating && detail.error && <p className="text-kind-1">{detail.error instanceof ApiRequestError ? detail.error.message : 'Не удалось загрузить сеть'}</p>}
              {n && editing && <Editor key={`${n.id}:${n.updated_at}`} n={n} initialCidr="" onSaved={() => setEditing(false)} onCancel={() => setEditing(false)} />}
              {n && !editing && <Card n={n} onOpen={onOpen} />}
            </div>
          </>
        )}
      </aside>
      {n && deleting && <ConfirmDelete n={n} onCancel={() => setDeleting(false)} onDeleted={() => { setDeleting(false); onClose() }} />}
    </>
  )
}
