import { useEffect, useRef, useState, type ReactNode } from 'react'
import { UsersRound, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useGroup, useGroupExpanded } from '@/modules/assets/api/queries'
import {
  GPO_VIA_LABELS,
  GROUP_KIND_LABELS,
  GROUP_SOURCE_LABELS,
  num,
  type GroupDetail,
  type GroupFact,
  type GroupItem,
  type GroupMember,
  type GroupMemberKind,
  type GroupPolicy,
  type GroupRef,
} from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { SectionTitle } from './AssetDrawer'

const LINK = 'text-text hover:text-primary hover:underline'
const LINK_BUTTON = 'text-left text-text hover:text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring rounded'
const TAG = 'shrink-0 rounded border border-grid px-1 text-[10px] text-text-secondary'

const MEMBER_KIND_LABELS: Record<GroupMemberKind, string> = {
  group: 'группа',
  user: 'пользователь',
  computer: 'компьютер',
  well_known: 'встроенный',
  unknown: 'неизвестный',
}

/** Действие записи GPO, как в gpo_rights: Restricted Groups — Members / Member Of, GPP — добавить, заменить, удалить. */
const GPO_ACTION_LABELS: Record<string, string> = {
  member: 'Members',
  memberof: 'Member Of',
  add: 'добавить',
  replace: 'заменить состав',
  delete: 'удалить',
}

/** Сколько хостов записи GPO показывать сразу; остальные — числом «и ещё N». */
const POLICY_HOSTS_SHOWN = 20

/** «на 1 хосте», «на 21 хосте», «на 1 200 хостах». */
function onHosts(n: number): string {
  return `на ${num(n)} ${n % 10 === 1 && n % 100 !== 11 ? 'хосте' : 'хостах'}`
}

/** Локальная группа Linux: синхронизация пишет в описание «GID n», SID у неё нет. */
function isLinuxGroup(g: GroupItem): boolean {
  return g.local && /^GID \d+$/.test(g.description)
}

function groupTitle(g: { id: number; name: string; sid: string }): string {
  return g.name || g.sid || `группа #${g.id}`
}

/** Вид группы бейджем: локальная / доменная; доменная, которой нет в выгрузках AD, — «нет в AD». */
export function GroupKindBadge({ g }: { g: GroupItem }) {
  return (
    <span className="flex items-center gap-1 whitespace-nowrap">
      <span className={cn('rounded border px-1 py-px text-[10px]', g.local ? 'border-grid text-text-secondary' : 'border-border text-text')}>{GROUP_KIND_LABELS[g.local ? 'local' : 'domain']}</span>
      {!g.local && !g.in_ad && <span className="rounded border border-grid px-1 py-px text-[10px] text-kind-1" title="Группу видит VM участником локальных групп, в выгрузках AD её нет">нет в AD</span>}
    </span>
  )
}

/** Цепочка групп «через A → B»: каждая — в свою карточку. */
function Via({ via, onOpenGroup }: { via: GroupRef[]; onOpenGroup: (id: number) => void }) {
  if (via.length === 0) return null
  return (
    <span className="text-text-secondary">
      через{' '}
      {via.map((g, i) => (
        <span key={`${g.id}:${i}`}>
          {i > 0 && ' → '}
          <button type="button" className={LINK_BUTTON} onClick={() => onOpenGroup(g.id)}>{g.name || `группа #${g.id}`}</button>
        </span>
      ))}
    </span>
  )
}

/** Участник по виду: пользователь — в его карточку, группа — в карточку группы, компьютер — в карточку хоста; без записи — текстом. */
function MemberName({ kind, id, name, sid, onOpenGroup }: { kind: string; id: number | null; name: string; sid: string; onOpenGroup: (id: number) => void }) {
  const label = name || sid || '—'
  if (id === null) return <span className="break-all text-text">{label}</span>
  if (kind === 'user') return <Link to={`/assets/users?user=${id}`} className={cn(LINK, 'break-all')}>{label}</Link>
  if (kind === 'computer') return <Link to={`/assets/list?asset=${id}`} className={cn(LINK, 'break-all')}>{label}</Link>
  if (kind === 'group') return <button type="button" className={cn(LINK_BUTTON, 'break-all')} onClick={() => onOpenGroup(id)}>{label}</button>
  return <span className="break-all text-text">{label}</span>
}

function HostLink({ id, name }: { id: number | null; name: string }) {
  if (id === null) return <span className="font-mono text-text-secondary">{name || '—'}</span>
  return <Link to={`/assets/list?asset=${id}`} className={cn(LINK, 'font-mono')}>{name || `актив #${id}`}</Link>
}

/** Первые хосты через запятую и «и ещё N», если всего больше показанных. */
function HostList({ hosts, total }: { hosts: { id: number | null; name: string }[]; total: number }) {
  const rest = total - hosts.length
  return (
    <span className="text-text-secondary">
      {hosts.map((h, i) => (
        <span key={`${h.id ?? h.name}:${i}`}>
          {i > 0 && ', '}
          <HostLink id={h.id} name={h.name} />
        </span>
      ))}
      {rest > 0 && <span>{hosts.length > 0 ? ' ' : ''}и ещё {num(rest)}</span>}
    </span>
  )
}

function Capped({ shown, total }: { shown: number; total: number }) {
  if (total <= shown) return null
  return <p className="mb-1 text-text-secondary">показаны {num(shown)} из {num(total)}</p>
}

function Identity({ g }: { g: GroupDetail }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
      <dt className="text-text-secondary">Имя</dt><dd className="break-all text-text">{g.name || '—'}</dd>
      <dt className="text-text-secondary">{g.local ? 'Компьютер' : 'Домен'}</dt>
      <dd className="text-text">
        {g.local ? (
          <span>локальная группа хоста <HostLink id={g.host_asset_id} name={g.host_name || g.domain_label} /></span>
        ) : (
          <span className="font-mono">{g.domain_label || '—'}</span>
        )}
      </dd>
      <dt className="text-text-secondary">Вид</dt>
      <dd className="flex flex-wrap items-center gap-2 text-text">
        <GroupKindBadge g={g} />
        {!g.local && !g.in_ad && <span className="text-text-secondary">VM видит её участником локальных групп, в выгрузках AD её нет</span>}
      </dd>
      <dt className="text-text-secondary">SID</dt><dd className="font-mono break-all text-text">{g.sid || '—'}</dd>
      <dt className="text-text-secondary">Описание</dt><dd className="break-words text-text">{g.description || '—'}</dd>
      <dt className="text-text-secondary">Источники</dt>
      <dd className="text-text">{g.sources.length ? g.sources.map((s) => GROUP_SOURCE_LABELS[s]).join(', ') : '—'}</dd>
      {g.gone && (
        <>
          <dt className="text-text-secondary">Состояние</dt>
          <dd className="text-risk-medium">пропала: последняя синхронизация её больше не видит</dd>
        </>
      )}
    </dl>
  )
}

function MemberRow({ m, onOpenGroup }: { m: GroupMember; onOpenGroup: (id: number) => void }) {
  return (
    <li className="flex flex-col py-0.5">
      <div className="flex items-baseline gap-2">
        <span className={TAG}>{MEMBER_KIND_LABELS[m.kind]}</span>
        <span className="min-w-0 flex-1"><MemberName kind={m.kind} id={m.id} name={m.name} sid={m.sid} onOpenGroup={onOpenGroup} /></span>
        {m.primary && <span className={TAG} title="Участник через primaryGroupID учётки">основная группа</span>}
        {m.domain && <span className="shrink-0 font-mono text-[10px] text-text-secondary">{m.domain}</span>}
      </div>
      {m.text && <div className="pl-1 text-text-secondary">{m.text}</div>}
    </li>
  )
}

function Members({ g, onOpenGroup }: { g: GroupDetail; onOpenGroup: (id: number) => void }) {
  return (
    <>
      <SectionTitle>Состав ({num(g.members_total)})</SectionTitle>
      {g.members_total === 0 && <p className="text-text-secondary">{!g.local && !g.in_ad ? 'участники не известны — группы нет в выгрузках AD' : 'прямых участников нет'}</p>}
      <Capped shown={g.members.length} total={g.members_total} />
      <ul className="flex flex-col">
        {g.members.map((m, i) => <MemberRow key={`${m.kind}:${m.id ?? m.sid ?? m.name}:${i}`} m={m} onOpenGroup={onOpenGroup} />)}
      </ul>
      {isLinuxGroup(g) && <p className="mt-1 text-text-secondary">основная группа пользователя (по GID учётки) в составе не видна</p>}
    </>
  )
}

/** Полный состав — по запросу: обход вниз по вложенности на сервере, пользователи и компьютеры постранично. */
function Expanded({ groupId, onOpenGroup }: { groupId: number; onOpenGroup: (id: number) => void }) {
  const [open, setOpen] = useState(false)
  const q = useGroupExpanded(groupId, open)
  const first = q.data?.pages[0]
  const items = q.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <>
      <SectionTitle>Полный состав{first ? ` (${num(first.total)})` : ''}</SectionTitle>
      {!open && (
        <div className="flex items-center gap-2">
          <Button onClick={() => setOpen(true)}>Показать полный состав</Button>
          <span className="text-text-secondary">пользователи и компьютеры через все вложенные группы</span>
        </div>
      )}
      {open && q.isLoading && <div className="flex justify-center py-4"><Spinner /></div>}
      {open && q.error && <p className="text-kind-1">{q.error instanceof ApiRequestError ? q.error.message : 'Не удалось загрузить полный состав'}</p>}
      {first && (
        <div className="flex flex-col gap-3">
          {first.notes.length > 0 && (
            <div className="rounded border border-grid px-3 py-2 text-text-secondary">
              <div className="mb-0.5 text-kind-1">Оговорка выгрузки AD</div>
              {first.notes.map((n) => <p key={n}>{n}</p>)}
            </div>
          )}
          {first.well_known.length > 0 && (
            <div>
              <div className="mb-0.5 text-text-secondary">Встроенные субъекты ({num(first.well_known.length)}) — не раскрываются в учётки</div>
              <ul className="flex flex-col">
                {first.well_known.map((w) => (
                  <li key={w.sid} className="py-0.5">
                    <div className="flex items-baseline gap-2">
                      <span className="min-w-0 flex-1 break-all text-text">{w.name || w.sid}</span>
                      <span className="shrink-0 font-mono text-[10px] text-text-secondary">{w.sid}</span>
                    </div>
                    <div className="pl-1 text-text-secondary">
                      {w.text}
                      {w.via.length > 0 && <> · <Via via={w.via} onOpenGroup={onOpenGroup} /></>}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div>
            <div className="mb-0.5 text-text-secondary">Пользователи и компьютеры ({num(first.total)})</div>
            {first.total === 0 && <p className="text-text-secondary">нет</p>}
            <ul className="flex flex-col">
              {items.map((x, i) => (
                <li key={`${x.kind}:${x.id ?? x.sid ?? x.name}:${i}`} className="py-0.5">
                  <div className="flex items-baseline gap-2">
                    <span className={TAG}>{MEMBER_KIND_LABELS[x.kind]}</span>
                    <span className="min-w-0 flex-1"><MemberName kind={x.kind} id={x.id} name={x.name} sid={x.sid} onOpenGroup={onOpenGroup} /></span>
                    {x.domain && <span className="shrink-0 font-mono text-[10px] text-text-secondary">{x.domain}</span>}
                  </div>
                  {(x.via.length > 0 || x.paths > 1) && (
                    <div className="pl-1">
                      <Via via={x.via} onOpenGroup={onOpenGroup} />
                      {x.paths > 1 && <span className="text-text-secondary">{x.via.length > 0 ? ' · ' : ''}путей {num(x.paths)}</span>}
                    </div>
                  )}
                </li>
              ))}
            </ul>
            {items.length < first.total && (
              <div className="mt-1 flex items-center gap-2">
                <Button loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>Показать ещё</Button>
                <span className="text-text-secondary">показаны {num(items.length)} из {num(first.total)}</span>
              </div>
            )}
          </div>
          {first.dead_ends_total > 0 && (
            <div>
              <div className="mb-0.5 text-text-secondary">Тупики ({num(first.dead_ends_total)}) — дальше раскрыть нельзя</div>
              <Capped shown={first.dead_ends.length} total={first.dead_ends_total} />
              <ul className="flex flex-col">
                {first.dead_ends.map((d, i) => (
                  <li key={`${d.kind}:${d.id ?? d.sid ?? d.name}:${i}`} className="py-0.5">
                    <div className="flex items-baseline gap-2">
                      <span className={TAG}>{d.kind === 'group' ? 'группа' : 'неизвестный'}</span>
                      <span className="min-w-0 flex-1"><MemberName kind={d.kind} id={d.id} name={d.name} sid={d.sid} onOpenGroup={onOpenGroup} /></span>
                      <span className="shrink-0 text-kind-1">{d.reason}</span>
                    </div>
                    {(d.via.length > 0 || d.paths > 1) && (
                      <div className="pl-1">
                        <Via via={d.via} onOpenGroup={onOpenGroup} />
                        {d.paths > 1 && <span className="text-text-secondary">{d.via.length > 0 ? ' · ' : ''}путей {num(d.paths)}</span>}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </>
  )
}

function MemberOf({ g, onOpenGroup }: { g: GroupDetail; onOpenGroup: (id: number) => void }) {
  return (
    <>
      <SectionTitle>Куда входит</SectionTitle>
      {g.member_of.length === 0 && g.local_member_of_total === 0 && <p className="text-text-secondary">ни в одну группу</p>}
      {g.member_of.length > 0 && (
        <>
          <div className="mt-1 mb-1 text-text-secondary">Доменные группы ({num(g.member_of.length)})</div>
          <ul className="flex flex-col gap-0.5">
            {g.member_of.map((p) => (
              <li key={p.id} className="flex items-baseline gap-2">
                <button type="button" className={cn(LINK_BUTTON, 'min-w-0 break-all')} onClick={() => onOpenGroup(p.id)}>{p.name || `группа #${p.id}`}</button>
                {!p.direct && <span className={TAG}>через вложенность</span>}
                {p.domain && <span className="ml-auto shrink-0 font-mono text-[10px] text-text-secondary">{p.domain}</span>}
              </li>
            ))}
          </ul>
        </>
      )}
      {g.local_member_of_total > 0 && (
        <>
          <div className="mt-2 mb-1 text-text-secondary">Локальные группы на хостах ({num(g.local_member_of_total)})</div>
          <Capped shown={g.local_member_of.length} total={g.local_member_of_total} />
          <ul className="flex flex-col gap-0.5">
            {g.local_member_of.map((l) => (
              <li key={l.group_id}>
                <button type="button" className={LINK_BUTTON} onClick={() => onOpenGroup(l.group_id)}>{l.name || `группа #${l.group_id}`}</button>
                <span className="text-text-secondary"> на </span>
                <HostLink id={l.host_asset_id} name={l.host_name} />
                {l.via.length > 0 && <> · <Via via={l.via} onOpenGroup={onOpenGroup} /></>}
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  )
}

function SubBlock({ title, hint, children }: { title: string; hint: string; children: ReactNode }) {
  return (
    <div className="mt-1 rounded border border-grid px-3 py-2">
      <div className="text-text">{title}</div>
      <div className="mb-1.5 text-[11px] text-text-secondary">{hint}</div>
      {children}
    </div>
  )
}

function FactRow({ f, onOpenGroup }: { f: GroupFact; onOpenGroup: (id: number) => void }) {
  return (
    <li className="py-1">
      <div>
        <span className="text-text">{f.local_group || f.local_group_sid || '—'}</span>
        <span className="text-text-secondary"> {onHosts(f.hosts_total)} · </span>
        {f.via.length > 0 ? <Via via={f.via} onOpenGroup={onOpenGroup} /> : <span className="text-text-secondary">прямо</span>}
      </div>
      <div className="pl-1"><HostList hosts={f.hosts.map((h) => ({ id: h.host_asset_id, name: h.host_name }))} total={f.hosts_total} /></div>
    </li>
  )
}

function PolicyRow({ p, onOpenGroup }: { p: GroupPolicy; onOpenGroup: (id: number) => void }) {
  const hosts = p.hosts.slice(0, POLICY_HOSTS_SHOWN)
  return (
    <li className="py-1">
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span className="text-text">{p.local_group || '—'}</span>
        <span className="text-text-secondary">GPO «{p.gpo_name || '—'}»</span>
        <span className={TAG}>{GPO_VIA_LABELS[p.via] ?? p.via}{p.action ? ` · ${GPO_ACTION_LABELS[p.action] ?? p.action}` : ''}</span>
        {p.filtered && <span className={cn(TAG, 'text-kind-1')} title="У GPO есть фильтр безопасности: политика может применяться не ко всем хостам из списка">фильтр безопасности</span>}
      </div>
      {p.through && (
        <div className="pl-1 text-text-secondary">
          через доменную группу <button type="button" className={LINK_BUTTON} onClick={() => p.through && onOpenGroup(p.through.id)}>{p.through.name || `группа #${p.through.id}`}</button>
        </div>
      )}
      <div className="pl-1">
        <span className="text-text-secondary">{p.hosts_total > 0 ? `${onHosts(p.hosts_total)}: ` : 'хосты не определены'}</span>
        {p.hosts_total > 0 && <HostList hosts={hosts.map((h) => ({ id: h.asset_id, name: h.name }))} total={p.hosts_total} />}
      </div>
    </li>
  )
}

/** Оговорки разбора GPO по доменам — показываются как есть, без смешения с записями. */
function PolicyNotes({ g }: { g: GroupDetail }) {
  const lines = g.rights.notes.flatMap((n) => [
    ...(n.links_known ? [] : ['ссылки GPO неизвестны (старая выгрузка) — область применения не определена']),
    ...(n.files_known ? [] : ['файлы GPO не прочитаны — назначения из них не известны']),
    ...n.notes,
  ].map((text) => ({ domain: n.domain, text })))
  if (lines.length === 0) return null
  return (
    <div className="mt-2 text-text-secondary">
      <div className="mb-0.5 text-kind-1">Оговорки разбора GPO</div>
      <ul className="flex flex-col gap-0.5">
        {lines.map((l, i) => <li key={`${l.domain}:${i}`}><span className="font-mono text-[10px]">{l.domain}</span> — {l.text}</li>)}
      </ul>
    </div>
  )
}

function Rights({ g, onOpenGroup }: { g: GroupDetail; onOpenGroup: (id: number) => void }) {
  return (
    <>
      <SectionTitle>Права</SectionTitle>
      <SubBlock title="По факту (VM)" hint="локальные группы хостов, где группа состоит по данным MaxPatrol VM">
        {g.rights.fact.length === 0 ? (
          <p className="text-text-secondary">VM не видит группу в локальных группах хостов</p>
        ) : (
          <ul className="flex flex-col">
            {g.rights.fact.map((f, i) => <FactRow key={`${f.local_group_sid || f.local_group}:${i}`} f={f} onOpenGroup={onOpenGroup} />)}
          </ul>
        )}
      </SubBlock>
      <SubBlock title="По политике (GPO)" hint="записи Restricted Groups и GPP, которые назначают группу в локальные группы">
        {g.rights.policy.length === 0 ? (
          <p className="text-text-secondary">записей GPO нет</p>
        ) : (
          <ul className="flex flex-col">
            {g.rights.policy.map((p, i) => <PolicyRow key={`${p.gpo_name}:${p.local_group}:${p.action}:${i}`} p={p} onOpenGroup={onOpenGroup} />)}
          </ul>
        )}
        <PolicyNotes g={g} />
      </SubBlock>
    </>
  )
}

/** Карточка группы справа: шапка, прямой состав, полный состав по запросу, куда входит, права по факту и по политике. */
export function GroupDrawer({ groupId, onClose, onOpenGroup }: { groupId: number | null; onClose: () => void; onOpenGroup: (id: number) => void }) {
  const open = groupId !== null
  const detail = useGroup(groupId)
  const closeRef = useRef<HTMLButtonElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  // Переход в другую группу из карточки — с начала карточки, а не с места, где щёлкнули.
  useEffect(() => { if (open) { closeRef.current?.focus(); bodyRef.current?.scrollTo({ top: 0 }) } }, [open, groupId])
  const g = detail.data

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Группа" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[600px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {open && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <UsersRound size={16} className="shrink-0 text-text-secondary" aria-hidden />
                <span className="truncate text-sm text-text">{g ? groupTitle(g) : `группа #${groupId}`}</span>
                {g?.domain_label && <span className="truncate font-mono text-xs text-text-secondary">{g.domain_label}</span>}
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
            </div>
            <div ref={bodyRef} className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {detail.error && <p className="text-kind-1">{detail.error instanceof ApiRequestError ? detail.error.message : 'Не удалось загрузить группу'}</p>}
              {g && (
                <>
                  <Identity g={g} />
                  <Members g={g} onOpenGroup={onOpenGroup} />
                  <Expanded key={g.id} groupId={g.id} onOpenGroup={onOpenGroup} />
                  <MemberOf g={g} onOpenGroup={onOpenGroup} />
                  <Rights g={g} onOpenGroup={onOpenGroup} />
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
