import { useId, useState } from 'react'
import { ChevronDown, ChevronRight, Lock, LockOpen } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef, type ColumnWidths } from '@/platform/table/useColumnWidths'
import { useNetRules } from '../../api/queries'
import type { NetRuleItem, NetRulesQuery } from '../../api/types'
import { LoadMore, MaybeMark } from '../objects/ObjectsParts'
import { ActionCell, PortsCell, RuleFlags, ScopeChips } from './RuleCells'
import { comparisonText, groupPolicies, inactiveLabel, MODE_LABELS, readOpenSections, sectionKey, type ProfileGroup, type Section } from './model'

type Col = 'position' | 'action' | 'direction' | 'protocol' | 'ports' | 'addresses' | 'name' | 'enabled'
const COLUMNS: ColumnDef<Col>[] = [
  { key: 'position', label: '№', width: 48, align: 'right' }, { key: 'action', label: 'Действие', width: 150 },
  { key: 'direction', label: 'Направление', width: 140 }, { key: 'protocol', label: 'Протокол', width: 90 },
  { key: 'ports', label: 'Порты', width: 150 }, { key: 'addresses', label: 'Адреса', width: 300, flex: true },
  { key: 'name', label: 'Название и состояние', width: 220 }, { key: 'enabled', label: 'Вкл.', width: 70 },
]
interface Props { snapshotId: number; sections: Section[]; args: NetRulesQuery; storageKey: string; openRowId: number | null; onOpen: (id: number) => void; maybe: Set<string> }
type Shared = Omit<Props, 'storageKey' | 'sections'> & { cols: ColumnWidths<Col> }
const BUTTON = 'rounded px-2 py-1 text-xs hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

export function SectionTable({ storageKey, ...props }: Props) {
  const cols = useColumnWidths('ksc-net-rules-columns-v2', COLUMNS)
  const [opened, setOpened] = useState<string[]>(() => {
    try { return readOpenSections(localStorage.getItem(storageKey)) } catch { return [] }
  })
  const save = (next: string[]) => { setOpened(next); try { localStorage.setItem(storageKey, JSON.stringify(next)) } catch { /* необязательно */ } }
  const toggle = (key: string) => save(opened.includes(key) ? opened.filter(k => k !== key) : [...opened, key])
  const shared = { ...props, cols }
  return <div data-col-resize-root style={{ minWidth: cols.gridStyle.minWidth }}>
    <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
      <ResizableHeader cols={cols} as="div" className="px-2 py-2" resetIn="enabled" />
    </div>
    <div className="flex items-center justify-between border-b border-grid px-4 py-2 text-xs text-text-secondary">
      <span>Базовые правила политики и отличия профилей. Одинаковые списки объединены внутри политики.</span>
      <button type="button" onClick={() => save([])} disabled={!opened.length} className={cn(BUTTON, 'shrink-0 disabled:opacity-50')}>Свернуть всё</button>
    </div>
    {groupPolicies(props.sections).map(policy => <section key={policy.id} aria-label={policy.name || `Политика #${policy.id}`}>
      <div className="border-y border-grid border-l-4 border-l-primary bg-surface px-4 py-3 text-sm font-semibold text-text">
        {policy.name || `Политика #${policy.id}`} <span className="ml-3 text-xs font-normal text-text-secondary">под политикой {policy.hosts} хостов</span>
      </div>
      {policy.layers.map(layer => {
        const unlockedKey = `unlocked:${policy.id}:${layer.layer}`
        const isOpen = opened.includes(unlockedKey)
        return <div key={layer.layer}>
          <div className="border-b border-grid px-4 py-2 text-xs font-semibold text-text-secondary">{layer.layer === 'packet' ? 'Пакетные правила · применяются первыми' : 'Правила программ · после пакетных правил'}</div>
          {layer.base ? <BaseList {...shared} section={layer.base} open={opened.includes(sectionKey(layer.base))} onToggle={() => toggle(sectionKey(layer.base!))} /> : <p className="border-b border-grid px-4 py-3 text-xs text-text-secondary">В этом слое нет собранных базовых правил политики.</p>}
          {layer.groups.map(group => <ProfileList key={group.key} {...shared} group={group} open={opened.includes(group.key)} onToggle={() => toggle(group.key)} />)}
          {layer.unlocked.length > 0 && <Disclosure title={`Без замка · профилей: ${layer.unlocked.reduce((n, g) => n + g.members.length, 0)} · списков: ${layer.unlocked.length}`} subtitle="Эти списки не переопределяют правила политики. Сохранены для сравнения." open={isOpen} onToggle={() => toggle(unlockedKey)} muted>
            {isOpen && layer.unlocked.map(group => <ProfileList key={group.key} {...shared} group={group} open={opened.includes(group.key)} onToggle={() => toggle(group.key)} />)}
          </Disclosure>}
        </div>
      })}
    </section>)}
  </div>
}

function Disclosure({ title, subtitle, open, onToggle, children, muted = false }: { title: string; subtitle?: string; open: boolean; onToggle: () => void; children: React.ReactNode; muted?: boolean }) {
  const id = useId()
  return <div>
    <button type="button" aria-expanded={open} aria-controls={id} onClick={onToggle} className={cn('flex w-full items-start gap-2 border-b border-grid bg-surface px-4 py-2.5 text-left text-xs hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring', muted ? 'text-text-secondary' : 'text-text')}>
      {open ? <ChevronDown size={15} className="mt-0.5 shrink-0" aria-hidden /> : <ChevronRight size={15} className="mt-0.5 shrink-0" aria-hidden />}
      <span><span className="font-semibold">{title}</span>{subtitle && <span className="mt-1 block font-normal text-text-secondary">{subtitle}</span>}</span>
    </button>
    <div id={id} hidden={!open}>{children}</div>
  </div>
}

function SourceState({ section: s, maybe }: { section: Section; maybe: Set<string> }) {
  return <span className="inline-flex flex-wrap items-center gap-2 text-text-secondary">
    {s.profile && <span>{s.priority === null ? 'Приоритет не получен' : `Приоритет ${s.priority}`}</span>}
    {s.locked === null ? <span>Замок не определён</span> : <span className="inline-flex items-center gap-1">{s.locked ? <Lock size={12} aria-hidden /> : <LockOpen size={12} aria-hidden />}{s.locked ? 'С замком' : 'Без замка'}</span>}
    {inactiveLabel(s.overridden_reason, s.overridden_by) && <span>{inactiveLabel(s.overridden_reason, s.overridden_by)}</span>}
    {s.overlay && <span>{MODE_LABELS[s.overlay]}</span>}
    {maybe.has(`${s.policy_id}\u0000${s.profile}`) && <MaybeMark />}
  </span>
}

function BaseList({ section, open, onToggle, ...props }: Shared & { section: Section; open: boolean; onToggle: () => void }) {
  return <Disclosure title={`Базовые правила · ${section.total}`} subtitle={section.rules === section.total ? undefined : `По фильтрам: ${section.rules} из ${section.total} правил`} open={open} onToggle={onToggle}>
    {open && <><div className="border-b border-grid px-4 py-2 text-xs"><SourceState section={section} maybe={props.maybe} /></div>{section.rules > 0 ? <SectionRows {...props} section={section} changes={false} /> : <EmptyRows />}</>}
  </Disclosure>
}

function ProfileList({ group, open, onToggle, ...props }: Shared & { group: ProfileGroup; open: boolean; onToggle: () => void }) {
  const [selected, setSelected] = useState(group.members[0].profile)
  const s = group.members.find(m => m.profile === selected) ?? group.members[0]
  const [full, setFull] = useState(false)
  const changes = !full && !!s.comparison?.base_known
  const count = changes ? s.comparison?.differences ?? 0 : s.rules
  const title = group.members.length === 1 ? `Профиль «${s.profile}»` : `Одинаковый список · профилей: ${group.members.length}`
  const names = group.members.length > 1 ? `${group.members.slice(0, 3).map(m => m.profile).join(', ')}${group.members.length > 3 ? ` и ещё ${group.members.length - 3}` : ''}. ` : ''
  return <Disclosure title={title} subtitle={`${names}${comparisonText(s.comparison)} · ${s.total} правил в списке`} open={open} onToggle={onToggle} muted={s.locked === false}>
    {open && <>
      <div className="border-b border-grid bg-surface px-4 py-2 text-xs">
        {group.members.length > 1 && <p className="mb-2 text-text-secondary">Содержимое одинаковое. Выберите профиль, чтобы открыть его записи и увидеть состояние применения.</p>}
        <div className="max-h-56 overflow-y-auto">
          {group.members.map(member => <div key={member.profile} className="flex flex-wrap items-center gap-3 py-1">
            <button type="button" aria-pressed={s.profile === member.profile} onClick={() => setSelected(member.profile)} className={cn(BUTTON, s.profile === member.profile ? 'bg-row-selected text-primary' : 'text-text')}>{member.profile}</button>
            <SourceState section={member} maybe={props.maybe} />
          </div>)}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-b border-grid px-4 py-2 text-xs">
        {s.comparison?.base_known && <button type="button" aria-pressed={changes} className={cn(BUTTON, changes && 'bg-row-selected text-primary')} onClick={() => setFull(false)}>Отличия от политики</button>}
        <button type="button" aria-pressed={!changes} className={cn(BUTTON, !changes && 'bg-row-selected text-primary')} onClick={() => setFull(true)}>Полный список</button>
        <span className="text-text-secondary">{changes ? `Без изменений: ${s.comparison?.unchanged}. По фильтрам: ${count} отличий.` : `По фильтрам: ${s.rules} из ${s.total} правил.`}</span>
      </div>
      {changes && <p className="border-b border-grid px-4 py-2 text-xs text-text-secondary">Сравнение содержимого списков. «Нет в профиле» не означает блокировку трафика: применение зависит от замка, активации и режима наложения.</p>}
      {count > 0 ? <SectionRows key={`${s.profile}:${changes}`} {...props} section={s} changes={changes} /> : <EmptyRows text={changes && s.comparison && !s.comparison.added && !s.comparison.removed && !s.comparison.changed && !s.comparison.moved ? 'Состав и порядок совпадают с политикой. Повторные строки скрыты.' : undefined} />}
    </>}
  </Disclosure>
}

function EmptyRows({ text = 'По выбранным фильтрам строк нет.' }: { text?: string }) {
  return <p className="border-b border-grid px-4 py-4 text-xs text-text-secondary">{text}</p>
}

const FIELD_LABELS: Record<string, string> = { name: 'название', action: 'действие', direction: 'направление', protocol: 'протокол', local_ports: 'локальные порты', remote_ports: 'удалённые порты', addresses: 'адреса', enabled: 'включение', scope: 'условия адресов, портов или протокола' }
const CHANGE_LABELS = { added: 'Добавлено в профиль', removed: 'Нет в профиле · правило политики', changed: 'Изменено в профиле', moved: 'Изменён порядок' }
function SectionRows({ snapshotId, section, args, changes, ...props }: Shared & { section: Section; changes: boolean }) {
  const query = useNetRules(snapshotId, { ...args, policy_id: [section.policy_id], profile: section.profile, layer: section.layer as 'packet' | 'app', changes: changes || undefined })
  const items = query.data?.pages.flatMap(p => p.items) ?? []
  if (query.isLoading || query.isPlaceholderData) return <div className="flex justify-center p-4"><Spinner /></div>
  if (query.isError) return <div className="p-4"><ErrorState message={query.error instanceof ApiRequestError ? query.error.message : 'Не удалось загрузить правила'} onRetry={() => query.refetch()} /></div>
  return <>
    {items.map(item => <div key={item.id}>
      {item.change && <div className="border-b border-grid bg-surface px-4 py-2 text-xs font-semibold text-text">
        {CHANGE_LABELS[item.change.kind]}{item.change.fields.length > 0 && <span className="font-normal text-text-secondary"> · {item.change.fields.map(f => FIELD_LABELS[f] ?? f).join(', ')}</span>}
        {item.change.previous && <span className="ml-2 font-normal text-text-secondary">№{item.change.previous.position} в политике → №{item.position} в профиле</span>}
        {item.change.moved && item.change.kind !== 'moved' && <span> · изменён порядок</span>}
      </div>}
      {item.change?.previous && <><div className="px-4 pt-2 text-[11px] text-text-secondary">В политике</div><RuleRow {...props} item={item.change.previous} /></>}
      {item.change?.previous && <div className="px-4 pt-2 text-[11px] text-text-secondary">В профиле «{section.profile}»</div>}
      <RuleRow {...props} item={item} />
    </div>)}
    {items.length === 0 && <EmptyRows />}
    <LoadMore loaded={items.length} total={query.data?.pages[0]?.total ?? 0} hasNext={!!query.hasNextPage} fetching={query.isFetchingNextPage} onMore={() => query.fetchNextPage()} />
  </>
}

function RuleRow({ item, cols, openRowId, onOpen, maybe }: Pick<Shared, 'cols' | 'openRowId' | 'onOpen' | 'maybe'> & { item: NetRuleItem }) {
  return <div {...clickableRow(() => onOpen(item.id))} className={cn(ROW_FOCUS, 'grid cursor-pointer items-start border-b border-grid py-2 text-xs [&>div]:min-w-0 [&>div]:px-2', openRowId === item.id ? 'bg-row-selected' : 'hover:bg-row-hover', item.overridden ? 'text-text-secondary' : 'text-text')} style={cols.gridStyle}>
    <div className="text-right font-mono tabular-nums text-text-secondary">{item.position}</div>
    <div><ActionCell action={item.action} /></div><div className="break-words text-text-secondary">{item.direction || '—'}</div><div className="text-text-secondary">{item.protocol || '—'}</div>
    <div><PortsCell item={item} /></div><div><ScopeChips item={item} /></div>
    <div className="break-words">{item.name || '—'}{maybe.has(`${item.policy_id}\u0000${item.profile}`) && <MaybeMark />}<RuleFlags item={item} /></div>
    <div className="text-text-secondary">{item.enabled ? 'да' : 'нет'}</div>
  </div>
}
