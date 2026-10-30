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
import type { NetRulesQuery } from '../../api/types'
import { LoadMore, MaybeMark } from '../objects/ObjectsParts'
import { ActionCell, PortsCell, RuleFlags, ScopeChips } from './RuleCells'
import { inactiveLabel, MODE_LABELS, readOpenSections, sectionKey, type Section } from './model'

type Col = 'position' | 'action' | 'direction' | 'protocol' | 'ports' | 'addresses' | 'name' | 'enabled'
const COLUMNS: ColumnDef<Col>[] = [
  { key: 'position', label: '№', width: 48, align: 'right' }, { key: 'action', label: 'Действие', width: 150 },
  { key: 'direction', label: 'Направление', width: 140 }, { key: 'protocol', label: 'Протокол', width: 90 },
  { key: 'ports', label: 'Порты', width: 150 }, { key: 'addresses', label: 'Адреса', width: 300, flex: true },
  { key: 'name', label: 'Название и состояние', width: 220 }, { key: 'enabled', label: 'Вкл.', width: 70 },
]
interface Props { snapshotId: number; sections: Section[]; args: NetRulesQuery; storageKey: string; openRowId: number | null; onOpen: (id: number) => void; maybe: Set<string> }

export function SectionTable({ storageKey, ...props }: Props) {
  const cols = useColumnWidths('ksc-net-rules-columns-v2', COLUMNS)
  const [opened, setOpened] = useState<string[]>(() => {
    try { return readOpenSections(localStorage.getItem(storageKey)) } catch { return [] }
  })
  const save = (next: string[]) => { setOpened(next); try { localStorage.setItem(storageKey, JSON.stringify(next)) } catch { /* хранилище необязательно */ } }
  const toggle = (key: string) => save(opened.includes(key) ? opened.filter(k => k !== key) : [...opened, key])
  const layers = [...new Set(props.sections.map(s => s.layer))]
  return <div data-col-resize-root style={{ minWidth: cols.gridStyle.minWidth }}>
    <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
      <ResizableHeader cols={cols} as="div" className="px-2 py-2" resetIn="enabled" />
    </div>
    <div className="flex items-center justify-between border-b border-grid px-4 py-2 text-xs text-text-secondary">
      <span>Строки загружаются при раскрытии секции. Порядок правил — внутри каждого списка.</span>
      <button type="button" onClick={() => save([])} disabled={!opened.length} className="shrink-0 rounded px-2 py-1 hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-focus-ring disabled:opacity-50">Свернуть всё</button>
    </div>
    {layers.map(layer => <section key={layer} aria-label={layer === 'packet' ? 'Пакетные правила' : layer === 'app' ? 'Правила программ' : layer}>
      <div className="border-y border-grid border-l-4 border-l-primary bg-surface px-4 py-3 text-xs font-semibold text-text">
        {layer === 'packet' ? 'Пакетные правила · применяются первыми, по порядку' : layer === 'app' ? 'Правила программ · если пакетные передали им решение или не подошли' : layer}
      </div>
      {props.sections.filter(s => s.layer === layer).map(section => <RuleSection key={sectionKey(section)} {...props} section={section} cols={cols} open={opened.includes(sectionKey(section))} onToggle={() => toggle(sectionKey(section))} />)}
    </section>)}
  </div>
}

function RuleSection({ section: s, open, onToggle, cols, ...props }: Omit<Props, 'storageKey'> & { section: Section; open: boolean; onToggle: () => void; cols: ColumnWidths<Col> }) {
  const id = useId()
  const inactive = inactiveLabel(s.overridden_reason, s.overridden_by)
  const uncertain = props.maybe.has(`${s.policy_id}\u0000${s.profile}`)
  return <div>
    <button type="button" aria-expanded={open} aria-controls={id} onClick={onToggle} className={cn('flex w-full items-start gap-2 border-b border-grid bg-surface px-3 py-2 text-left text-xs hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring', inactive ? 'text-text-secondary' : 'text-text')}>
      {open ? <ChevronDown size={15} className="mt-0.5 shrink-0" aria-hidden /> : <ChevronRight size={15} className="mt-0.5 shrink-0" aria-hidden />}
      <span className="min-w-0 flex-1">
        <span className="font-semibold">{s.policy_name || `Политика #${s.policy_id}`}{s.profile ? ` → профиль «${s.profile}»` : ' · сама политика'}</span>
        <span className="ml-3 text-text-secondary">{s.rules === s.total ? `${s.rules} правил` : `${s.rules} из ${s.total} правил`} · в тени {s.shadowed} · под политикой {s.hosts} хостов</span>
        {uncertain && <MaybeMark />}
        <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-text-secondary">
          {s.profile && <span>{s.priority === null ? 'Приоритет не получен' : `Приоритет ${s.priority}`}</span>}
          {s.locked !== null && <span className="inline-flex items-center gap-1">{s.locked ? <Lock size={12} aria-hidden /> : <LockOpen size={12} aria-hidden />}{s.locked ? 'Список с замком' : 'Список без замка'}</span>}
          {inactive && <span>{inactive}</span>}
          {s.overlay && <span>{MODE_LABELS[s.overlay]}</span>}
        </span>
      </span>
    </button>
    <div id={id} hidden={!open}>
      {open && s.rules > 0 && <SectionRows {...props} section={s} cols={cols} />}
    </div>
  </div>
}

/** Не монтируется для свёрнутых и пустых секций: даже при сотнях полос нет лавины запросов. */
function SectionRows({ snapshotId, section, args, cols, openRowId, onOpen, maybe }: Omit<Props, 'storageKey' | 'sections'> & { section: Section; cols: ColumnWidths<Col> }) {
  const query = useNetRules(snapshotId, { ...args, policy_id: [section.policy_id], profile: section.profile, layer: section.layer as 'packet' | 'app' })
  const items = query.data?.pages.flatMap(p => p.items) ?? []
  if (query.isLoading || query.isPlaceholderData) return <div className="flex justify-center p-4"><Spinner /></div>
  if (query.isError) return <div className="p-4"><ErrorState message={query.error instanceof ApiRequestError ? query.error.message : 'Не удалось загрузить правила секции'} onRetry={() => query.refetch()} /></div>
  return <>
    {items.map(item => <div key={item.id} {...clickableRow(() => onOpen(item.id))} className={cn(ROW_FOCUS, 'grid cursor-pointer items-start border-b border-grid py-2 text-xs [&>div]:min-w-0 [&>div]:px-2', openRowId === item.id ? 'bg-row-selected' : 'hover:bg-row-hover', item.overridden ? 'text-text-secondary' : 'text-text')} style={cols.gridStyle}>
      <div className="text-right font-mono tabular-nums text-text-secondary">{item.position}</div>
      <div><ActionCell action={item.action} /></div><div className="break-words text-text-secondary">{item.direction || '—'}</div><div className="text-text-secondary">{item.protocol || '—'}</div>
      <div><PortsCell item={item} /></div><div><ScopeChips item={item} /></div>
      <div className="break-words">{item.name || '—'}{maybe.has(`${item.policy_id}\u0000${item.profile}`) && <MaybeMark />}<RuleFlags item={item} /></div>
      <div className="text-text-secondary">{item.enabled ? 'да' : 'нет'}</div>
    </div>)}
    <LoadMore loaded={items.length} total={query.data?.pages[0]?.total ?? 0} hasNext={!!query.hasNextPage} fetching={query.isFetchingNextPage} onMore={() => query.fetchNextPage()} />
  </>
}
