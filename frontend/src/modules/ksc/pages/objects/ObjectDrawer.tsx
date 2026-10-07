import { useEffect, useRef, useState, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useExclusionDetail, useNetRuleDetail } from '@/modules/ksc/api/queries'
import { EXCLUSION_KIND_LABELS, type ExclusionDetail, type NetRuleDetail, type SameInItem } from '@/modules/ksc/api/types'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { SeverityBadge } from '@/platform/collector/SeverityBadge'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'

export type ObjectKind = 'exclusion' | 'net_rule'

const KIND_TITLES: Record<ObjectKind, string> = { exclusion: 'Исключение', net_rule: 'Сетевое правило' }
const LAYER_TITLES: Record<string, string> = { packet: 'пакетное правило', app: 'правило программы' }

/**
 * Боковая панель записи — исключения или сетевого правила: все поля целиком, политика и профиль ссылками,
 * у исключения — риски с рекомендациями, у обеих — та же запись в других политиках и профилях (нажатие открывает её здесь же).
 * Esc закрывает только эту панель: перехватывается до обработчиков страниц (список хостов закрывает по Esc свою).
 */
export function ObjectDrawer({ kind, rowId, snapshotId, serverId, onClose }: { kind: ObjectKind; rowId: number | null; snapshotId: number; serverId: number; onClose: () => void }) {
  const open = rowId !== null
  useEffect(() => {
    if (!open) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== 'Escape') return
      e.stopPropagation()
      onClose()
    }
    document.addEventListener('keydown', onKeyDown, true)
    return () => document.removeEventListener('keydown', onKeyDown, true)
  }, [open, onClose])

  return (
    <>
      <div className={cn('fixed inset-0 z-50 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label={KIND_TITLES[kind]} aria-hidden={!open} className={cn('fixed top-0 right-0 z-50 flex h-full w-[640px] max-w-[calc(100vw-2rem)] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {rowId !== null && <Body key={rowId} kind={kind} initialRowId={rowId} snapshotId={snapshotId} serverId={serverId} onClose={onClose} />}
      </aside>
    </>
  )
}

/** Содержимое панели; `key` по открытой строке сбрасывает переход по «той же записи», когда таблица открывает другую. */
function Body({ kind, initialRowId, snapshotId, serverId, onClose }: { kind: ObjectKind; initialRowId: number; snapshotId: number; serverId: number; onClose: () => void }) {
  const [rowId, setRowId] = useState(initialRowId)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { closeRef.current?.focus() }, [])
  const exclusion = useExclusionDetail(kind === 'exclusion' ? snapshotId : undefined, rowId)
  const rule = useNetRuleDetail(kind === 'net_rule' ? snapshotId : undefined, rowId)
  const query = kind === 'exclusion' ? exclusion : rule
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить запись' : null
  const title = kind === 'exclusion' ? exclusion.data?.value : rule.data && (rule.data.name || '—')

  return (
    <>
      <div className="flex items-start justify-between gap-3 border-b border-grid px-4 py-3">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{KIND_TITLES[kind]}</div>
          <div className={cn('text-sm break-all text-text', kind === 'exclusion' && 'font-mono')}>{title ?? `#${rowId}`}</div>
        </div>
        <button ref={closeRef} type="button" onClick={onClose} className="shrink-0 rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
      </div>
      <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
        {query.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
        {errorMessage && <ErrorState message={errorMessage} onRetry={() => query.refetch()} />}
        {kind === 'exclusion' && exclusion.data && <ExclusionBody d={exclusion.data} serverId={serverId} onOpen={setRowId} />}
        {kind === 'net_rule' && rule.data && <NetRuleBody d={rule.data} serverId={serverId} onOpen={setRowId} />}
      </div>
    </>
  )
}

function ExclusionBody({ d, serverId, onOpen }: { d: ExclusionDetail; serverId: number; onOpen: (rowId: number) => void }) {
  return (
    <>
      <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <Field label="Вид">{EXCLUSION_KIND_LABELS[d.kind] ?? d.kind}</Field>
        <Field label="Значение" mono>{d.value}</Field>
        <Field label="Компоненты">{d.components.length ? d.components.join(', ') : '—'}</Field>
        <Field label="Включено">{d.enabled ? 'да' : 'нет'}</Field>
        <Field label="Комментарий">{d.comment || '—'}</Field>
        <PolicyFields d={d} serverId={serverId} />
        <Field label="В политиках"><span className={d.policies > 1 ? 'text-risk-medium' : undefined}>{d.policies}</span></Field>
        <Field label="Перекрыто" mono>{d.covered_by ?? 'нет'}</Field>
        <Field label="Ключ сравнения" mono>{d.key}</Field>
      </dl>

      <Section title="Риски">
        {d.risk_details.length === 0 && <div className="text-text-secondary">{d.enabled ? 'не найдены' : 'исключение выключено — риски не оцениваются'}</div>}
        {d.risk_details.map((r) => (
          <div key={r.code} className="mb-2 rounded border border-grid bg-app-bg px-3 py-2">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              {r.severity && <SeverityBadge severity={r.severity} />}
              <span className="font-medium text-text">{r.title}</span>
            </div>
            {r.detail && <p className="mb-2 text-text">{r.detail}</p>}
            {r.recommendations.length > 0 && (
              <>
                <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Рекомендации</div>
                <ul className="list-disc pl-4 text-text">{r.recommendations.map((t) => <li key={t}>{t}</li>)}</ul>
              </>
            )}
          </div>
        ))}
      </Section>

      <SameIn items={d.same_in} serverId={serverId} onOpen={onOpen} />
    </>
  )
}

function NetRuleBody({ d, serverId, onOpen }: { d: NetRuleDetail; serverId: number; onOpen: (rowId: number) => void }) {
  return (
    <>
      <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <Field label="Название">{d.name || '—'}</Field>
        <Field label="Слой">{LAYER_TITLES[d.layer] ?? (d.layer || '—')}</Field>
        <Field label="№ в списке" mono>{d.position}</Field>
        <Field label="Действие">{d.action || '—'}</Field>
        <Field label="Направление">{d.direction || '—'}</Field>
        <Field label="Протокол">{d.protocol || '—'}</Field>
        <Field label="Локальные порты" mono>{d.local_ports || '—'}</Field>
        <Field label="Удалённые порты" mono>{d.remote_ports || '—'}</Field>
        <Field label="Адреса" mono>{d.addresses || '—'}</Field>
        <Field label="Включено">{d.enabled ? 'да' : 'нет'}</Field>
        <PolicyFields d={d} serverId={serverId} />
        <Field label="Ключ сравнения" mono>{d.key}</Field>
      </dl>
      <SameIn items={d.same_in} serverId={serverId} onOpen={onOpen} />
    </>
  )
}

/** Строка `dl`; `mono` — значение целиком, с переносом по любому знаку (адреса, порты, пути не обрезаются). */
function Field({ label, mono = false, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <>
      <dt className="text-text-secondary">{label}</dt>
      <dd className="min-w-0 text-text">{mono ? <pre className="font-mono whitespace-pre-wrap break-all">{children}</pre> : children}</dd>
    </>
  )
}

/** Политика и профиль ссылками (профиль — на вкладку профилей), хостов под политикой, пометка о неполном содержимом. */
function PolicyFields({ d, serverId }: { d: ExclusionDetail | NetRuleDetail; serverId: number }) {
  const policyUrl = `/ksc/servers/${serverId}/policies/${d.policy_id}`
  return (
    <>
      <Field label="Политика">
        <Link to={policyUrl} className="text-text hover:text-primary hover:underline">{d.policy_name || '—'}</Link>
        {d.policy_partial && <span className="ml-2 text-risk-medium" title="часть секций политики не прочиталась — записи и настройки могут быть неполными">содержимое политики собрано не полностью</span>}
      </Field>
      <Field label="Профиль">
        {d.profile ? <Link to={`${policyUrl}?tab=profiles`} className="text-text hover:text-primary hover:underline">{d.profile}</Link> : <span className="text-text-secondary">сама политика</span>}
      </Field>
      <Field label="Хостов под политикой" mono>{d.policy_hosts}</Field>
    </>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-4">
      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      {children}
    </div>
  )
}

/** Та же запись (по ключу) в других политиках и в профилях — в том числе своей политики: имя политики ведёт в карточку, строка целиком открывает ту запись здесь же. */
function SameIn({ items, serverId, onOpen }: { items: SameInItem[]; serverId: number; onOpen: (rowId: number) => void }) {
  return (
    <Section title="Та же запись в других политиках и профилях">
      {items.length === 0 && <div className="text-text-secondary">больше нигде нет</div>}
      {items.length > 0 && (
        <ul className="flex flex-col gap-0.5">
          {items.map((s) => (
            <li key={s.row_id} {...clickableRow(() => onOpen(s.row_id))} className={cn(ROW_FOCUS, 'flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 hover:bg-row-hover')} title="открыть эту запись">
              <span className="min-w-0 flex-1 truncate" role="presentation" onClick={(e) => e.stopPropagation()}>
                <Link to={`/ksc/servers/${serverId}/policies/${s.policy_id}`} className="text-text hover:text-primary hover:underline" title={s.policy_name}>{s.policy_name}</Link>
              </span>
              <span className="shrink-0 text-text-secondary">{s.profile ? `профиль ${s.profile}` : 'сама политика'}</span>
              {!s.enabled && <span className="shrink-0 text-risk-medium">выключено</span>}
            </li>
          ))}
        </ul>
      )}
    </Section>
  )
}
