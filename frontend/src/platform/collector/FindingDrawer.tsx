import { useEffect, useRef, type ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { FindingWorkBlock } from '@/platform/findings/FindingWorkBlock'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { SeverityBadge } from './SeverityBadge'
import type { FindingBase, FindingDetail } from './types'

// DN сами содержат запятые, поэтому списки DN (samples) — по одному в строке.
function fmt(v: unknown, key = ''): string {
  if (v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)) return '—'
  if (typeof v === 'boolean') return v ? 'да' : 'нет'
  // Даты (например, дата сбора данных ЦС) — в том же виде, что история ниже.
  if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(v)) return new Date(v).toLocaleString('ru-RU')
  // Субъекты с правами (principals у AD CS) — «имя — права», по одному в строке.
  if (Array.isArray(v) && v.some((x) => x !== null && typeof x === 'object')) {
    return v.map((x) => {
      const p = x as { name?: unknown; rights?: unknown }
      return p && typeof p === 'object' && 'name' in p ? `${fmt(p.name)} — ${fmt(p.rights)}` : fmt(x)
    }).join('\n')
  }
  if (Array.isArray(v)) return v.map(String).join(key === 'samples' ? '\n' : ', ')
  if (typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k}: ${fmt(x)}`).join(', ')
  return String(v)
}

const NONE: ReadonlySet<string> = new Set()

/**
 * Карточка находки справа: описание, поля, снапшоты с находкой и блок
 * «Работа с находкой» (статус, исполнитель, срок, история) — общий механизм
 * платформы, область модуля — module/scopeId. Открывается по ключу: находка
 * может быть не в загруженной странице списка (ссылка `?key=`). Строки до
 * «Статуса» и после полей details модуль рисует сам.
 */
export function CollectorFindingDrawer<F extends FindingBase>({ findingKey, snapshotId, module, scopeId, useFindingDetail, titleOf, leadRows, trailRows, hiddenDetails = NONE, onChanged, onClose }: {
  findingKey: string | null
  snapshotId: number | undefined
  module: string
  scopeId: number
  useFindingDetail: (snapshotId: number | undefined, key: string | undefined) => UseQueryResult<FindingDetail<F>, ApiRequestError>
  /** Короткая подпись находки для «Моих находок». */
  titleOf: (d: FindingDetail<F>) => string
  leadRows: (d: FindingDetail<F>) => ReactNode
  trailRows?: (d: FindingDetail<F>) => ReactNode
  hiddenDetails?: ReadonlySet<string>
  onChanged: () => void
  onClose: () => void
}) {
  const open = findingKey !== null
  const detail = useFindingDetail(open ? snapshotId : undefined, findingKey ?? undefined)
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { if (open) closeRef.current?.focus() }, [open, findingKey])
  const d = detail.data

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Находка" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[520px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {open && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                {d && <SeverityBadge severity={d.severity} />}
                <span className="truncate text-sm text-text">{d?.check_title ?? ''}</span>
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {detail.isError && <p className="text-kind-1">{detail.error instanceof ApiRequestError ? detail.error.message : 'Не удалось загрузить находку'}</p>}
              {d && (
                <>
                  <p className="mb-3 leading-relaxed text-text-secondary">{d.description}</p>
                  <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                    {leadRows(d)}
                    <dt className="text-text-secondary">Статус</dt>
                    <dd className="text-text">
                      <StatusBadge status={d.status} />
                      {d.delta === 'gone' && <span className="ml-1 text-text-secondary">· нет в последнем снапшоте</span>}
                      {d.delta === 'new' && <span className="ml-1 text-risk-high">· появилась в этом снапшоте</span>}
                      {d.allowlisted && <span className="ml-1 text-text-secondary">· в allowlist, severity понижена с {d.severity_original}</span>}
                    </dd>
                    {d.first_seen_at && <><dt className="text-text-secondary">Впервые</dt><dd className="text-text">{new Date(d.first_seen_at).toLocaleString('ru-RU')} ({d.age_days ?? 0} дн.)</dd></>}
                    {Object.entries(d.details).filter(([k]) => !hiddenDetails.has(k)).map(([k, v]) => (
                      <span key={k} className="contents"><dt className="text-text-secondary">{k}</dt><dd className="font-mono break-all whitespace-pre-line text-text">{fmt(v, k)}</dd></span>
                    ))}
                    {trailRows?.(d)}
                  </dl>
                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Снапшоты с находкой</div>
                  <ul className="mb-4 flex flex-col gap-0.5 text-text-secondary">
                    {d.history.map((h) => <li key={h.snapshot_id}>снапшот #{h.snapshot_id} · {new Date(h.collected_at).toLocaleString('ru-RU')}</li>)}
                  </ul>
                  <div className="border-t border-grid pt-3">
                    <FindingWorkBlock module={module} scopeId={scopeId} findingKey={d.key} title={titleOf(d)} severity={d.severity} onChanged={onChanged} />
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
