import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { CheckCircle2, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { SeverityBadge } from './SeverityBadge'
import { STATUS_LABELS, type FindingBase, type FindingDetail } from './types'

function fmt(v: unknown): string {
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v === 'boolean') return v ? 'да' : 'нет'
  if (Array.isArray(v)) return v.map(String).join(', ')
  return String(v)
}

const NONE: ReadonlySet<string> = new Set()

/**
 * Карточка находки справа: описание, поля, история, вердикт. Вердикт
 * привязан к области модуля (домен, сервер) — её поле модуль отдаёт в scope.
 * Строки до «Статуса» и после полей details модуль рисует сам.
 */
export function CollectorFindingDrawer<F extends FindingBase, S extends object>({ finding, snapshotId, scope, useFindingDetail, accept, drop, leadRows, trailRows, hiddenDetails = NONE, reasonPlaceholder, verdictNote, onClose }: {
  finding: F | null
  snapshotId: number | undefined
  scope: S
  useFindingDetail: (snapshotId: number | undefined, key: string | undefined) => UseQueryResult<FindingDetail<F>, ApiRequestError>
  accept: UseMutationResult<void, ApiRequestError, { key: string; reason: string } & S>
  drop: UseMutationResult<void, ApiRequestError, { key: string } & S>
  leadRows: (d: FindingDetail<F>) => ReactNode
  trailRows?: (d: FindingDetail<F>) => ReactNode
  hiddenDetails?: ReadonlySet<string>
  reasonPlaceholder: string
  verdictNote: string
  onClose: () => void
}) {
  const open = finding !== null
  // Принятый вердикт аудитор видит вместе с автором и датой; принять свой
  // или вернуть находку в работу он не может — это решение, а не наблюдение.
  const { write } = useCan()
  const detail = useFindingDetail(open ? snapshotId : undefined, finding?.key)
  const [reason, setReason] = useState('')
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => { if (open) { closeRef.current?.focus(); setReason('') } }, [open, finding?.key])
  const d = detail.data
  const err = accept.error ?? drop.error

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside role="dialog" aria-label="Находка" aria-hidden={!open} className={cn('fixed top-0 right-0 z-40 flex h-full w-[520px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}>
        {finding && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex min-w-0 items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="truncate text-sm text-text">{finding.check_title}</span>
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {detail.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {d && (
                <>
                  <p className="mb-3 leading-relaxed text-text-secondary">{d.description}</p>
                  <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                    {leadRows(d)}
                    <dt className="text-text-secondary">Статус</dt><dd className="text-text">{STATUS_LABELS[d.status]}{d.allowlisted && <span className="ml-1 text-text-secondary">· в allowlist, severity понижена с {d.severity_original}</span>}</dd>
                    {Object.entries(d.details).filter(([k]) => !hiddenDetails.has(k)).map(([k, v]) => (
                      <span key={k} className="contents"><dt className="text-text-secondary">{k}</dt><dd className="font-mono break-all text-text">{fmt(v)}</dd></span>
                    ))}
                    {trailRows?.(d)}
                  </dl>
                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">История</div>
                  <ul className="mb-4 flex flex-col gap-0.5 text-text-secondary">
                    {d.history.map((h) => <li key={h.snapshot_id}>снапшот #{h.snapshot_id} · {new Date(h.collected_at).toLocaleString('ru-RU')}</li>)}
                  </ul>
                  {(write || d.verdict) && (
                    <>
                      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Вердикт</div>
                      {d.verdict ? (
                        <div className="rounded border border-kind-accepted/40 bg-kind-accepted/5 px-3 py-2">
                          <div className="flex items-center gap-1.5 text-kind-accepted"><CheckCircle2 size={14} aria-hidden /> принято как норма</div>
                          <div className="mt-1 text-text">{d.verdict.reason || 'без причины'}</div>
                          <div className="mt-1 text-[11px] text-text-secondary">{d.verdict.decided_by}, {new Date(d.verdict.decided_at).toLocaleString('ru-RU')}</div>
                          {write && <Button className="mt-2" onClick={() => drop.mutate({ key: d.key, ...scope })} loading={drop.isPending}>Вернуть в работу</Button>}
                        </div>
                      ) : (
                        <div className="flex flex-col gap-2">
                          <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder={reasonPlaceholder} className="w-full rounded border border-border bg-app-bg px-2.5 py-1.5 text-xs text-text placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" />
                          <div><Button variant="primary" onClick={() => accept.mutate({ key: d.key, ...scope, reason })} loading={accept.isPending}>Принять как норму</Button></div>
                          <p className="text-[11px] text-text-secondary">{verdictNote}</p>
                        </div>
                      )}
                    </>
                  )}
                  {err && <p className="mt-2 text-kind-1">{err instanceof ApiRequestError ? err.message : 'Не удалось сохранить'}</p>}
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
