import { useEffect, useRef } from 'react'
import { X } from 'lucide-react'
import { useFindingDetail } from '@/modules/siem/api/queries'
import type { FindingListItem } from '@/modules/siem/api/types'
import { OBJECT_TYPE_LABELS, POLARITY_LABELS } from '@/modules/siem/api/types'

const SHAPE_LABELS: Record<string, string> = {
  fqdn: 'имя узла',
  ip: 'IP-адрес',
  cidr: 'подсеть',
}
import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { HighlightedBody, spansForValue } from '@/modules/siem/components/ui/HighlightedBody'
import { StatusBadge } from '@/modules/siem/components/ui/StatusBadge'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

interface DetailDrawerProps {
  finding: FindingListItem | null
  ordinal: number | null
  onClose: () => void
  onAccept: () => void
  onTakeInWork: () => void
}

/**
 * Значение и фрагмент тела приходят только сюда, по явному запросу
 * /detail — списки находок их никогда не показывают.
 */
export function DetailDrawer({ finding, ordinal, onClose, onAccept, onTakeInWork }: DetailDrawerProps) {
  const open = finding !== null
  const { data, isLoading, isError } = useFindingDetail(finding?.id, { enabled: open })
  const closeRef = useRef<HTMLButtonElement>(null)
  // Вердикт — решение, а решения аудитор не выносит: сервер ответит 403.
  const { write } = useCan()

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open, finding?.id])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    if (open) document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  return (
    <>
      <div
        className={cn(
          'fixed inset-0 z-30 bg-black/50 transition-opacity duration-200',
          open ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
        onClick={onClose}
        aria-hidden
      />
      <aside
        role="dialog"
        aria-label="Детали находки"
        aria-hidden={!open}
        className={cn(
          'fixed top-0 right-0 z-40 flex h-full w-[420px] flex-col border-l border-grid bg-surface',
          'transition-transform duration-200',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        {finding && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="flex items-center gap-2">
                {ordinal !== null && <span className="font-mono text-xs tabular-nums text-text-secondary">№{ordinal}</span>}
                <KindBadge kind={finding.kind} />
              </div>
              <button
                ref={closeRef}
                type="button"
                onClick={onClose}
                className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                aria-label="Свернуть (Esc)"
              >
                <X size={16} aria-hidden />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-4 py-4">
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-xs">
                <dt className="text-text-secondary">Объект</dt>
                <dd className="truncate font-mono text-text" title={finding.object_name}>
                  {finding.object_name}
                </dd>
                <dt className="text-text-secondary">Тип</dt>
                <dd className="text-text">{OBJECT_TYPE_LABELS[finding.object_type]}</dd>
                <dt className="text-text-secondary">Поле</dt>
                <dd className="font-mono text-text">{finding.field}</dd>
                {finding.shape && (
                  <>
                    {/* Форма значения — не то же, что класс: сетевое имя,
                        продублированное в списке, попадает в «дублирует
                        список», и по классу его не найти. */}
                    <dt className="text-text-secondary">Форма</dt>
                    <dd className="text-text">{SHAPE_LABELS[finding.shape]}</dd>
                  </>
                )}
                <dt className="text-text-secondary">Полярность</dt>
                <dd className="text-text">{POLARITY_LABELS[finding.polarity]}</dd>
                <dt className="text-text-secondary">Статус</dt>
                <dd>
                  <StatusBadge status={finding.status} />
                </dd>
              </dl>

              <div className="mt-4 border-t border-grid pt-4">
                {isLoading && (
                  <div className="flex items-center gap-2 text-xs text-text-secondary">
                    <Spinner size={14} /> загрузка значения…
                  </div>
                )}
                {isError && <div className="text-xs text-kind-1">Не удалось получить детали находки.</div>}
                {data && (
                  <div className="flex flex-col gap-3">
                    <div>
                      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                        Значение
                      </div>
                      <div className="rounded border border-grid bg-app-bg px-2.5 py-2 font-mono text-xs break-all text-text">
                        {data.value || '(значение недоступно)'}
                      </div>
                    </div>
                    <div>
                      <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                        Фрагмент тела
                      </div>
                      {/* Значение подсвечено тем же цветом, что и класс
                          находки вверху: во фрагменте на восемь строк
                          глазами его искать не легче, чем в целом теле. */}
                      <HighlightedBody
                        body={data.body_excerpt}
                        spans={spansForValue(
                          data.body_excerpt,
                          data.value,
                          Number(finding.kind),
                          finding.status,
                        )}
                      />
                    </div>
                    {data.table_name && (
                      <div>
                        <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                          Табличный список
                        </div>
                        <div className="font-mono text-xs text-text">{data.table_name}</div>
                      </div>
                    )}
                    {data.affected_rules.length > 0 && (
                      <div>
                        <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                          Затронутые правила ({data.affected_rules.length})
                        </div>
                        <ul className="flex flex-col gap-1">
                          {data.affected_rules.map((r) => (
                            <li key={r.uuid} className="truncate font-mono text-xs text-text-secondary" title={r.name}>
                              {r.name}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {write && (
            <div className="flex gap-2 border-t border-grid px-4 py-3">
              <button
                type="button"
                onClick={onTakeInWork}
                disabled={finding.status !== 'open'}
                className="flex-1 rounded border border-border px-3 py-1.5 text-xs font-medium text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:cursor-not-allowed disabled:opacity-40"
              >
                Взять в работу
              </button>
              <button
                type="button"
                onClick={onAccept}
                disabled={finding.status === 'accepted'}
                className="flex-1 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:cursor-not-allowed disabled:opacity-40"
              >
                Принять как норму
              </button>
            </div>
            )}
          </>
        )}
      </aside>
    </>
  )
}
