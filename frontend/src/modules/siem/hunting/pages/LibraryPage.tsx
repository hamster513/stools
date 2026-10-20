import { useMemo, useState } from 'react'
import { Download, Library, Plus, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { clickableRow, ROW_FOCUS } from '@/components/ui/clickableRow'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { LIBRARY_EXPORT_URL, useHunts } from '../api/queries'
import type { HuntQueryStatus } from '../api/types'
import { ImportDialog } from '../components/ImportDialog'
import { QueryStatus } from '../components/QueryStatus'
import { ScheduleLink } from '../components/ScheduleLink'
import { ruStamp } from '../format'

const ROW_HEIGHT = 36

const COLUMNS: ColumnDef[] = [
  { key: 'schedule', label: 'Расписание', width: 112 },
  { key: 'code', label: 'Код', width: 120 },
  { key: 'name', label: 'Название', width: 380, flex: true },
  { key: 'technique', label: 'Техника', width: 104 },
  { key: 'queries', label: 'Запросов', width: 88, align: 'right' },
  { key: 'last', label: 'Последний прогон', width: 232 },
  { key: 'fresh', label: 'Новых находок', width: 112, align: 'right' },
]

type Enabled = 'all' | 'on' | 'off'

/** Прогон, после которого хант «с ошибками»: запрос упал или прогон оборвался. */
const isRunError = (status: HuntQueryStatus | undefined) => status === 'failed' || status === 'aborted'

const HEADER_LINK =
  'flex items-center gap-1.5 rounded border border-border px-2 py-1 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Библиотека хантов Threat Hunting: ханты и их запросы, состояние в расписании ночных прогонов (меняется в планировщике), итог последнего прогона и число новых находок.
 * «+ хант» и «Загрузить YAML» — только тем, кто пишет; выгрузка в YAML доступна всем.
 */
export function LibraryPage() {
  const { navigate } = useRouter()
  const { write } = useCan()
  const [enabled, setEnabled] = useState<Enabled>('all')
  const [technique, setTechnique] = useState('')
  const [errorsOnly, setErrorsOnly] = useState(false)
  const [importing, setImporting] = useState(false)
  const filtersPanel = useFiltersPanel('siem-th-library')
  const cols = useColumnWidths('siem-th-library-columns', COLUMNS)
  const query = useHunts({ enabled: enabled === 'all' ? undefined : enabled === 'on', technique: technique || undefined })
  // Техники для фильтра берём из всей библиотеки, а не из отобранного: иначе выбранную технику не снять.
  const everything = useHunts()

  const techniques = useMemo(
    () => [...new Set([...(everything.data ?? []).map((h) => h.technique_id).filter((t): t is string => !!t), ...(technique ? [technique] : [])])].sort(),
    [everything.data, technique],
  )

  const chips: FilterChip[] = []
  if (enabled !== 'all') chips.push({ label: enabled === 'on' ? 'В расписании: да' : 'В расписании: нет', clear: () => setEnabled('all') })
  if (technique) chips.push({ label: `Техника: ${technique}`, clear: () => setTechnique('') })
  if (errorsOnly) chips.push({ label: 'Есть ошибки', clear: () => setErrorsOnly(false) })

  const data = query.data
  const items = (data ?? []).filter((h) => !errorsOnly || isRunError(h.last_run?.status))
  const errorMessage = query.error instanceof ApiRequestError ? query.error.message : query.isError ? 'Не удалось загрузить библиотеку' : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-grid bg-surface px-4 py-2.5">
        <h1 className="text-sm font-semibold text-text">Библиотека хантов</h1>
        <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
        <div className="font-mono text-xs tabular-nums text-text-secondary">{data ? `всего: ${items.length}` : ''}</div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {write && (
            <Button variant="primary" onClick={() => navigate('/siem/hunting/library/new')} className="px-2.5 py-1 text-xs">
              <Plus size={13} aria-hidden /> хант
            </Button>
          )}
          {write && (
            <button type="button" onClick={() => setImporting(true)} className={HEADER_LINK}>
              <Upload size={13} aria-hidden /> Загрузить YAML
            </button>
          )}
          <a href={LIBRARY_EXPORT_URL} download className={HEADER_LINK}>
            <Download size={13} aria-hidden /> Выгрузить YAML
          </a>
        </div>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </header>

      <div className="flex min-h-0 flex-1">
        {filtersPanel.open && (
          <div className="flex h-full w-60 shrink-0 flex-col overflow-y-auto border-r border-grid bg-surface">
            <div className="border-b border-grid px-2 py-3">
              <div className="mb-1.5 px-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">В расписании</div>
              {([['all', 'Любые'], ['on', 'В расписании'], ['off', 'Не запускаются']] as const).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setEnabled(value)}
                  aria-pressed={enabled === value}
                  className={cn(
                    'flex w-full items-center rounded px-2 py-1.5 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                    enabled === value ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="flex flex-col gap-3 px-4 py-3">
              <label className="block">
                <span className="mb-1.5 block text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Техника</span>
                <select value={technique} onChange={(e) => setTechnique(e.target.value)} className={cn(FIELD, 'font-mono text-xs')}>
                  <option value="">Любая</option>
                  {techniques.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="flex items-center gap-1.5 text-xs text-text">
                <input type="checkbox" checked={errorsOnly} onChange={(e) => setErrorsOnly(e.target.checked)} className="accent-primary" />
                есть ошибки
              </label>
              <p className="text-[11px] text-text-secondary">Ошибки: последний прогон ханта упал или оборвался.</p>
            </div>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col bg-app-bg">
          {query.isLoading && <FullPageSpinner />}
          {errorMessage && <div className="p-6"><ErrorState message={errorMessage} onRetry={() => query.refetch()} /></div>}
          {data && !errorMessage && items.length === 0 && (
            <div className="p-6">
              <EmptyState
                icon={Library}
                title="Хантов нет"
                description={chips.length ? 'Под выбранные фильтры ничего не попало. Снимите фильтры, чтобы увидеть всю библиотеку.' : 'Библиотека пуста: добавьте хант или загрузите готовую библиотеку из YAML.'}
              />
            </div>
          )}
          {data && !errorMessage && items.length > 0 && (
            <div data-col-resize-root className="min-h-0 flex-1 overflow-auto">
              <div className="sticky top-0 z-10 grid border-b border-grid bg-surface text-[11px] tracking-wide text-text-secondary uppercase" style={cols.gridStyle}>
                <ResizableHeader cols={cols} as="div" className="px-2 py-2" />
              </div>
              {items.map((h) => (
                <div
                  key={h.id}
                  {...clickableRow(() => navigate(`/siem/hunting/library/${h.id}`))}
                  className={cn(ROW_FOCUS, 'grid cursor-pointer items-center border-b border-grid text-xs hover:bg-row-hover', !h.enabled && 'text-text-secondary')}
                  style={{ ...cols.gridStyle, height: ROW_HEIGHT }}
                >
                  <div className="min-w-0 truncate px-2"><ScheduleLink enabled={h.enabled} /></div>
                  <div className="min-w-0 truncate px-2 font-mono text-text">{h.code}</div>
                  <div className="min-w-0 truncate px-2 text-text" title={h.name}>{h.name}</div>
                  <div className="min-w-0 truncate px-2 font-mono text-text-secondary">{h.technique_id ?? '—'}</div>
                  <div className="min-w-0 px-2 text-right font-mono tabular-nums text-text">{h.queries}</div>
                  <div className="min-w-0 truncate px-2 text-text-secondary">
                    {h.last_run ? (
                      <>
                        <QueryStatus status={h.last_run.status} /> <span className="tabular-nums">{ruStamp(h.last_run.at)}</span>
                      </>
                    ) : '—'}
                  </div>
                  <div className={cn('min-w-0 px-2 text-right font-mono tabular-nums', h.new_findings > 0 ? 'font-semibold text-text' : 'text-text-secondary')}>{h.new_findings}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {importing && <ImportDialog onClose={() => setImporting(false)} />}
    </div>
  )
}
