import { useState } from 'react'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { Camera, RotateCcw, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, useRouter } from '@/lib/router'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { SEVERITIES, type SnapshotBase } from './types'

const COLUMNS: ColumnDef[] = [
  { key: 'snapshot', label: 'Снапшот', width: 160, flex: true },
  { key: 'source', label: 'Источник', width: 152 },
  { key: 'count', label: 'Количество', width: 108, align: 'right' },
  { key: 'findings', label: 'Находок', width: 88, align: 'right' },
  ...SEVERITIES.slice(0, 4).map((s): ColumnDef => ({ key: s, label: s, width: 72, align: 'right' })),
  { key: 'new', label: 'Новых', width: 72, align: 'right' },
  { key: 'fixed', label: 'Закрыто', width: 84, align: 'right' },
  { key: 'actions', label: 'Действие', width: 104, resizable: false },
]

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/**
 * Экран «Снапшоты» модуля. Модуль задаёт, куда ведёт снапшот, как назвать
 * источник и что считать (объекты, хосты), и тексты пустого списка и удаления.
 * Ширины колонок — под `storageKey`, по умолчанию по модулю из адреса (`ad-snapshots-columns`).
 */
export function CollectorSnapshotsPage<S extends SnapshotBase>({ snapshots, reanalyze, remove, findingsPath, emptyDescription, countHeader, count, source, deleteNote, storageKey }: {
  snapshots: UseQueryResult<S[], ApiRequestError>
  reanalyze: UseMutationResult<{ job_id: number }, ApiRequestError, number>
  remove: UseMutationResult<void, ApiRequestError, number>
  findingsPath: string
  emptyDescription: string
  countHeader: string
  count: (s: S) => number
  source: (s: S) => string
  deleteNote: string
  storageKey?: string
}) {
  // Список снапшотов — чтение; пересчёт и удаление аудитору недоступны.
  const { write } = useCan()
  const [confirm, setConfirm] = useState<S | null>(null)
  const { path } = useRouter()
  const cols = useColumnWidths(storageKey ?? `${path.split('/')[1] || 'collector'}-snapshots-columns`, COLUMNS)

  if (snapshots.isLoading) return <FullPageSpinner />
  if (snapshots.isError || !snapshots.data) {
    const msg = snapshots.error instanceof ApiRequestError ? snapshots.error.message : 'Не удалось загрузить снапшоты'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => snapshots.refetch()} /></div>
  }
  const err = reanalyze.error ?? remove.error
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-text">Снапшоты</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Каждая выгрузка или сбор — снапшот. Разница считается с предыдущим по времени сбора. Пересчёт заново
          прогоняет проверки по сохранённой выгрузке с текущими правилами; статусы находок живут отдельно и не теряются.
        </p>
      </div>
      {snapshots.data.length === 0 ? (
        <EmptyState icon={Camera} title="Снапшотов нет" description={emptyDescription} />
      ) : (
        <div className="overflow-x-auto rounded border border-grid">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="bg-surface text-[11px] tracking-wide text-text-secondary uppercase">
              <tr>
                <ResizableHeader cols={cols} className="px-3 py-2" content={{ count: countHeader, actions: <span className="sr-only">Действие</span> }} />
              </tr>
            </thead>
            <tbody>
              {snapshots.data.map((s) => (
                <tr key={s.id} className="border-t border-grid">
                  <td className="px-3 py-2">
                    <Link to={`${findingsPath}?snapshot=${s.id}`} className="text-text hover:text-primary">#{s.id} · {when(s.collected_at)}</Link>
                  </td>
                  <td className="px-3 py-2 break-words text-text-secondary">{source(s)} · {s.collector}{s.filename ? ` · ${s.filename}` : ''}</td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{count(s).toLocaleString('ru-RU')}</td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-text">{s.findings}</td>
                  {SEVERITIES.slice(0, 4).map((sev) => <td key={sev} className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{s.by_severity[sev] ?? 0}</td>)}
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-risk-high">{s.new ?? '—'}</td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-kind-accepted">{s.fixed ?? '—'}</td>
                  <td className="px-3 py-2 text-right whitespace-nowrap">
                    {write && (
                      <>
                        <Button variant="ghost" onClick={() => reanalyze.mutate(s.id)} loading={reanalyze.isPending} title="Пересчитать с текущими правилами"><RotateCcw size={13} aria-hidden /></Button>
                        <Button variant="ghost" onClick={() => setConfirm(s)} title="Удалить снапшот"><Trash2 size={13} aria-hidden /></Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {err && <p className="mt-3 text-xs text-kind-1">{err instanceof ApiRequestError ? err.message : 'Не удалось выполнить'}</p>}
      {reanalyze.data && <p className="mt-3 text-xs text-text-secondary">пересчёт запущен, задача #{reanalyze.data.job_id}</p>}
      {confirm && (
        <div role="dialog" aria-label="Удалить снапшот" className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
            <div className="mb-2 text-sm font-semibold text-text">Удалить снапшот #{confirm.id}?</div>
            <p className="mb-4 text-xs text-text-secondary">{deleteNote}</p>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setConfirm(null)}>Отмена</Button>
              <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(confirm.id, { onSuccess: () => setConfirm(null) })}>Удалить</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
