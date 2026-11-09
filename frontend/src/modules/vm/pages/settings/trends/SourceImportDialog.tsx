import { useState } from 'react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { TREND_BASE, useTrendMutation } from '../../../api/trends'
import type { CatalogPlan } from '../../../api/trendMonitoring'
export function SourceImportDialog({ initial, close }: { initial: CatalogPlan; close: () => void }) {
  const [plan, setPlan] = useState(initial)
  const save = useTrendMutation(async () => { await api.post(TREND_BASE + '/catalog/apply', plan); close() })
  const selected = plan.rows.filter(r => r.selected).length
  return <section className="space-y-3 rounded border border-grid p-4"><h4 className="font-semibold">Предпросмотр источников</h4><p className="text-sm">Выбрано {selected} из {plan.rows.length}. Новые источники каталога выключены. Выбор существующей строки явно применит показанные отличия.</p>
    <div className="max-h-96 overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th>Выбор</th><th>Источник</th><th>Действие / отличия</th></tr></thead><tbody>{plan.rows.map((row, index) => <tr key={row.index} className="border-t border-grid"><td className="p-2"><input type="checkbox" aria-label={`Выбрать ${row.source.name}`} checked={row.selected} disabled={['error', 'duplicate', 'conflict'].includes(row.action)} onChange={e => setPlan({ ...plan, rows: plan.rows.map((r, i) => i === index ? { ...r, selected: e.target.checked, action: r.action === 'existing' ? 'update' : r.action } : r) })} /></td><td className="p-2">{row.source.name}<p className="break-all text-xs text-text-secondary">{row.source.url}</p></td><td className="p-2">{row.error ?? ({ add: 'Добавить', existing: 'Уже есть', update: 'Обновить', duplicate: 'Дубль', conflict: 'Конфликт — разрешите вручную' }[row.action] ?? row.action)}<p className="text-xs">{row.changed_fields?.join(', ')}</p></td></tr>)}</tbody></table></div>
    <div className="flex gap-2"><Button disabled={!selected || save.isPending} onClick={() => save.mutate()}>Применить выбранное</Button><Button onClick={close}>Закрыть предпросмотр</Button></div>{save.error && <p role="alert">{save.error.message}</p>}
  </section>
}
