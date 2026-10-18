import { useEffect, useState } from 'react'
import { Save } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useRecalculate, useSaveZones, useZones } from '@/modules/vm/api/queries'
import type { Zone } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'zone', label: 'Зона', width: 200, flex: true },
  { key: 'hosts', label: 'Хостов', width: 80, align: 'right' },
  { key: 'internet', label: 'Доступна из интернета', width: 160 },
  { key: 'confidential', label: 'Конфиденциальные данные', width: 176 },
  { key: 'marked', label: 'Разметка', width: 120 },
]

/** Разметка зон — единственный источник двух из трёх слагаемых Impact. */
export function ZonesSection() {
  // Разметка зон — решение, а не наблюдение: аудитор видит её, но не ставит.
  const { write } = useCan()
  const zones = useZones()
  const save = useSaveZones()
  const recalc = useRecalculate()
  const cols = useColumnWidths('vm-zones-columns', COLUMNS)
  const [draft, setDraft] = useState<Zone[]>([])
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (zones.data) { setDraft(zones.data); setDirty(false) }
  }, [zones.data])

  function toggle(name: string, key: 'internet_access' | 'confidential_data') {
    setDirty(true)
    setDraft((d) => d.map((z) => (z.name === name ? { ...z, [key]: !z[key], marked: true } : z)))
  }
  function submit() {
    save.mutate(draft.map(({ name, internet_access, confidential_data }) => ({ name, internet_access, confidential_data })), {
      onSuccess: () => { setDirty(false); recalc.mutate() },
    })
  }
  const unmarked = draft.filter((z) => !z.marked).length

  return (
    <Section
      id="zones"
      title="Зоны"
      about="Зоны приходят из Host.UF_Zone при импорте. VM не знает, доступна ли зона из интернета и лежат ли в ней конфиденциальные данные, — это и задаётся здесь, один раз. Неразмеченная зона считается как «нет и нет», и каждая пара в ней помечена в карточке как подстановка. Сохранение запускает пересчёт."
    >
      {draft.length === 0 ? (
        <p className="text-xs text-text-secondary">Зон ещё нет — появятся после первого импорта.</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full max-w-3xl text-xs" style={cols.tableStyle}>
              <ColGroup cols={cols} />
              <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
                <tr>
                  <ResizableHeader cols={cols} className="py-1.5 pr-3" />
                </tr>
              </thead>
              <tbody>
                {draft.map((z) => (
                  <tr key={z.name} className="border-t border-grid">
                    <td className="truncate py-1.5 pr-3 font-mono text-text" title={z.name}>{z.name}</td>
                    <td className="py-1.5 pr-3 text-right font-mono tabular-nums text-text-secondary">{z.hosts.toLocaleString('ru-RU')}</td>
                    <td className="py-1.5 pr-3"><label className="inline-flex items-center gap-2"><input type="checkbox" className="accent-primary" checked={z.internet_access} onChange={() => toggle(z.name, 'internet_access')} aria-label={`${z.name}: доступна из интернета`} disabled={!write} /></label></td>
                    <td className="py-1.5 pr-3"><label className="inline-flex items-center gap-2"><input type="checkbox" className="accent-primary" checked={z.confidential_data} onChange={() => toggle(z.name, 'confidential_data')} aria-label={`${z.name}: конфиденциальные данные`} disabled={!write} /></label></td>
                    <td className={cn('truncate py-1.5 pr-3', z.marked ? 'text-text-secondary' : 'text-risk-medium')}>{z.marked ? 'размечена' : 'не размечена'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {write && (
            <div className="mt-3 flex items-center gap-3 border-t border-grid pt-3">
              <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}><Save size={13} aria-hidden /> Сохранить и пересчитать</Button>
              {unmarked > 0 && <span className="text-xs text-risk-medium">не размечено: {unmarked}</span>}
              {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
              {recalc.data && !dirty && <span className="text-xs text-text-secondary">пересчёт запущен, задача #{recalc.data.job_id}</span>}
            </div>
          )}
        </>
      )}
    </Section>
  )
}
