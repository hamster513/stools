import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCaData, useDeleteCaData, useDomains, useJob } from '@/modules/ad/api/queries'
import { CA_SECTION_LABELS, type CaData } from '@/modules/ad/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'collected', label: 'Дата сбора', width: 176 },
  { key: 'sections', label: 'Разделы', width: 240, flex: true },
  { key: 'cas', label: 'ЦС', width: 64, align: 'right' },
  { key: 'dcs', label: 'Контроллеров', width: 112, align: 'right' },
  { key: 'uploaded', label: 'Кто загрузил', width: 160 },
  { key: 'actions', label: 'Удалить', width: 48, resizable: false },
]

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/** Загрузки данных центра сертификации по домену: список и удаление. */
export function CaDataSection() {
  const { write } = useCan()
  const domains = useDomains()
  const list = domains.data ?? []
  const [picked, setPicked] = useState<number | undefined>()
  const domainId = picked ?? list[0]?.id
  const data = useCaData(domainId)
  const remove = useDeleteCaData()
  // Пересчёт после удаления — как после загрузки: useJob опрашивает задачу и по её окончании
  // обновляет обзор, находки и снапшоты.
  const job = useJob(remove.data?.job_id)
  const [confirm, setConfirm] = useState<CaData | null>(null)
  const cols = useColumnWidths('ad-ca-data-columns', COLUMNS)

  return (
    <Section title="Данные центра сертификации" about="Настройки и права ЦС, реестр контроллеров и веб-выдача собираются отдельно скриптом (пункты 5–7 меню), из продукта по LDAP они недоступны. Файл загружается тем же полем, что и выгрузка AD; анализ берёт каждый раздел из самой свежей загрузки, где он есть.">
      {list.length === 0 ? (
        <p className="text-xs text-text-secondary">Доменов ещё нет: сначала загрузите выгрузку домена.</p>
      ) : (
        <>
          <div className="mb-3 max-w-xs">
            <Field label="Домен">
              <select className={FIELD} value={domainId ?? ''} onChange={(e) => setPicked(Number(e.target.value))}>
                {list.map((d) => <option key={d.id} value={d.id}>{d.dns_root || d.netbios || d.sid}</option>)}
              </select>
            </Field>
          </div>
          {data.isError && <p className="text-xs text-kind-1">{data.error instanceof ApiRequestError ? data.error.message : 'Не удалось загрузить данные ЦС'}</p>}
          {data.data && data.data.length === 0 && <p className="text-xs text-text-secondary">Данные ЦС не загружались: ESC6–8, 10, 11, 16 не проверяются</p>}
          {data.data && data.data.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs" style={cols.tableStyle}>
                <ColGroup cols={cols} />
                <thead className="text-[11px] tracking-wide text-text-secondary uppercase"><tr><ResizableHeader cols={cols} className="py-1.5 pr-3" content={{ actions: <span className="sr-only">Удалить</span> }} /></tr></thead>
                <tbody>
                  {data.data.map((c) => (
                    <tr key={c.id} className="border-t border-grid align-top">
                      <td className="py-2 pr-3 text-text">{when(c.collected_at)}<div className="text-[10px] break-all text-text-secondary">{c.filename}</div></td>
                      <td className="py-2 pr-3 break-words text-text-secondary">{c.sections.map((s) => CA_SECTION_LABELS[s] ?? s).join(', ')}</td>
                      <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{c.cas}</td>
                      <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{c.dcs}</td>
                      <td className="py-2 pr-3 break-all text-text-secondary">{c.uploaded_by}<div className="text-[10px]">{when(c.imported_at)}</div></td>
                      <td className="py-2 text-right">{write && <Button variant="ghost" onClick={() => setConfirm(c)} aria-label="Удалить данные ЦС"><Trash2 size={13} aria-hidden /></Button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      {remove.data && job.data?.status === 'failed' && <p className="mt-2 text-xs text-kind-1">пересчёт не удался, задача #{remove.data.job_id}: {job.data.error}</p>}
      {remove.data && job.data?.status !== 'failed' && <p className="mt-2 text-xs text-text-secondary">{job.data && job.data.status !== 'running' ? `пересчёт завершён, задача #${remove.data.job_id}` : `пересчёт запущен, задача #${remove.data.job_id} — прогресс на экране «Задачи»`}</p>}
      {remove.error && <p className="mt-2 text-xs text-kind-1">{remove.error instanceof ApiRequestError ? remove.error.message : 'Не удалось удалить'}</p>}
      {confirm && (
        <div role="dialog" aria-label="Удалить данные ЦС" className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
            <div className="mb-2 text-sm font-semibold text-text">Удалить данные ЦС от {when(confirm.collected_at)}?</div>
            <p className="mb-4 text-xs text-text-secondary">Последний снапшот домена будет пересчитан: разделы возьмутся из более ранних загрузок, а если их нет — соответствующие ESC станут непроверенными.</p>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setConfirm(null)}>Отмена</Button>
              <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(confirm.id, { onSuccess: () => setConfirm(null) })}>Удалить</Button>
            </div>
          </div>
        </div>
      )}
    </Section>
  )
}
