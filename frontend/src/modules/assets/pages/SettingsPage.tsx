import { useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useCreateZone, useDeleteZone, useZones } from '@/modules/assets/api/queries'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { DnsSection } from './settings/DnsSection'

function message(error: unknown, fallback: string): string {
  return error instanceof ApiRequestError ? error.message : fallback
}

/** Справочник зон: зона сети выбирается из него; зону, заданную у сетей, удалить нельзя. */
function ZonesSection() {
  const { write } = useCan()
  const zones = useZones()
  const create = useCreateZone()
  const remove = useDeleteZone()
  const [form, setForm] = useState({ name: '', title: '', description: '' })

  return (
    <Section title="Справочник зон" about="Зона сети — DMZ, внутренняя, гостевая и т. п. По зоне фильтруются активы. Зону, которая задана у сетей, удалить нельзя: сначала смените сетям зону.">
      {zones.isLoading && <Spinner />}
      {zones.isError && <ErrorState message={message(zones.error, 'Не удалось загрузить зоны')} onRetry={() => zones.refetch()} />}
      {zones.data && (
        <table className="mb-3 w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr><th className="py-1.5 pr-3 text-left">Зона</th><th className="py-1.5 pr-3 text-left">Название</th><th className="py-1.5 pr-3 text-left">Описание</th><th className="py-1.5 pr-3 text-right">Сетей</th><th /></tr>
          </thead>
          <tbody>
            {zones.data.map((z) => (
              <tr key={z.name} className="border-t border-grid align-top">
                <td className="py-2 pr-3 font-mono text-text">{z.name}</td>
                <td className="py-2 pr-3 text-text">{z.title || '—'}</td>
                <td className="py-2 pr-3 text-text-secondary">{z.description || '—'}</td>
                <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{z.networks}</td>
                <td className="py-2 text-right">
                  {write && (
                    <Button variant="ghost" onClick={() => remove.mutate(z.name)} disabled={z.networks > 0} title={z.networks > 0 ? 'зона задана у сетей' : undefined} aria-label={`Удалить зону ${z.name}`}>
                      <Trash2 size={13} aria-hidden />
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {remove.error && <p className="mb-2 text-xs text-kind-1">{message(remove.error, 'Зона не удалена')}</p>}
      {write && (
        <div className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_2fr_auto]">
          <Field label="Имя"><input className={FIELD} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Lab" /></Field>
          <Field label="Название"><input className={FIELD} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
          <Field label="Описание"><input className={FIELD} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <Button loading={create.isPending} disabled={!form.name.trim()} onClick={() => create.mutate(form, { onSuccess: () => setForm({ name: '', title: '', description: '' }) })}>
            <Plus size={13} aria-hidden /> Добавить
          </Button>
        </div>
      )}
      {create.error && <p className="mt-2 text-xs text-kind-1">{message(create.error, 'Зона не добавлена')}</p>}
    </Section>
  )
}

/** «Настройки и данные» модуля Assets: DNS-серверы и справочник зон; пороги и синхронизация — следующими блоками. */
export function SettingsPage() {
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Справочники и настройки реестра активов.</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <DnsSection />
        <ZonesSection />
      </div>
    </div>
  )
}
