import { useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { useSaveNetwork, useZones } from '@/modules/assets/api/queries'
import type { Network, NetworkIn } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/platform/collector/ui'

/** Теги в форме — строкой: так их удобно вставлять из заметок и таблиц. */
interface FormState extends Omit<NetworkIn, 'tags'> {
  tags: string
}

const EMPTY: NetworkIn = { cidr: '', title: '', description: '', zone: null, site: '', owner: '', vlan: null, tags: [] }

const shown = (value: number | null) => (value === null || Number.isNaN(value) ? '' : value)

function toForm(n: NetworkIn): FormState {
  return { ...n, tags: n.tags.join(', ') }
}

function toBody(f: FormState): NetworkIn {
  return {
    ...f,
    tags: f.tags.split(',').map((t) => t.trim()).filter(Boolean),
    vlan: f.vlan === null || Number.isNaN(f.vlan) ? null : f.vlan,
  }
}

/** Форма сети: CIDR, название, зона, площадка, владелец, VLAN, теги, описание.
 * `initialCidr` — CIDR новой сети, предложенный по адресу актива без сети. */
export function NetworkForm({ network, initialCidr = '', onDone, onCancel }: { network: Network | null; initialCidr?: string; onDone: () => void; onCancel: () => void }) {
  const save = useSaveNetwork()
  const zones = useZones()
  const [f, setF] = useState<FormState>(() => toForm(network ?? { ...EMPTY, cidr: initialCidr }))
  const patch = (p: Partial<FormState>) => setF((v) => ({ ...v, ...p }))

  return (
    <div className="rounded border border-grid bg-surface p-4">
      <div className="mb-3 text-sm font-semibold text-text">{network ? `Сеть ${network.cidr}` : 'Новая сеть'}</div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="CIDR" hint="Например 10.10.0.0/24"><input className={FIELD} value={f.cidr} onChange={(e) => patch({ cidr: e.target.value })} spellCheck={false} /></Field>
        <Field label="Название"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
        <Field label="Зона" hint="Справочник зон — в настройках модуля">
          <select className={FIELD} value={f.zone ?? ''} onChange={(e) => patch({ zone: e.target.value || null })}>
            <option value="">без зоны</option>
            {(zones.data ?? []).map((z) => <option key={z.name} value={z.name}>{z.title && z.title !== z.name ? `${z.name} — ${z.title}` : z.name}</option>)}
          </select>
        </Field>
        <Field label="Площадка"><input className={FIELD} value={f.site} onChange={(e) => patch({ site: e.target.value })} /></Field>
        <Field label="Владелец"><input className={FIELD} value={f.owner} onChange={(e) => patch({ owner: e.target.value })} /></Field>
        <Field label="VLAN" hint="1–4094, необязательно"><input className={FIELD} type="number" min={1} max={4094} value={shown(f.vlan)} onChange={(e) => patch({ vlan: e.target.value === '' ? null : Number(e.target.value) })} /></Field>
        <Field label="Теги через запятую"><input className={FIELD} value={f.tags} onChange={(e) => patch({ tags: e.target.value })} /></Field>
        <div className="sm:col-span-2">
          <Field label="Описание"><textarea className={FIELD} rows={2} value={f.description} onChange={(e) => patch({ description: e.target.value })} /></Field>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.cidr.trim()} onClick={() => save.mutate({ id: network?.id, body: toBody(f) }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onCancel}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
      </div>
    </div>
  )
}
