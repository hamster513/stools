import { useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { useDeleteSchedule, useSaveNetwork, useSaveSchedule, useZones } from '@/modules/assets/api/queries'
import { DEFAULT_PORTS, type Network, type NetworkIn } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/platform/collector/ui'

/** Списки в форме — строкой: так их удобно вставлять из заметок и таблиц. */
interface FormState extends Omit<NetworkIn, 'tags' | 'ports' | 'exclude'> {
  tags: string
  ports: string
  exclude: string
}

const EMPTY: NetworkIn = {
  cidr: '', title: '', description: '', zone: null, site: '', owner: '', vlan: null, tags: [],
  scan_enabled: false, ports: DEFAULT_PORTS, exclude: [], concurrency: 64, icmp_timeout_ms: 1000, tcp_timeout_ms: 2000,
}

const split = (text: string) => text.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean)

// Пустое числовое поле — NaN, а не 0: уходит как null, и API отвечает русским текстом о допустимых границах.
const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number | null) => (value === null || Number.isNaN(value) ? '' : value)

function toForm(n: NetworkIn): FormState {
  return { ...n, tags: n.tags.join(', '), ports: n.ports.join(', '), exclude: n.exclude.join(', ') }
}

function toBody(f: FormState): NetworkIn {
  return {
    ...f,
    tags: f.tags.split(',').map((t) => t.trim()).filter(Boolean),
    // Нечисловой порт уходит как есть (NaN → null), чтобы API ответил текстом, а не форма молча его выбросила.
    ports: split(f.ports).map(Number),
    exclude: split(f.exclude),
    vlan: f.vlan === null || Number.isNaN(f.vlan) ? null : f.vlan,
  }
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : '—'
}

/** Расписание сканов сети: интервал и окно. Сохраняется отдельно от полей сети — это своя запись планировщика. */
function ScheduleBlock({ network }: { network: Network }) {
  const save = useSaveSchedule(network.id)
  const remove = useDeleteSchedule(network.id)
  const current = network.schedule
  const [hours, setHours] = useState<number>(current?.interval_hours ?? 24)
  const [from, setFrom] = useState(current?.window_from ?? '')
  const [to, setTo] = useState(current?.window_to ?? '')
  const [enabled, setEnabled] = useState(current?.enabled ?? true)
  const error = save.error ?? remove.error
  return (
    <>
      <div className="mt-4 mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Расписание сканов</div>
      <label className="mb-3 flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Сканировать по расписанию</label>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Интервал, часов" hint="1–720"><input className={FIELD} type="number" min={1} max={720} value={shown(hours)} onChange={(e) => setHours(numberOrEmpty(e.target.value))} /></Field>
        <Field label="Окно с" hint="Пусто — без окна"><input className={FIELD} type="time" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="Окно по" hint="Конец окна не входит"><input className={FIELD} type="time" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
      </div>
      <p className="mt-2 text-xs text-text-secondary">
        Окно в поясе STOOLS_TZ{current ? ` (${current.tz})` : ''}. Сканирование сети должно быть включено, иначе запуск по расписанию отклоняется.
        {current && ` Следующий запуск: ${current.enabled ? when(current.next_run_at) : 'выключено'}; прошлый: ${when(current.last_run_at)}.`}
      </p>
      <div className="mt-2 flex items-center gap-2">
        <Button loading={save.isPending} onClick={() => save.mutate({ interval_hours: hours, window_from: from || null, window_to: to || null, enabled })}>
          Сохранить расписание
        </Button>
        {current && <Button variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}>Удалить расписание</Button>}
        {save.isSuccess && !save.isPending && <span className="text-xs text-text-secondary">сохранено</span>}
        {error && <span className="text-xs text-kind-1">{error instanceof ApiRequestError ? error.message : 'Не удалось сохранить расписание'}</span>}
      </div>
    </>
  )
}

/** Форма сети: описание, настройки сканирования и расписание сканов (у сохранённой сети). */
export function NetworkForm({ network, onDone, onCancel }: { network: Network | null; onDone: () => void; onCancel: () => void }) {
  const save = useSaveNetwork()
  const zones = useZones()
  const [f, setF] = useState<FormState>(() => toForm(network ?? EMPTY))
  const patch = (p: Partial<FormState>) => setF((v) => ({ ...v, ...p }))

  return (
    <div className="rounded border border-grid bg-surface p-4">
      <div className="mb-3 text-sm font-semibold text-text">{network ? `Сеть ${network.cidr}` : 'Новая сеть'}</div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="CIDR" hint="Например 10.10.0.0/24; IPv4 не шире /16"><input className={FIELD} value={f.cidr} onChange={(e) => patch({ cidr: e.target.value })} spellCheck={false} /></Field>
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

      <div className="mt-4 mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Сканирование</div>
      <label className="mb-3 flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={f.scan_enabled} onChange={(e) => patch({ scan_enabled: e.target.checked })} /> Сканировать эту сеть</label>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Порты TCP" hint="Через запятую, не больше 64"><input className={FIELD} value={f.ports} onChange={(e) => patch({ ports: e.target.value })} spellCheck={false} /></Field>
        <Field label="Исключить" hint="Адреса и сети через запятую"><input className={FIELD} value={f.exclude} onChange={(e) => patch({ exclude: e.target.value })} spellCheck={false} /></Field>
        <Field label="Параллельно адресов" hint="1–256"><input className={FIELD} type="number" min={1} max={256} value={shown(f.concurrency)} onChange={(e) => patch({ concurrency: numberOrEmpty(e.target.value) })} /></Field>
        <Field label="Таймаут ICMP, мс" hint="50–10000"><input className={FIELD} type="number" min={50} max={10000} step={100} value={shown(f.icmp_timeout_ms)} onChange={(e) => patch({ icmp_timeout_ms: numberOrEmpty(e.target.value) })} /></Field>
        <Field label="Таймаут TCP, мс" hint="50–30000"><input className={FIELD} type="number" min={50} max={30000} step={100} value={shown(f.tcp_timeout_ms)} onChange={(e) => patch({ tcp_timeout_ms: numberOrEmpty(e.target.value) })} /></Field>
      </div>

      {network ? <ScheduleBlock network={network} /> : <p className="mt-3 text-xs text-text-secondary">Расписание сканов задаётся после сохранения сети.</p>}

      <div className="mt-4 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.cidr.trim()} onClick={() => save.mutate({ id: network?.id, body: toBody(f) }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onCancel}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{save.error instanceof ApiRequestError ? save.error.message : 'Не удалось сохранить'}</span>}
      </div>
    </div>
  )
}
