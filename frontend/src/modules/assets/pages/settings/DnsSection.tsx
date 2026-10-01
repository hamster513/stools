import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Play, Plus, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useAdConnections, useDeleteDns, useDeleteDnsSchedule, useDnsServers, useJob, useRunDns, useSaveDns, useSaveDnsSchedule,
} from '@/modules/assets/api/queries'
import type { AdConnectionRef, DnsIn, DnsServer, NetworkSchedule } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'

const EMPTY: DnsIn = {
  title: '', mode: 'direct', server: '', ad_connection_id: null, zones: [], forward: true, reverse: true, zone_read: false,
  rate_per_s: 50, timeout_ms: 3000, enabled: true,
}

/** Зоны в форме — по одной на строку. */
interface FormState extends Omit<DnsIn, 'zones'> {
  zones: string
}

// Пустое числовое поле — NaN: уходит как null, и API отвечает русским текстом о границах.
const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number) => (Number.isNaN(value) ? '' : value)

function message(error: unknown, fallback: string): string {
  return error instanceof ApiRequestError ? error.message : fallback
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : '—'
}

function scheduleText(s: NetworkSchedule | null): string {
  if (!s) return 'вручную'
  const every = s.interval_hours % 24 === 0 ? `раз в ${s.interval_hours / 24} сут` : `раз в ${s.interval_hours} ч`
  const window = s.window_from && s.window_to ? `, ${s.window_from}–${s.window_to} ${s.tz}` : ''
  if (!s.enabled) return `выключено (${every}${window})`
  return `${every}${window}; следующий ${when(s.next_run_at)}`
}

function whatText(d: DnsServer, connections: AdConnectionRef[]): string {
  if (d.mode === 'ad') {
    const conn = connections.find((c) => c.id === d.ad_connection_id)
    return `зоны AD ${d.zones.join(', ')} · ${conn ? conn.title || conn.host : 'подключение удалено'}`
  }
  const kinds = [d.forward && 'прямые', d.reverse && 'обратные'].filter(Boolean).join(' и ')
  return `${d.server || 'системный резолвер'} · ${kinds}`
}

/** «Запустить сейчас»: номер задачи, ход и итог; по окончании обновляются реестр и список серверов. */
function RunButton({ dns }: { dns: DnsServer }) {
  const qc = useQueryClient()
  const run = useRunDns()
  const [jobId, setJobId] = useState<number | null>(null)
  const job = useJob(jobId)
  const status = job.data?.status
  useEffect(() => {
    if (status && status !== 'running') {
      for (const key of ['assets-dns', 'assets-list', 'assets-asset']) qc.invalidateQueries({ queryKey: [key] })
    }
  }, [status, qc])
  const running = run.isPending || status === 'running' || (jobId !== null && !job.data)
  return (
    <div className="flex flex-col items-end gap-0.5">
      <Button variant="ghost" loading={running} disabled={running || !dns.enabled} title={dns.enabled ? undefined : 'Сервер выключен — включите его в форме'}
        onClick={() => run.mutate(dns.id, { onSuccess: (r) => setJobId(r.job_id) })}>
        <Play size={13} aria-hidden /> запустить
      </Button>
      {run.error && <span className="max-w-56 text-right text-[11px] whitespace-normal text-kind-1">{run.error.message}</span>}
      {jobId !== null && (
        <span className="max-w-56 text-right text-[11px] whitespace-normal text-text-secondary">
          <Link to="/assets/jobs" className="hover:underline">задача #{jobId}</Link>
          {status === 'running' && job.data && ` · ${job.data.message}`}
          {status === 'done' && ` · ${job.data?.message}`}
          {status === 'failed' && <span className="text-kind-1"> · {job.data?.error ?? 'не удалась'}</span>}
          {status === 'cancelled' && ' · отменена'}
        </span>
      )}
    </div>
  )
}

/** Расписание обновления через DNS: интервал и окно, своя запись планировщика. */
function ScheduleBlock({ dns }: { dns: DnsServer }) {
  const save = useSaveDnsSchedule(dns.id)
  const remove = useDeleteDnsSchedule(dns.id)
  const current = dns.schedule
  const [hours, setHours] = useState<number>(current?.interval_hours ?? 24)
  const [from, setFrom] = useState(current?.window_from ?? '')
  const [to, setTo] = useState(current?.window_to ?? '')
  const [enabled, setEnabled] = useState(current?.enabled ?? true)
  const error = save.error ?? remove.error
  return (
    <>
      <div className="mt-4 mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Расписание</div>
      <label className="mb-3 flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Обновлять по расписанию</label>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Интервал, часов" hint="1–720"><input className={FIELD} type="number" min={1} max={720} value={shown(hours)} onChange={(e) => setHours(numberOrEmpty(e.target.value))} /></Field>
        <Field label="Окно с" hint="Пусто — без окна"><input className={FIELD} type="time" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="Окно по" hint="Конец окна не входит"><input className={FIELD} type="time" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
      </div>
      <p className="mt-2 text-xs text-text-secondary">
        Окно в поясе STOOLS_TZ{current ? ` (${current.tz})` : ''}. Выключенный сервер по расписанию не запускается.
        {current && ` Следующий запуск: ${current.enabled ? when(current.next_run_at) : 'выключено'}; прошлый: ${when(current.last_run_at)}.`}
      </p>
      <div className="mt-2 flex items-center gap-2">
        <Button loading={save.isPending} onClick={() => save.mutate({ interval_hours: hours, window_from: from || null, window_to: to || null, enabled })}>
          Сохранить расписание
        </Button>
        {current && <Button variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}>Удалить расписание</Button>}
        {save.isSuccess && !save.isPending && <span className="text-xs text-text-secondary">сохранено</span>}
        {error && <span className="text-xs text-kind-1">{message(error, 'Не удалось сохранить расписание')}</span>}
      </div>
    </>
  )
}

function DnsForm({ dns, connections, onDone }: { dns: DnsServer | null; connections: AdConnectionRef[]; onDone: () => void }) {
  const save = useSaveDns()
  const [f, setF] = useState<FormState>(() => {
    const src = dns ?? EMPTY
    return { ...src, zones: src.zones.join('\n') }
  })
  const patch = (p: Partial<FormState>) => setF((v) => ({ ...v, ...p }))
  const body = (): DnsIn => ({
    title: f.title, mode: f.mode, server: f.server, ad_connection_id: f.ad_connection_id,
    zones: f.zones.split('\n').map((z) => z.trim()).filter(Boolean),
    forward: f.forward, reverse: f.reverse, zone_read: f.zone_read, rate_per_s: f.rate_per_s, timeout_ms: f.timeout_ms, enabled: f.enabled,
  })
  const check = (label: string, key: 'forward' | 'reverse' | 'zone_read' | 'enabled') => (
    <label className="flex items-center gap-2 text-xs text-text">
      <input type="checkbox" className="accent-primary" checked={f[key]} onChange={(e) => patch({ [key]: e.target.checked })} /> {label}
    </label>
  )

  return (
    <div className="mb-3 rounded border border-grid p-4">
      <div className="mb-3 text-sm font-semibold text-text">{dns ? `DNS-сервер ${dns.title || dns.server || `#${dns.id}`}` : 'Новый DNS-сервер'}</div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Название"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
        <Field label="Режим">
          <select className={FIELD} value={f.mode} onChange={(e) => patch({ mode: e.target.value as DnsIn['mode'], zone_read: e.target.value === 'ad' ? true : f.zone_read })}>
            <option value="direct">запросы к серверу</option>
            <option value="ad">зоны AD через LDAP</option>
          </select>
        </Field>
        {f.mode === 'direct' ? (
          <Field label="Сервер" hint="Имя или адрес; пусто — системный резолвер"><input className={FIELD} value={f.server} onChange={(e) => patch({ server: e.target.value })} spellCheck={false} placeholder="10.10.0.2" /></Field>
        ) : (
          <Field label="Подключение AD" hint="Профили — в модуле AD">
            <select className={FIELD} value={f.ad_connection_id ?? ''} onChange={(e) => patch({ ad_connection_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">не выбрано</option>
              {connections.map((c) => <option key={c.id} value={c.id}>{c.title ? `${c.title} — ${c.host}` : c.host}</option>)}
            </select>
          </Field>
        )}
        {f.mode === 'ad' && (
          <div className="sm:col-span-2 lg:col-span-3">
            <Field label="Зоны" hint="По одной на строку; читаются из раздела DomainDnsZones">
              <textarea className={FIELD} rows={3} value={f.zones} onChange={(e) => patch({ zones: e.target.value })} spellCheck={false} placeholder="corp.local" />
            </Field>
          </div>
        )}
        <Field label="Запросов в секунду" hint="1–1000"><input className={FIELD} type="number" min={1} max={1000} value={shown(f.rate_per_s)} onChange={(e) => patch({ rate_per_s: numberOrEmpty(e.target.value) })} /></Field>
        <Field label="Таймаут, мс" hint="100–30000"><input className={FIELD} type="number" min={100} max={30000} step={100} value={shown(f.timeout_ms)} onChange={(e) => patch({ timeout_ms: numberOrEmpty(e.target.value) })} /></Field>
      </div>
      <div className="mt-3 flex flex-wrap gap-4">
        {f.mode === 'direct' ? (
          <>
            {check('Прямые запросы (A/AAAA по известным именам)', 'forward')}
            {check('Обратные запросы (PTR по известным адресам)', 'reverse')}
          </>
        ) : (
          check('Читать зоны', 'zone_read')
        )}
        {check('Включён', 'enabled')}
      </div>

      {dns ? <ScheduleBlock dns={dns} /> : <p className="mt-3 text-xs text-text-secondary">Расписание задаётся после сохранения.</p>}

      <div className="mt-4 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} onClick={() => save.mutate({ id: dns?.id, body: body() }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onDone}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{message(save.error, 'Не удалось сохранить')}</span>}
      </div>
    </div>
  )
}

/** DNS-серверы: прямые и обратные запросы обновляют IP и имена активов, зоны AD дают записи без живых хостов. */
export function DnsSection() {
  const { write } = useCan()
  const servers = useDnsServers()
  const connections = useAdConnections()
  const remove = useDeleteDns()
  // undefined — форма закрыта, null — новый сервер.
  const [editing, setEditing] = useState<DnsServer | null | undefined>(undefined)
  const conns = connections.data ?? []

  return (
    <Section title="DNS" about="Запросы к серверу: A/AAAA по известным именам обновляют IP активов (устаревшие адреса в VM и антивирусе подсвечиваются), PTR по известным адресам даёт имена хостам из скана. Зоны AD читаются через подключение AD с его паузами между запросами: запись без живого хоста видна как расхождение.">
      {servers.isLoading && <Spinner />}
      {servers.isError && <ErrorState message={message(servers.error, 'Не удалось загрузить DNS-серверы')} onRetry={() => servers.refetch()} />}
      {editing !== undefined && <DnsForm key={editing?.id ?? 'new'} dns={editing} connections={conns} onDone={() => setEditing(undefined)} />}
      {servers.data && servers.data.length > 0 && (
        <table className="mb-3 w-full text-xs">
          <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
            <tr>
              <th className="py-1.5 pr-3 text-left">Название</th>
              <th className="py-1.5 pr-3 text-left">Что делает</th>
              <th className="py-1.5 pr-3 text-left">Последний запуск</th>
              <th className="py-1.5 pr-3 text-left">Расписание</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {servers.data.map((d) => (
              <tr key={d.id} className="border-t border-grid align-top">
                <td className="py-2 pr-3 text-text">{d.title || '—'}{!d.enabled && <span className="ml-1 text-text-secondary">· выключен</span>}</td>
                <td className="py-2 pr-3 text-text-secondary">{whatText(d, conns)}</td>
                <td className="py-2 pr-3 text-text-secondary">{when(d.last_run_at)}</td>
                <td className="py-2 pr-3 text-text-secondary">{scheduleText(d.schedule)}</td>
                <td className="py-2">
                  {write && (
                    <div className="flex items-start justify-end gap-1 whitespace-nowrap">
                      <RunButton dns={d} />
                      <Button variant="ghost" onClick={() => setEditing(d)}>изменить</Button>
                      <Button variant="ghost" loading={remove.isPending && remove.variables === d.id} onClick={() => remove.mutate(d.id)} aria-label={`Удалить DNS-сервер ${d.title || d.id}`}>
                        <Trash2 size={13} aria-hidden />
                      </Button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {servers.data?.length === 0 && editing === undefined && <p className="mb-3 text-xs text-text-secondary">DNS-серверов ещё нет.</p>}
      {remove.error && <p className="mb-2 text-xs text-kind-1">{message(remove.error, 'DNS-сервер не удалён')}</p>}
      {write && editing === undefined && <Button onClick={() => setEditing(null)}><Plus size={13} aria-hidden /> Добавить DNS-сервер</Button>}
    </Section>
  )
}
