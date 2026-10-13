import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Play, Plus, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useCheckRacktables, useDeleteRacktables, useDeleteRacktablesSchedule, useJob, useRacktables, useRunRacktables, useSaveRacktables, useSaveRacktablesSchedule,
} from '@/modules/assets/api/queries'
import type { NetworkSchedule, Racktables, RacktablesIn } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { ScheduleBlock } from '@/platform/collector/ScheduleBlock'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const EMPTY: RacktablesIn = { title: '', url: '', username: '', password: '', verify_tls: true, rate_per_s: 10, timeout_ms: 30000, enabled: true }

const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number) => (Number.isNaN(value) ? '' : value)

const COLUMNS: ColumnDef[] = [
  { key: 'title', label: 'Название', width: 176 },
  { key: 'url', label: 'Адрес и учётка', width: 280, flex: true },
  { key: 'last_run', label: 'Последний проход', width: 144 },
  { key: 'schedule', label: 'Расписание', width: 200 },
]
const WRITE_COLUMNS: ColumnDef[] = [...COLUMNS, { key: 'actions', label: 'Действие', width: 260, resizable: false }]

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

/** «Проверить» — версия API сохранёнными учётными данными; «запустить» — проход с номером задачи и итогом. */
function Actions({ rt }: { rt: Racktables }) {
  const qc = useQueryClient()
  const check = useCheckRacktables()
  const run = useRunRacktables()
  const [jobId, setJobId] = useState<number | null>(null)
  const job = useJob(jobId)
  const status = job.data?.status
  useEffect(() => {
    if (status && status !== 'running') {
      for (const key of ['assets-racktables', 'assets-networks', 'assets-list', 'assets-asset', 'assets-overview']) qc.invalidateQueries({ queryKey: [key] })
    }
  }, [status, qc])
  const running = run.isPending || status === 'running' || (jobId !== null && !job.data)
  return (
    <div className="flex flex-col items-end gap-0.5">
      <div className="flex gap-1">
        <Button variant="ghost" loading={check.isPending} onClick={() => check.mutate(rt.id)}>проверить</Button>
        <Button variant="ghost" loading={running} disabled={running || !rt.enabled} title={rt.enabled ? undefined : 'Подключение выключено — включите его в форме'}
          onClick={() => run.mutate(rt.id, { onSuccess: (r) => setJobId(r.job_id) })}>
          <Play size={13} aria-hidden /> запустить
        </Button>
      </div>
      {check.isSuccess && <span className="text-[11px] text-text-secondary">API v{check.data.version}</span>}
      {check.error && <span className="max-w-64 text-right text-[11px] whitespace-normal text-kind-1">{check.error.message}</span>}
      {run.error && <span className="max-w-64 text-right text-[11px] whitespace-normal text-kind-1">{run.error.message}</span>}
      {jobId !== null && (
        <span className="max-w-64 text-right text-[11px] whitespace-normal text-text-secondary">
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

function RacktablesSchedule({ rt }: { rt: Racktables }) {
  return (
    <ScheduleBlock title="Расписание" enableLabel="Проходить по расписанию" current={rt.schedule}
      note="Выключенное подключение по расписанию не запускается."
      save={useSaveRacktablesSchedule(rt.id)} remove={useDeleteRacktablesSchedule(rt.id)} />
  )
}

function RacktablesForm({ rt, onDone }: { rt: Racktables | null; onDone: () => void }) {
  const save = useSaveRacktables()
  const [f, setF] = useState<RacktablesIn>(() => (rt ? { ...rt, password: '' } : EMPTY))
  const patch = (p: Partial<RacktablesIn>) => setF((v) => ({ ...v, ...p }))
  const check = (label: string, key: 'verify_tls' | 'enabled') => (
    <label className="flex items-center gap-2 text-xs text-text">
      <input type="checkbox" className="accent-primary" checked={f[key]} onChange={(e) => patch({ [key]: e.target.checked })} /> {label}
    </label>
  )
  return (
    <div className="mb-3 rounded border border-grid p-4">
      <div className="mb-3 text-sm font-semibold text-text">{rt ? `RackTables ${rt.title || rt.url}` : 'Новое подключение RackTables'}</div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Название"><input className={FIELD} value={f.title} onChange={(e) => patch({ title: e.target.value })} /></Field>
        <div className="sm:col-span-2">
          <Field label="Адрес json_api.php" hint="Например https://racktables.example.local/json_api.php"><input className={FIELD} value={f.url} onChange={(e) => patch({ url: e.target.value })} spellCheck={false} /></Field>
        </div>
        <Field label="Учётная запись" hint="Учётка AD с правом просмотра в RackTables"><input className={FIELD} value={f.username} onChange={(e) => patch({ username: e.target.value })} spellCheck={false} autoComplete="off" /></Field>
        <Field label="Пароль" hint={rt?.password_set ? 'Сохранён; пусто — оставить прежний' : 'Хранится зашифрованным'}>
          <input className={FIELD} type="password" value={f.password} onChange={(e) => patch({ password: e.target.value })} autoComplete="new-password" />
        </Field>
        <Field label="Запросов в секунду" hint="1–100; проход — список сетей плюс запрос на каждую сеть"><input className={FIELD} type="number" min={1} max={100} value={shown(f.rate_per_s)} onChange={(e) => patch({ rate_per_s: numberOrEmpty(e.target.value) })} /></Field>
        <Field label="Таймаут, мс" hint="1000–120000"><input className={FIELD} type="number" min={1000} max={120000} step={1000} value={shown(f.timeout_ms)} onChange={(e) => patch({ timeout_ms: numberOrEmpty(e.target.value) })} /></Field>
      </div>
      <div className="mt-3 flex flex-wrap gap-4">
        {check('Проверять сертификат TLS', 'verify_tls')}
        {check('Включено', 'enabled')}
      </div>

      {rt ? <RacktablesSchedule rt={rt} /> : <p className="mt-3 text-xs text-text-secondary">Расписание задаётся после сохранения.</p>}

      <div className="mt-4 flex items-center gap-2">
        <Button variant="primary" loading={save.isPending} disabled={!f.url.trim()} onClick={() => save.mutate({ id: rt?.id, body: f }, { onSuccess: onDone })}>Сохранить</Button>
        <Button onClick={onDone}>Отмена</Button>
        {save.error && <span className="text-xs text-kind-1">{message(save.error, 'Не удалось сохранить')}</span>}
      </div>
    </div>
  )
}

/** RackTables: сети с названиями и VLAN становятся сетями Assets, имена адресов — наблюдениями источника RT. */
export function RacktablesSection() {
  const { write } = useCan()
  const rows = useRacktables()
  const remove = useDeleteRacktables()
  // undefined — форма закрыта, null — новое подключение.
  const [editing, setEditing] = useState<Racktables | null | undefined>(undefined)
  const cols = useColumnWidths('assets-racktables-columns', write ? WRITE_COLUMNS : COLUMNS)

  return (
    <Section title="RackTables" about="Проход по JSON API RackTables: все сети (listCells) создаются или обновляются в Assets с названием, VLAN и тегами, затем по каждой сети читаются адреса (getIPAddressList). Адрес с именем становится наблюдением источника RT и сопоставляется с активами по имени и IP; адрес только с IP не переносится. Сеть, описанная вручную с тем же CIDR, остаётся вашей.">
      {rows.isLoading && <Spinner />}
      {rows.isError && <ErrorState message={message(rows.error, 'Не удалось загрузить подключения RackTables')} onRetry={() => rows.refetch()} />}
      {editing !== undefined && <RacktablesForm key={editing?.id ?? 'new'} rt={editing} onDone={() => setEditing(undefined)} />}
      {rows.data && rows.data.length > 0 && (
        <div className="mb-3 overflow-x-auto">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
              <tr>
                <ResizableHeader cols={cols} className="py-1.5 pr-3" content={{ actions: <span className="sr-only">Действие</span> }} />
              </tr>
            </thead>
            <tbody>
              {rows.data.map((d) => (
                <tr key={d.id} className="border-t border-grid align-top">
                  <td className="py-2 pr-3 break-words text-text">{d.title || '—'}{!d.enabled && <span className="ml-1 text-text-secondary">· выключено</span>}</td>
                  <td className="py-2 pr-3 break-all text-text-secondary">{d.url}{d.username && <span> · {d.username}</span>}{!d.password_set && <span className="text-kind-1"> · пароль не задан</span>}</td>
                  <td className="py-2 pr-3 text-text-secondary">{when(d.last_run_at)}</td>
                  <td className="py-2 pr-3 break-words text-text-secondary">{scheduleText(d.schedule)}</td>
                  {write && (
                    <td className="py-2">
                      <div className="flex items-start justify-end gap-1 whitespace-nowrap">
                        <Actions rt={d} />
                        <Button variant="ghost" onClick={() => setEditing(d)}>изменить</Button>
                        <Button variant="ghost" loading={remove.isPending && remove.variables === d.id} onClick={() => remove.mutate(d.id)} aria-label={`Удалить подключение RackTables ${d.title || d.id}`}>
                          <Trash2 size={13} aria-hidden />
                        </Button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows.data?.length === 0 && editing === undefined && <p className="mb-3 text-xs text-text-secondary">Подключений RackTables ещё нет.</p>}
      {remove.error && <p className="mb-2 text-xs text-kind-1">{message(remove.error, 'Подключение не удалено')}</p>}
      {write && editing === undefined && <Button onClick={() => setEditing(null)}><Plus size={13} aria-hidden /> Добавить подключение</Button>}
    </Section>
  )
}
