import { useState } from 'react'
import { ArrowRight, Plus, Save, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useAssetSettings, useCreateZone, useDeleteSyncSchedule, useDeleteZone, usePatchZone, useSaveAssetSettings, useSaveSyncSchedule, useSyncSchedule, useSyncStatus, useZones,
} from '@/modules/assets/api/queries'
import { PLACEMENT_LABELS, PLACEMENTS, type AssetSettings, type Placement, type SyncSource, type ZoneIn } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { moduleTitle } from '@/platform/modules'
import { ScheduleBlock } from '@/platform/collector/ScheduleBlock'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { useScrollToAnchor } from '@/platform/settings/useScrollToAnchor'
import { DnsSection } from './settings/DnsSection'
import { RacktablesSection } from './settings/RacktablesSection'
import { SyncButton } from './SyncButton'

const SYNC_COLUMNS: ColumnDef[] = [
  { key: 'source', label: 'Источник', width: 160, flex: true },
  { key: 'live', label: 'Видит хостов', width: 112, align: 'right' },
  { key: 'gone', label: 'Пропали', width: 96, align: 'right' },
  { key: 'seen', label: 'Данные от', width: 144, align: 'right' },
]
const ZONE_COLUMNS: ColumnDef[] = [
  { key: 'name', label: 'Группа', width: 120 },
  { key: 'title', label: 'Название', width: 160 },
  { key: 'description', label: 'Описание', width: 200, flex: true },
  { key: 'placement', label: 'Расположение', width: 136 },
  { key: 'internet_facing', label: 'Из интернета', width: 104 },
  { key: 'confidential', label: 'Конфиденциальные', width: 128 },
  { key: 'networks', label: 'Сетей', width: 72, align: 'right' },
  { key: 'actions', label: 'Удалить', width: 48, resizable: false },
]

function message(error: unknown, fallback: string): string {
  return error instanceof ApiRequestError ? error.message : fallback
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : '—'
}

// Пустое числовое поле — NaN: уходит как null, и API отвечает русским текстом о границах.
const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number) => (Number.isNaN(value) ? '' : value)

/** Форма порогов: черновик живёт, пока не сохранён; без изменений кнопка выключена. */
function ThresholdsForm({ saved }: { saved: AssetSettings }) {
  const { admin } = useCan()
  const save = useSaveAssetSettings()
  const [form, setForm] = useState(saved)
  const dirty = form.inactive_days !== saved.inactive_days || form.stale_days !== saved.stale_days || form.sync_after_import !== saved.sync_after_import
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Устаревание, дней" hint="Значение источника старше актуального на столько дней — «данные устарели», моложе — «источники расходятся». 0 — любое отличие считается устаревшим.">
          <input type="number" min={0} className={FIELD} disabled={!admin} value={shown(form.stale_days)} onChange={(e) => setForm({ ...form, stale_days: numberOrEmpty(e.target.value) })} />
        </Field>
        <Field label="Неактивность AD, дней" hint="Компьютер AD без входа и без других источников дольше — «неактивный компьютер AD»; с входом не старше — нужен агент антивируса.">
          <input type="number" min={1} className={FIELD} disabled={!admin} value={shown(form.inactive_days)} onChange={(e) => setForm({ ...form, inactive_days: numberOrEmpty(e.target.value) })} />
        </Field>
      </div>
      <label className="mt-3 flex items-center gap-2 text-xs text-text">
        <input type="checkbox" disabled={!admin} checked={form.sync_after_import} onChange={(e) => setForm({ ...form, sync_after_import: e.target.checked })} />
        Синхронизировать сразу после импорта в модулях VM, антивирус и AD
      </label>
      {admin && (
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" loading={save.isPending} disabled={!dirty} onClick={() => save.mutate(form)}>
            <Save size={13} aria-hidden /> Сохранить
          </Button>
          {save.error && <span className="text-xs text-kind-1">{message(save.error, 'Настройки не сохранены')}</span>}
        </div>
      )}
    </>
  )
}

function ThresholdsSection() {
  const settings = useAssetSettings()
  return (
    <Section id="rules" title="Пороги и автосинхронизация" about="Пороги задают, когда отличие значения источника — устаревшие данные, а когда — расхождение, и какой компьютер AD считать неактивным. Меняются сразу для всего реестра: расхождения считаются при чтении.">
      {settings.isLoading && <Spinner />}
      {settings.isError && <ErrorState message={message(settings.error, 'Не удалось загрузить настройки')} onRetry={() => settings.refetch()} />}
      {settings.data && <ThresholdsForm key={JSON.stringify(settings.data)} saved={settings.data} />}
    </Section>
  )
}

const SYNC_SOURCES: { source: SyncSource; title: string }[] = [
  { source: 'vm', title: 'VM' },
  { source: 'ksc', title: 'Антивирус (KSC)' },
  { source: 'ad', title: 'Active Directory' },
]

/** Расписание синхронизации: форма у того, кто может писать, строка — у остальных. */
function SyncSchedule() {
  const { admin } = useCan()
  const schedule = useSyncSchedule()
  const save = useSaveSyncSchedule()
  const remove = useDeleteSyncSchedule()
  if (schedule.isError) return <p className="mt-3 text-xs text-kind-1">{message(schedule.error, 'Не удалось загрузить расписание')}</p>
  if (schedule.data === undefined) return null
  const current = schedule.data
  if (!admin) {
    return (
      <p className="mt-3 text-xs text-text-secondary">
        Расписание: {current ? `раз в ${current.interval_hours} ч${current.window_from && current.window_to ? `, ${current.window_from}–${current.window_to} ${current.tz}` : ''}; следующий запуск ${current.enabled ? when(current.next_run_at) : 'выключено'}` : 'не задано'}.
      </p>
    )
  }
  return (
    <ScheduleBlock key={current?.id ?? 'none'} title="Расписание синхронизации" enableLabel="Синхронизировать по расписанию" current={current}
      note="Пока идёт другая синхронизация, запуск откладывается; запись результатов DNS или RackTables синхронизация дожидается."
      save={save} remove={remove} />
  )
}

/** Синхронизация с модулями: кнопка, время последней, что лежит по каждому источнику, расписание. */
function SyncSection() {
  const { write } = useCan()
  const status = useSyncStatus()
  const s = status.data
  const cols = useColumnWidths('assets-sync-columns', SYNC_COLUMNS)
  return (
    <Section id="sync" title="Синхронизация с модулями" about="Assets читает хосты VM, последние снапшоты антивируса и выгрузки AD и сопоставляет их с активами. Хосты, которых источник больше не отдаёт, помечаются пропавшими. Время источника — когда он видел хост: у VM это время импорта, у антивируса и AD — время сбора снапшота.">
      {status.isLoading && <Spinner />}
      {status.isError && <ErrorState message={message(status.error, 'Не удалось загрузить состояние синхронизации')} onRetry={() => status.refetch()} />}
      {s && (
        <>
          <p className="mb-3 text-xs text-text-secondary">
            {s.running_job_id ? <>Идёт синхронизация, <Link to="/assets/jobs" className="underline">задача #{s.running_job_id}</Link>.</> : <>Последняя синхронизация: <span className="text-text">{when(s.last_sync_at)}</span>.</>}
          </p>
          <div className="mb-3 overflow-x-auto">
            <table className="w-full text-xs" style={cols.tableStyle}>
              <ColGroup cols={cols} />
              <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
                <tr><ResizableHeader cols={cols} className="py-1.5 pr-3" /></tr>
              </thead>
              <tbody>
                {SYNC_SOURCES.map(({ source, title }) => {
                  const row = s.sources[source]
                  return (
                    <tr key={source} className="border-t border-grid">
                      <td className="truncate py-2 pr-3 text-text" title={title}>{title}</td>
                      <td className="py-2 pr-3 text-right font-mono tabular-nums text-text">{row?.live ?? 0}</td>
                      <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{row?.gone ?? 0}</td>
                      <td className="py-2 pr-3 text-right text-text-secondary">{when(row?.seen_at ?? null)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
      <div className="flex items-center justify-between gap-3">
        <Link to="/assets/jobs" className="inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text">Задачи модуля <ArrowRight size={12} aria-hidden /></Link>
        {write && <SyncButton label="Обновить сейчас" />}
      </div>
      <SyncSchedule />
    </Section>
  )
}

const EMPTY_ZONE: ZoneIn = { name: '', title: '', description: '', placement: '', internet_facing: false, confidential: false }
const SELECT = 'rounded border border-border bg-app-bg px-1.5 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Группы сетей (в API — зоны) и их признаки: расположение, доступ из интернета, конфиденциальные данные. Группа сети
 * выбирается из справочника или назначается правилами; группу, заданную у сетей или в правилах, удалить нельзя.
 */
function ZonesSection() {
  const { admin } = useCan()
  const zones = useZones()
  const create = useCreateZone()
  const remove = useDeleteZone()
  const patchZone = usePatchZone()
  const [form, setForm] = useState<ZoneIn>(EMPTY_ZONE)
  const cols = useColumnWidths('assets-zones-columns', ZONE_COLUMNS)

  return (
    <Section id="zones" title="Группы сетей" about={<>Группа сети — DMZ, внутренняя, гостевая и т. п.; её признаки показывают, где хост, и по ним фильтруются сети и активы (в расчёт риска не идут). Группу сети выбирают в её карточке или назначают <Link to="/assets/networks?tab=rules" className="text-primary hover:underline">правила групп</Link>. Группу, которая задана у сетей или в правилах, удалить нельзя.</>}>
      {zones.isLoading && <Spinner />}
      {zones.isError && <ErrorState message={message(zones.error, 'Не удалось загрузить группы сетей')} onRetry={() => zones.refetch()} />}
      {zones.data && (
        <div className="mb-3 overflow-x-auto">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
              <tr><ResizableHeader cols={cols} className="py-1.5 pr-3" content={{ actions: <span className="sr-only">Удалить</span> }} /></tr>
            </thead>
            <tbody>
              {zones.data.map((z) => (
                <tr key={z.name} className="border-t border-grid align-top">
                  <td className="py-2 pr-3 font-mono break-all text-text">{z.name}</td>
                  <td className="py-2 pr-3 break-words text-text">{z.title || '—'}</td>
                  <td className="py-2 pr-3 break-words text-text-secondary">{z.description || '—'}</td>
                  <td className="py-1.5 pr-3">
                    {admin ? (
                      <select value={z.placement} onChange={(e) => patchZone.mutate({ name: z.name, body: { placement: e.target.value as Placement } })} aria-label={`Расположение группы ${z.name}`} className={SELECT}>
                        {PLACEMENTS.map((p) => <option key={p} value={p}>{PLACEMENT_LABELS[p]}</option>)}
                      </select>
                    ) : <span className="text-text">{PLACEMENT_LABELS[z.placement]}</span>}
                  </td>
                  <td className="py-2 pr-3">
                    <input type="checkbox" className="accent-primary" checked={z.internet_facing} disabled={!admin} onChange={(e) => patchZone.mutate({ name: z.name, body: { internet_facing: e.target.checked } })} aria-label={`Группа ${z.name} доступна из интернета`} />
                  </td>
                  <td className="py-2 pr-3">
                    <input type="checkbox" className="accent-primary" checked={z.confidential} disabled={!admin} onChange={(e) => patchZone.mutate({ name: z.name, body: { confidential: e.target.checked } })} aria-label={`В группе ${z.name} конфиденциальные данные`} />
                  </td>
                  <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{z.networks}</td>
                  <td className="py-2 text-right">
                    {admin && (
                      <Button variant="ghost" onClick={() => remove.mutate(z.name)} disabled={z.networks > 0} title={z.networks > 0 ? 'группа задана у сетей' : undefined} aria-label={`Удалить группу ${z.name}`}>
                        <Trash2 size={13} aria-hidden />
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {remove.error && <p className="mb-2 text-xs text-kind-1">{message(remove.error, 'Группа не удалена')}</p>}
      {patchZone.error && <p className="mb-2 text-xs text-kind-1">{message(patchZone.error, 'Признак группы не изменён')}</p>}
      {admin && (
        <div className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_2fr]">
          <Field label="Имя"><input className={FIELD} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Lab" /></Field>
          <Field label="Название"><input className={FIELD} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
          <Field label="Описание"><input className={FIELD} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <Field label="Расположение">
            <select className={FIELD} value={form.placement} onChange={(e) => setForm({ ...form, placement: e.target.value as Placement })}>
              {PLACEMENTS.map((p) => <option key={p} value={p}>{PLACEMENT_LABELS[p]}</option>)}
            </select>
          </Field>
          <div className="flex items-center gap-4 pb-2 text-xs text-text">
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-primary" checked={form.internet_facing} onChange={(e) => setForm({ ...form, internet_facing: e.target.checked })} /> из интернета</label>
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-primary" checked={form.confidential} onChange={(e) => setForm({ ...form, confidential: e.target.checked })} /> конфиденциальные</label>
          </div>
          <div className="pb-0.5">
            <Button loading={create.isPending} disabled={!form.name.trim()} onClick={() => create.mutate(form, { onSuccess: () => setForm(EMPTY_ZONE) })}>
              <Plus size={13} aria-hidden /> Добавить
            </Button>
          </div>
        </div>
      )}
      {create.error && <p className="mt-2 text-xs text-kind-1">{message(create.error, 'Группа не добавлена')}</p>}
    </Section>
  )
}

/** Настройки модуля Assets: пороги, синхронизация с модулями, DNS-серверы, RackTables, группы сетей. */
export function SettingsPage() {
  // Секции отрисованы сразу, данные они грузят каждая сама.
  useScrollToAnchor(true)
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">{moduleTitle('assets')}</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Справочники и настройки реестра активов.</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <ThresholdsSection />
        <SyncSection />
        <DnsSection />
        <RacktablesSection />
        <ZonesSection />
      </div>
    </div>
  )
}
