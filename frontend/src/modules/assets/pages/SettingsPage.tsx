import { useState } from 'react'
import { ArrowRight, Plus, Save, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useAssetSettings, useCreateZone, useDeleteSyncSchedule, useDeleteZone, useSaveAssetSettings, useSaveSyncSchedule, useSyncSchedule, useSyncStatus, useZones,
} from '@/modules/assets/api/queries'
import type { AssetSettings, SyncSource } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'
import { ScheduleBlock } from './ScheduleBlock'
import { DnsSection } from './settings/DnsSection'
import { SyncButton } from './SyncButton'

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
  const { write } = useCan()
  const save = useSaveAssetSettings()
  const [form, setForm] = useState(saved)
  const dirty = form.inactive_days !== saved.inactive_days || form.stale_days !== saved.stale_days || form.sync_after_import !== saved.sync_after_import
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Устаревание, дней" hint="Значение источника старше актуального на столько дней — «данные устарели», моложе — «источники расходятся». 0 — любое отличие считается устаревшим.">
          <input type="number" min={0} className={FIELD} disabled={!write} value={shown(form.stale_days)} onChange={(e) => setForm({ ...form, stale_days: numberOrEmpty(e.target.value) })} />
        </Field>
        <Field label="Неактивность AD, дней" hint="Компьютер AD без входа и без других источников дольше — «неактивный компьютер AD»; с входом не старше — нужен агент антивируса.">
          <input type="number" min={1} className={FIELD} disabled={!write} value={shown(form.inactive_days)} onChange={(e) => setForm({ ...form, inactive_days: numberOrEmpty(e.target.value) })} />
        </Field>
      </div>
      <label className="mt-3 flex items-center gap-2 text-xs text-text">
        <input type="checkbox" disabled={!write} checked={form.sync_after_import} onChange={(e) => setForm({ ...form, sync_after_import: e.target.checked })} />
        Синхронизировать сразу после импорта в модулях VM, антивирус и AD
      </label>
      {write && (
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
    <Section title="Пороги и автосинхронизация" about="Пороги задают, когда отличие значения источника — устаревшие данные, а когда — расхождение, и какой компьютер AD считать неактивным. Меняются сразу для всего реестра: расхождения считаются при чтении.">
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
  const { write } = useCan()
  const schedule = useSyncSchedule()
  const save = useSaveSyncSchedule()
  const remove = useDeleteSyncSchedule()
  if (schedule.isError) return <p className="mt-3 text-xs text-kind-1">{message(schedule.error, 'Не удалось загрузить расписание')}</p>
  if (schedule.data === undefined) return null
  const current = schedule.data
  if (!write) {
    return (
      <p className="mt-3 text-xs text-text-secondary">
        Расписание: {current ? `раз в ${current.interval_hours} ч${current.window_from && current.window_to ? `, ${current.window_from}–${current.window_to} ${current.tz}` : ''}; следующий запуск ${current.enabled ? when(current.next_run_at) : 'выключено'}` : 'не задано'}.
      </p>
    )
  }
  return (
    <ScheduleBlock key={current?.id ?? 'none'} title="Расписание синхронизации" enableLabel="Синхронизировать по расписанию" current={current}
      note="Пока идёт другая синхронизация, запуск откладывается; запись результатов скана или DNS синхронизация дожидается."
      save={save} remove={remove} />
  )
}

/** Синхронизация с модулями: кнопка, время последней, что лежит по каждому источнику, расписание. */
function SyncSection() {
  const { write } = useCan()
  const status = useSyncStatus()
  const s = status.data
  return (
    <Section title="Синхронизация с модулями" about="Assets читает хосты VM, последние снапшоты антивируса и выгрузки AD и сопоставляет их с активами. Хосты, которых источник больше не отдаёт, помечаются пропавшими. Время источника — когда он видел хост: у VM это время импорта, у антивируса и AD — время сбора снапшота.">
      {status.isLoading && <Spinner />}
      {status.isError && <ErrorState message={message(status.error, 'Не удалось загрузить состояние синхронизации')} onRetry={() => status.refetch()} />}
      {s && (
        <>
          <p className="mb-3 text-xs text-text-secondary">
            {s.running_job_id ? <>Идёт синхронизация, <Link to="/assets/jobs" className="underline">задача #{s.running_job_id}</Link>.</> : <>Последняя синхронизация: <span className="text-text">{when(s.last_sync_at)}</span>.</>}
          </p>
          <table className="mb-3 w-full text-xs">
            <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
              <tr><th className="py-1.5 pr-3 text-left">Источник</th><th className="py-1.5 pr-3 text-right">Видит хостов</th><th className="py-1.5 pr-3 text-right">Пропали</th><th className="py-1.5 text-right">Данные от</th></tr>
            </thead>
            <tbody>
              {SYNC_SOURCES.map(({ source, title }) => {
                const row = s.sources[source]
                return (
                  <tr key={source} className="border-t border-grid">
                    <td className="py-2 pr-3 text-text">{title}</td>
                    <td className="py-2 pr-3 text-right font-mono tabular-nums text-text">{row?.live ?? 0}</td>
                    <td className="py-2 pr-3 text-right font-mono tabular-nums text-text-secondary">{row?.gone ?? 0}</td>
                    <td className="py-2 text-right text-text-secondary">{when(row?.seen_at ?? null)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
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

/** «Настройки и данные» модуля Assets: пороги, синхронизация с модулями, DNS-серверы, справочник зон. */
export function SettingsPage() {
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Справочники и настройки реестра активов.</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <ThresholdsSection />
        <SyncSection />
        <DnsSection />
        <ZonesSection />
      </div>
    </div>
  )
}
