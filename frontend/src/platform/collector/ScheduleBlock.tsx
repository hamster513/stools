import { useState } from 'react'
import type { UseMutationResult } from '@tanstack/react-query'
import { ApiRequestError } from '@/api/client'
import { Button } from '@/components/ui/Button'
import type { ScheduleIn, ScheduleView } from './types'
import { DAYS } from '@/platform/settings/scheduleText'
import { Field, FIELD } from './ui'

// Пустое числовое поле — NaN: уходит как null, и API отвечает русским текстом о границах.
const numberOrEmpty = (value: string) => (value === '' ? NaN : Number(value))
const shown = (value: number) => (Number.isNaN(value) ? '' : value)

/**
 * Расписание задачи модуля (скан сети, обновление DNS, синхронизация, сбор по подключению): интервал и окно.
 * Сохраняется отдельно от формы владельца — это своя запись планировщика. Начальные значения берутся из `current` при монтировании.
 */
export function ScheduleBlock({ title, enableLabel, note, current, save, remove }: {
  title: string
  enableLabel: string
  /** Чем запуск по расписанию может быть отклонён. */
  note: string
  current: ScheduleView | null
  save: UseMutationResult<ScheduleView, ApiRequestError, ScheduleIn>
  remove: UseMutationResult<void, ApiRequestError, void>
}) {
  const [weekly, setWeekly] = useState(!!current?.weekdays?.length)
  const [days, setDays] = useState<number[]>(current?.weekdays?.length ? current.weekdays : [0, 1, 2, 3, 4])
  const [time, setTime] = useState(current?.run_time ?? '03:00')
  const [hours, setHours] = useState<number>(current?.interval_hours ?? 24)
  const [from, setFrom] = useState(current?.window_from ?? '')
  const [to, setTo] = useState(current?.window_to ?? '')
  const [enabled, setEnabled] = useState(current?.enabled ?? true)
  const error = save.error ?? remove.error
  return (
    <>
      <div className="mt-4 mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <label className="mb-3 flex items-center gap-2 text-xs text-text"><input type="checkbox" className="accent-primary" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> {enableLabel}</label>
      <Field label="Периодичность"><select className={FIELD} value={weekly ? 'week' : 'interval'} onChange={(e) => setWeekly(e.target.value === 'week')}>
        <option value="interval">Через интервал</option><option value="week">По дням недели</option>
      </select></Field>
      {weekly ? <div className="my-3 grid gap-3 sm:grid-cols-2">
        <fieldset><legend className="mb-1 text-xs">Дни недели</legend><div className="flex flex-wrap gap-2">
          {DAYS.map((day, i) => <label key={day} className="text-xs"><input type="checkbox" checked={days.includes(i)}
            onChange={(e) => setDays(e.target.checked ? [...days, i] : days.filter((d) => d !== i))} /> {day}</label>)}
        </div></fieldset>
        <Field label="Время запуска"><input type="time" className={FIELD} value={time} onChange={(e) => setTime(e.target.value)} /></Field>
      </div> : <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Интервал, часов" hint="1–720"><input className={FIELD} type="number" min={1} max={720} value={shown(hours)} onChange={(e) => setHours(numberOrEmpty(e.target.value))} /></Field>
        <Field label="Окно с" hint="Пусто — без окна"><input className={FIELD} type="time" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="Окно по" hint="Конец окна не входит"><input className={FIELD} type="time" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
      </div>}
      <p className="mt-2 text-xs text-text-secondary">
        Часовой пояс сервера{current ? ` (${current.tz})` : ''}. {note}
      </p>
      <div className="mt-2 flex items-center gap-2">
        <Button loading={save.isPending} disabled={remove.isPending || (weekly ? !days.length || !time : !Number.isInteger(hours) || hours < 1 || hours > 720 || Boolean(from) !== Boolean(to))}
          onClick={() => save.mutate({ interval_hours: weekly ? 24 : hours, window_from: !weekly && from || null, window_to: !weekly && to || null,
            weekdays: weekly ? days : [], run_time: weekly ? time : null, enabled })}>
          Сохранить расписание
        </Button>
        {current && <Button variant="ghost" disabled={save.isPending} loading={remove.isPending} onClick={() => remove.mutate()}>Удалить расписание</Button>}
        {save.isSuccess && !save.isPending && <span className="text-xs text-text-secondary">сохранено</span>}
        {error && <span className="text-xs text-kind-1">{error instanceof ApiRequestError ? error.message : 'Не удалось сохранить расписание'}</span>}
      </div>
    </>
  )
}
