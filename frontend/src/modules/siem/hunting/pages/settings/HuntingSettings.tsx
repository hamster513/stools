import { useState, type ReactNode } from 'react'
import { CheckCircle2, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useSaveThSettings, useThSettings } from '../../api/queries'
import type { ThSettings, ThSettingsView } from '../../api/types'
import { apiMessage, ruStamp } from '../../format'

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/
const SUBTITLE = 'mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

/** Поля формы строками: пока человек печатает, число может быть неполным. */
interface Draft {
  nightly_enabled: boolean
  window_from: string
  hunt_pause_s: string
  request_timeout_s: string
  retry_minutes: string
  nightly_deadline_h: string
  default_limit: string
  hot_days: string
  slice_hours: string
  slice_pause_s: string
  default_depth_months: string
  retention_days: string
}

type NumberKey = Exclude<keyof Draft, 'nightly_enabled' | 'window_from' | 'retry_minutes'>

/** Границы те же, что у сервера (`ThSettings`). */
const RANGES: Record<NumberKey, [number, number]> = {
  hunt_pause_s: [1, Infinity],
  request_timeout_s: [1, Infinity],
  nightly_deadline_h: [1, Infinity],
  default_limit: [1, 100_000],
  hot_days: [1, Infinity],
  slice_hours: [1, Infinity],
  slice_pause_s: [1, Infinity],
  default_depth_months: [1, 36],
  retention_days: [1, Infinity],
}

function toDraft(s: ThSettings): Draft {
  return {
    nightly_enabled: s.nightly_enabled,
    window_from: s.window_from,
    hunt_pause_s: String(s.hunt_pause_s),
    request_timeout_s: String(s.request_timeout_s),
    retry_minutes: s.retry_minutes.join(', '),
    nightly_deadline_h: String(s.nightly_deadline_h),
    default_limit: String(s.default_limit),
    hot_days: String(s.hot_days),
    slice_hours: String(s.slice_hours),
    slice_pause_s: String(s.slice_pause_s),
    default_depth_months: String(s.default_depth_months),
    retention_days: String(s.retention_days),
  }
}

function parseRetries(text: string): number[] | null {
  const parts = text.split(/[,\s;]+/).filter(Boolean)
  if (parts.length < 1 || parts.length > 20) return null
  const values = parts.map((p) => (/^\d+$/.test(p) ? Number(p) : NaN))
  return values.every((v) => v >= 1 && v <= 1440) ? values : null
}

/** Ошибки по полям; пусто — форму можно сохранять. */
function errorsOf(d: Draft): Partial<Record<keyof Draft, string>> {
  const out: Partial<Record<keyof Draft, string>> = {}
  if (!HHMM.test(d.window_from)) out.window_from = 'время в формате ЧЧ:ММ'
  if (parseRetries(d.retry_minutes) === null) out.retry_minutes = 'от 1 до 20 чисел через запятую, каждое от 1 до 1440 минут'
  for (const key of Object.keys(RANGES) as NumberKey[]) {
    const [min, max] = RANGES[key]
    const v = d[key].trim()
    if (!/^\d+$/.test(v) || Number(v) < min || Number(v) > max) out[key] = max === Infinity ? `целое число, не меньше ${min}` : `целое число от ${min} до ${max}`
  }
  return out
}

/** Тело PUT: сервер принимает настройки целиком, поэтому уходят все поля, в том числе нетронутые. */
function toSettings(d: Draft): ThSettings {
  return {
    nightly_enabled: d.nightly_enabled,
    window_from: d.window_from,
    hunt_pause_s: Number(d.hunt_pause_s),
    request_timeout_s: Number(d.request_timeout_s),
    retry_minutes: parseRetries(d.retry_minutes) ?? [],
    nightly_deadline_h: Number(d.nightly_deadline_h),
    default_limit: Number(d.default_limit),
    hot_days: Number(d.hot_days),
    slice_hours: Number(d.slice_hours),
    slice_pause_s: Number(d.slice_pause_s),
    default_depth_months: Number(d.default_depth_months),
    retention_days: Number(d.retention_days),
  }
}

function plain(view: ThSettingsView): ThSettings {
  const settings: Partial<ThSettingsView> = { ...view }
  delete settings.schedule
  return settings as ThSettings
}

/** Сравнение по полям, а не по тексту JSON: порядок ключей в ответе сервера не важен. */
function sameSettings(a: ThSettings, b: ThSettings): boolean {
  return (Object.keys(a) as (keyof ThSettings)[]).every((k) => JSON.stringify(a[k]) === JSON.stringify(b[k]))
}

/** Блок «Threat Hunting» на странице настроек SIEM: загрузка и ошибка здесь, форма — в `HuntingForm`. */
export function HuntingSettings() {
  const settings = useThSettings()

  return (
    <section className="rounded border border-grid bg-surface p-4" aria-label="Threat Hunting">
      <h2 className="mb-1 text-sm font-semibold text-text">Threat Hunting</h2>
      <p className="mb-4 text-xs text-text-secondary">
        Ночной прогон библиотеки хантов и большие ханты за длинный период. Подключение к MaxPatrol задаётся ниже, в блоке «Подключение к MaxPatrol».
      </p>
      {settings.isLoading && <div className="flex justify-center py-6"><Spinner /></div>}
      {settings.isError && <ErrorState message={apiMessage(settings.error, 'Не удалось загрузить настройки Threat Hunting')} onRetry={() => settings.refetch()} />}
      {settings.data && <HuntingForm view={settings.data} />}
    </section>
  )
}

function HuntingForm({ view }: { view: ThSettingsView }) {
  const { write } = useCan()
  const save = useSaveThSettings()
  const [draft, setDraft] = useState<Draft>(() => toDraft(plain(view)))
  const [saved, setSaved] = useState(false)

  const errors = errorsOf(draft)
  const valid = Object.keys(errors).length === 0
  // Несохранённое — по значениям, а не по тексту: «10,20» и «10, 20» одно и то же.
  const dirty = !valid || !sameSettings(toSettings(draft), plain(view))

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setSaved(false)
    setDraft((d) => ({ ...d, [key]: value }))
  }

  function submit() {
    if (!valid || !write) return
    save.mutate(toSettings(draft), { onSuccess: () => setSaved(true) })
  }

  function number(key: NumberKey, label: string, hint: string, unit?: string) {
    return (
      <Row label={label} hint={hint} error={errors[key]}>
        <div className="flex items-center gap-2">
          <div className="w-28"><input value={draft[key]} onChange={(e) => set(key, e.target.value)} disabled={!write} inputMode="numeric" aria-invalid={errors[key] ? true : undefined} className={cn(FIELD, 'font-mono')} /></div>
          {unit && <span className="text-xs text-text-secondary">{unit}</span>}
        </div>
      </Row>
    )
  }

  const schedule = view.schedule

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit() }} className="grid gap-5">
      <div>
        <div className={SUBTITLE}>Ночной прогон</div>
        <div className="grid gap-3">
          <label className="flex items-center gap-2 text-xs text-text">
            <input type="checkbox" checked={draft.nightly_enabled} disabled={!write} onChange={(e) => set('nightly_enabled', e.target.checked)} className="accent-primary" />
            Ночной прогон включён
          </label>
          <Row label="Начинать в" hint="Время суток по часам сервера, по умолчанию 01:00. Прогон ищет предыдущие сутки." error={errors.window_from}>
            <div className="w-32"><input type="time" value={draft.window_from} onChange={(e) => set('window_from', e.target.value)} disabled={!write} className={cn(FIELD, 'font-mono')} /></div>
          </Row>
          <p className="text-xs text-text-secondary">
            {schedule?.next_run_at && view.nightly_enabled
              ? <>Следующий запуск: <span className="text-text">{ruStamp(schedule.next_run_at)}</span> (по времени вашего браузера; часовой пояс сервера — {schedule.tz})</>
              : 'Следующий запуск: не назначен — прогон выключен.'}
            {schedule?.last_run_at && <> Прошлый запуск: {ruStamp(schedule.last_run_at)}.</>}
            {' '}Расписание обновляется после сохранения.
          </p>
          {number('hunt_pause_s', 'Интервал между хантами', 'По умолчанию 30. Не нагружает MaxPatrol; запросы одного ханта идут подряд.', 'с')}
          {number('request_timeout_s', 'Таймаут запроса', 'По умолчанию 300.', 'с')}
          <Row label="График повторов" hint="Минуты ожидания перед каждым повтором упавшего запроса через запятую; сколько чисел — столько повторов. По умолчанию 10, 20, 30, 30, 30, 30, 30." error={errors.retry_minutes}>
            <input value={draft.retry_minutes} onChange={(e) => set('retry_minutes', e.target.value)} disabled={!write} aria-invalid={errors.retry_minutes ? true : undefined} className={cn(FIELD, 'font-mono')} />
          </Row>
          {number('nightly_deadline_h', 'Предел длительности ночи', 'По умолчанию 20. Незавершённый к этому часу прогон снимается, оставшиеся запросы помечаются пропущенными.', 'ч')}
          {number('default_limit', 'Предел событий по умолчанию', 'По умолчанию 5000. Для запроса без своего предела; достигнутый предел помечается в находке.', 'событий')}
        </div>
      </div>

      <div>
        <div className={SUBTITLE}>Большой хант</div>
        <div className="grid gap-3">
          {number('hot_days', 'Горячие сутки', 'По умолчанию 7. Свежий период, где события быстро читаются, идёт одним запросом.', 'сут')}
          {number('slice_hours', 'Размер куска', 'По умолчанию 3. Глубже горячих суток период режется на куски такой длины.', 'ч')}
          {number('slice_pause_s', 'Пауза между кусками', 'По умолчанию 5.', 'с')}
          {number('default_depth_months', 'Глубина по умолчанию', 'По умолчанию 3. Подставляется, если в форме большого ханта месяцы не указаны.', 'мес')}
        </div>
      </div>

      <div>
        <div className={SUBTITLE}>Хранение</div>
        {number('retention_days', 'Хранение событий', 'По умолчанию 180. Старше события находок удаляются, сами находки и решения по ним остаются.', 'сут')}
      </div>

      {write && (
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!valid || !dirty}>
            <Save size={14} aria-hidden /> Сохранить настройки Threat Hunting
          </Button>
          {saved && !dirty && <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted"><CheckCircle2 size={14} aria-hidden /> сохранено</span>}
          {!valid && <span className="text-xs text-text-secondary">исправьте отмеченные поля</span>}
          {save.isError && <span className="text-xs text-kind-1" role="alert">{apiMessage(save.error, 'Не удалось сохранить настройки Threat Hunting')}</span>}
        </div>
      )}
    </form>
  )
}

function Row({ label, hint, error, children }: { label: string; hint: string; error?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text">{label}</span>
      {children}
      <span className={cn('mt-1 block text-xs', error ? 'text-kind-1' : 'text-text-secondary')}>{error ?? hint}</span>
    </label>
  )
}
