import { useState, type ReactNode } from 'react'
import { CheckCircle2, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { useFilterFolders, useSaveThSettings, useThSettings } from '../../api/queries'
import type { ThSettings, ThSettingsView } from '../../api/types'
import { apiMessage } from '../../format'

const SUBTITLE = 'mb-2 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

/**
 * Поля формы строками: пока человек печатает, число может быть неполным.
 * Включение ночного прогона, время старта и пауза между хантами здесь не правятся — они в «Планировщике».
 */
interface Draft {
  filter_folder_id: string
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

type NumberKey = Exclude<keyof Draft, 'retry_minutes' | 'filter_folder_id'>

/** Границы те же, что у сервера (`ThSettings`). */
const RANGES: Record<NumberKey, [number, number]> = {
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
    filter_folder_id: s.filter_folder_id ?? '',
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
  if (parseRetries(d.retry_minutes) === null) out.retry_minutes = 'от 1 до 20 чисел через запятую, каждое от 1 до 1440 минут'
  for (const key of Object.keys(RANGES) as NumberKey[]) {
    const [min, max] = RANGES[key]
    const v = d[key].trim()
    if (!/^\d+$/.test(v) || Number(v) < min || Number(v) > max) out[key] = max === Infinity ? `целое число, не меньше ${min}` : `целое число от ${min} до ${max}`
  }
  return out
}

/**
 * Тело PUT: сервер принимает настройки целиком, поэтому уходят все поля. Расписание (`nightly_enabled`,
 * `window_from`, `hunt_pause_s`) берётся из загруженных настроек без изменений: форма его не правит,
 * и сохранение здесь не должно его сбросить.
 */
function toSettings(d: Draft, base: ThSettings): ThSettings {
  return {
    filter_folder_id: d.filter_folder_id,
    nightly_enabled: base.nightly_enabled,
    window_from: base.window_from,
    hunt_pause_s: base.hunt_pause_s,
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
    <section id="hunting" className="rounded border border-grid bg-surface p-4" aria-label="Threat Hunting">
      <h2 className="mb-1 text-sm font-semibold text-text">Threat Hunting</h2>
      <p className="mb-4 text-xs text-text-secondary">
        Ночной прогон библиотеки хантов и большие ханты за длинный период. Подключение к MaxPatrol задаётся ниже, в блоке «Подключение к MaxPatrol».
        {' '}Время старта, интервал и очередь — в <Link to="/siem/hunting/scheduler" className="rounded text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">Планировщике</Link>.
      </p>
      {settings.isLoading && <div className="flex justify-center py-6"><Spinner /></div>}
      {settings.isError && <ErrorState message={apiMessage(settings.error, 'Не удалось загрузить настройки Threat Hunting')} onRetry={() => settings.refetch()} />}
      {settings.data && <HuntingForm view={settings.data} />}
    </section>
  )
}

function HuntingForm({ view }: { view: ThSettingsView }) {
  const { admin } = useCan()
  const save = useSaveThSettings()
  const folders = useFilterFolders(admin)
  const [draft, setDraft] = useState<Draft>(() => toDraft(plain(view)))
  const [saved, setSaved] = useState(false)

  const errors = errorsOf(draft)
  const valid = Object.keys(errors).length === 0
  // Несохранённое — по значениям, а не по тексту: «10,20» и «10, 20» одно и то же.
  const dirty = !valid || !sameSettings(toSettings(draft, plain(view)), plain(view))

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setSaved(false)
    setDraft((d) => ({ ...d, [key]: value }))
  }

  function submit() {
    if (!valid || !admin) return
    save.mutate(toSettings(draft, plain(view)), { onSuccess: () => setSaved(true) })
  }

  function number(key: NumberKey, label: string, hint: string, unit?: string) {
    return (
      <Row label={label} hint={hint} error={errors[key]}>
        <div className="flex items-center gap-2">
          <div className="w-28"><input value={draft[key]} onChange={(e) => set(key, e.target.value)} disabled={!admin} inputMode="numeric" aria-invalid={errors[key] ? true : undefined} className={cn(FIELD, 'font-mono')} /></div>
          {unit && <span className="text-xs text-text-secondary">{unit}</span>}
        </div>
      </Row>
    )
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit() }} className="grid gap-5">
      <div>
        <div className={SUBTITLE}>Фильтры MaxPatrol SIEM</div>
        <div className="grid gap-3">
          <Row label="Папка фильтров" hint="В этой папке создаются сохранённые фильтры для перехода из находок в SIEM. У подключения должны быть права на запись в папку." error={errors.filter_folder_id}>
            <div className="flex items-center gap-2">
              <select aria-label="Папка фильтров SIEM" value={draft.filter_folder_id} onChange={(e) => set('filter_folder_id', e.target.value)} disabled={!admin || folders.isFetching} className={FIELD}>
                <option value="">Не выбрана</option>
                {draft.filter_folder_id && !folders.data?.some((folder) => folder.id === draft.filter_folder_id) && <option value={draft.filter_folder_id}>Сохранённая папка ({draft.filter_folder_id})</option>}
                {folders.data?.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}
              </select>
              {admin && <Button type="button" loading={folders.isFetching} onClick={() => folders.refetch()}>Обновить</Button>}
            </div>
            {folders.isError && <p role="alert" className="mt-1 text-xs text-kind-1">{apiMessage(folders.error, 'Не удалось загрузить папки SIEM')}</p>}
          </Row>
          <p className="text-xs text-text-secondary">Из этой папки аналитик выбирает фильтры для запросов ханта. Создание и обновление фильтра в SIEM выполняется только по кнопке. Name — имя фильтра; Description хранится в STools.</p>
        </div>
      </div>
      <div>
        <div className={SUBTITLE}>Ночной прогон</div>
        <div className="grid gap-3">
          {number('request_timeout_s', 'Таймаут запроса', 'По умолчанию 300.', 'с')}
          <Row label="График повторов" hint="Минуты ожидания перед каждым повтором упавшего запроса через запятую; сколько чисел — столько повторов. По умолчанию 10, 20, 30, 30, 30, 30, 30." error={errors.retry_minutes}>
            <input value={draft.retry_minutes} onChange={(e) => set('retry_minutes', e.target.value)} disabled={!admin} aria-invalid={errors.retry_minutes ? true : undefined} className={cn(FIELD, 'font-mono')} />
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

      {admin && (
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
