import { useEffect, useState } from 'react'
import { CheckCircle2, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { useFindingSettings, useSaveFindingSettings } from '@/platform/findings/queries'
import { STATUSES, STATUS_TITLES, type FindingSettings } from '@/platform/findings/types'

/**
 * Статусы находок — настройки платформы: какие статусы учитывать в
 * подсчётах модулей, предельный срок и кто может принимать риск. Видят все,
 * меняет администратор.
 */
export function FindingsSettingsPage() {
  const { admin } = useCan()
  const settings = useFindingSettings()
  const save = useSaveFindingSettings()

  const [form, setForm] = useState<FindingSettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (settings.data) setForm(settings.data)
  }, [settings.data])

  if (settings.isError) {
    return (
      <div className="p-6">
        <ErrorState
          message={settings.error?.message ?? 'Не удалось загрузить настройки статусов находок'}
          onRetry={() => settings.refetch()}
        />
      </div>
    )
  }
  if (!form) return <FullPageSpinner />

  function patch(change: Partial<FindingSettings>) {
    setDirty(true)
    setSaved(false)
    setForm((prev) => (prev ? { ...prev, ...change } : prev))
  }

  function submit() {
    if (!form) return
    save.mutate(form, {
      onSuccess: () => {
        setDirty(false)
        setSaved(true)
      },
    })
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Статусы находок</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Общие для всех модулей.{' '}
            {admin ? 'Изменения действуют сразу после сохранения.' : 'Изменять может только администратор.'}
          </p>
        </div>
        {admin && (
          <div className="flex items-center gap-2">
            {saved && !dirty && (
              <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                <CheckCircle2 size={14} aria-hidden />
                сохранено
              </span>
            )}
            <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
              <Save size={14} aria-hidden />
              Сохранить
            </Button>
          </div>
        )}
      </div>

      {save.isError && <p className="mb-4 text-xs text-kind-1">{save.error.message}</p>}

      <section className="mb-4 max-w-xl rounded border border-grid bg-surface p-4">
        <h2 className="mb-1 text-sm font-medium text-text">Учитывать в подсчётах</h2>
        <p className="mb-3 text-xs text-text-secondary">
          Находка со снятым статусом остаётся в списках и видна с этим статусом, но не входит в
          счётчики: обзоры модулей, слой ATT&CK, «требует внимания» у правил SIEM.
        </p>
        <div className="grid gap-1.5 sm:grid-cols-2">
          {STATUSES.map((s) => (
            <label key={s} className="flex items-center gap-2 text-sm text-text">
              <input
                type="checkbox"
                disabled={!admin}
                checked={form.counted[s] ?? false}
                onChange={(e) => patch({ counted: { ...form.counted, [s]: e.target.checked } })}
              />
              {STATUS_TITLES[s]}
            </label>
          ))}
        </div>
      </section>

      <section className="grid max-w-xl gap-3 rounded border border-grid bg-surface p-4">
        <h2 className="text-sm font-medium text-text">Принятие риска</h2>
        <Field
          label="Максимальный срок принятия риска, дней"
          hint="Пусто — не ограничен. Если задан, «Принят риск» требует дату окончания не дальше этого срока."
        >
          <input
            className={FIELD}
            type="number"
            min={1}
            max={3650}
            disabled={!admin}
            placeholder="не ограничен"
            value={form.risk_max_days ?? ''}
            onChange={(e) => patch({ risk_max_days: e.target.value === '' ? null : Number(e.target.value) })}
          />
        </Field>
        <Field label="Кто может принимать риск">
          <select
            className={FIELD}
            disabled={!admin}
            value={form.risk_accept_role}
            onChange={(e) => patch({ risk_accept_role: e.target.value as FindingSettings['risk_accept_role'] })}
          >
            <option value="analyst">аналитик и администратор</option>
            <option value="admin">только администратор</option>
          </select>
        </Field>
      </section>
    </div>
  )
}
