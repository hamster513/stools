import { useEffect, useState } from 'react'
import { CheckCircle2, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { useSaveSecurity, useSecurity } from '@/platform/settings/api/queries'
import type { SecuritySettings } from '@/platform/settings/api/types'

/**
 * Срок сессии, таймаут бездействия и хранение журнала. Три числа, от
 * которых зависит, как быстро уходит забытая на чужом мониторе сессия и
 * как долго остаётся след действий.
 */
export function SecurityPage() {
  const security = useSecurity()
  const save = useSaveSecurity()
  // Читать раздел может и тот, кому платформа открыта на чтение; менять — её администратор.
  const admin = useCan().platform.admin

  const [form, setForm] = useState<SecuritySettings | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (security.data) setForm(security.data)
  }, [security.data])

  if (security.isError) {
    return (
      <div className="p-6">
        <ErrorState
          message={security.error?.message ?? 'Не удалось загрузить настройки безопасности'}
          onRetry={() => security.refetch()}
        />
      </div>
    )
  }
  if (!form) return <FullPageSpinner />

  function patch(change: Partial<SecuritySettings>) {
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
          <h1 className="text-base font-semibold text-text">Безопасность</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Правила для всех учёток сразу. Изменения действуют на сессии, которые начнутся после
            сохранения.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saved && !dirty && (
            <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
              <CheckCircle2 size={14} aria-hidden />
              сохранено
            </span>
          )}
          {admin ? (
            <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
              <Save size={14} aria-hidden />
              Сохранить
            </Button>
          ) : (
            <span className="text-xs text-text-secondary">только чтение</span>
          )}
        </div>
      </div>

      {save.isError && <p className="mb-4 text-xs text-kind-1">{save.error.message}</p>}

      <section className="grid max-w-xl gap-3 rounded border border-grid bg-surface p-4">
        <Field label="Срок сессии" hint="Часов от входа. По истечении нужно войти заново.">
          <input
            className={FIELD}
            type="number"
            min={1}
            max={720}
            value={form.session_ttl_hours}
            disabled={!admin}
            onChange={(e) => patch({ session_ttl_hours: Number(e.target.value) })}
          />
        </Field>
        <Field
          label="Таймаут бездействия"
          hint="Минут без запросов; 0 — без ограничения."
        >
          <input
            className={FIELD}
            type="number"
            min={0}
            max={1440}
            value={form.idle_timeout_minutes}
            disabled={!admin}
            onChange={(e) => patch({ idle_timeout_minutes: Number(e.target.value) })}
          />
        </Field>
        <Field
          label="Хранение журнала действий"
          hint="Дней; старые записи удаляются при входе любого пользователя."
        >
          <input
            className={FIELD}
            type="number"
            min={1}
            max={3650}
            value={form.audit_retention_days}
            disabled={!admin}
            onChange={(e) => patch({ audit_retention_days: Number(e.target.value) })}
          />
        </Field>
      </section>
    </div>
  )
}
