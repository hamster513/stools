import { useEffect, useState } from 'react'
import { CheckCircle2, PlugZap, Save, ServerCog, XCircle } from 'lucide-react'
import { errorText } from '@/api/client'
import { useImportState, useSaveVmSettings, useStartVmImport, useTestVm } from '@/modules/vm/api/queries'
import type { SettingsView } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Field, FIELD, Section } from '@/platform/collector/ui'

/** Подключение к MaxPatrol VM: то, что сохранено, и запуск импорта. */
export function VmConnection({ settings }: { settings: SettingsView }) {
  // Аудитору настройки видны целиком, но поля закрыты, а кнопок нет: сервер
  // ответит 403. Импорт — работа аналитика; сохранение и проверка — администратора модуля.
  const { write, admin } = useCan()
  const save = useSaveVmSettings()
  const test = useTestVm()
  const start = useStartVmImport()
  const importState = useImportState()
  const c = settings.connection

  const [form, setForm] = useState({
    host: c.host,
    api_token: '',
    verify_tls: c.verify_tls,
    os_exclude: c.os_exclude.join(', '),
    pdql_extra: c.pdql_extra,
    limit: c.limit,
  })
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    setForm({ host: c.host, api_token: '', verify_tls: c.verify_tls, os_exclude: c.os_exclude.join(', '), pdql_extra: c.pdql_extra, limit: c.limit })
    setDirty(false)
  }, [c.host, c.verify_tls, c.os_exclude, c.pdql_extra, c.limit])

  function patch(p: Partial<typeof form>) {
    setDirty(true)
    setForm((f) => ({ ...f, ...p }))
  }

  function submit() {
    save.mutate(
      {
        connection: { ...form, os_exclude: form.os_exclude.split(',').map((s) => s.trim()).filter(Boolean), limit: Number(form.limit) || 0 },
        weights: settings.weights,
        threshold: settings.threshold,
      },
      // Токен после сохранения не держим в состоянии: иначе он уйдёт с любым следующим сохранением.
      { onSuccess: () => { setDirty(false); setForm((f) => ({ ...f, api_token: '' })) } },
    )
  }

  const active = importState.data?.active ?? null

  return (
    <Section
      id="connections"
      title="Подключение к MaxPatrol VM"
      about="Хосты, их ОС, критичность, зона и список CVE запрашиваются PDQL-запросом через API и приходят CSV-экспортом. Персональный API-токен MaxPatrol хранится в базе и наружу не показывается: пустое поле при сохранении оставляет прежнее значение."
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Хост" hint="Имя или адрес без https://">
          <input className={FIELD} value={form.host} onChange={(e) => patch({ host: e.target.value })} placeholder="vm.corp.local" spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="API-токен" hint={c.api_token_set ? 'задан; введите, чтобы заменить' : 'не задан. Персональный токен доступа MaxPatrol (pat_…); выпускается в консоли управления'}>
          <input className={FIELD} type="password" value={form.api_token} onChange={(e) => patch({ api_token: e.target.value })} autoComplete="new-password" spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="Исключить ОС" hint="Через запятую; попадают в filter(Host.OsName != …)">
          <input className={FIELD} value={form.os_exclude} onChange={(e) => patch({ os_exclude: e.target.value })} spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="Дополнение фильтра PDQL" hint="Добавляется через and, например Host.UF_Zone = 'DMZ'">
          <input className={FIELD} value={form.pdql_extra} onChange={(e) => patch({ pdql_extra: e.target.value })} spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="Лимит записей" hint="0 — без ограничения; для пробы удобно 1000">
          <input className={FIELD} type="number" min={0} value={form.limit} onChange={(e) => patch({ limit: Number(e.target.value) })} disabled={!admin} />
        </Field>
        <div className="flex flex-col justify-end pb-1">
          <label className="flex items-center gap-2 text-xs text-text">
            <input type="checkbox" checked={form.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} className="accent-primary" disabled={!admin} />
            <span>Проверять TLS-сертификат</span>
          </label>
          <span className="mt-1 text-[11px] text-text-secondary">Выключено — сертификат VM не проверяется, как в первой итерации; включите за доверенным CA.</span>
        </div>
      </div>

      {write && (
      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-grid pt-3">
        {admin && (
          <>
            <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty}>
              <Save size={13} aria-hidden /> Сохранить
            </Button>
            <Button onClick={() => test.mutate()} loading={test.isPending} disabled={!c.configured || dirty} title={dirty ? 'Сначала сохраните' : undefined}>
              <PlugZap size={13} aria-hidden /> Проверить подключение
            </Button>
          </>
        )}
        <Button onClick={() => start.mutate()} loading={start.isPending} disabled={!c.configured || dirty || active !== null}>
          <ServerCog size={13} aria-hidden /> Импортировать из VM
        </Button>
        {test.data && (
          <span className={cn('inline-flex items-center gap-1.5 text-xs', test.data.ok ? 'text-kind-accepted' : 'text-kind-1')}>
            {test.data.ok ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
            {test.data.message}
          </span>
        )}
        {(errorText(save.error, 'Не удалось сохранить') || errorText(test.error, 'Проверка не удалась') || errorText(start.error, 'Импорт не запущен')) && (
          <span className="text-xs text-kind-1">{errorText(save.error, 'Не удалось сохранить') ?? errorText(test.error, 'Проверка не удалась') ?? errorText(start.error, 'Импорт не запущен')}</span>
        )}
        {start.data && !start.error && <span className="text-xs text-text-secondary">задача #{start.data.job_id} запущена, прогресс — на экране «Задачи»</span>}
      </div>
      )}
    </Section>
  )
}
