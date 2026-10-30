import { useEffect, useState } from 'react'
import { CheckCircle2, PlugZap, RefreshCw, Save, XCircle } from 'lucide-react'
import { errorText } from '@/api/client'
import { useHarbor, useRemoveHarborSchedule, useSaveHarbor, useSaveHarborSchedule, useTestHarbor } from '@/modules/vm/api/queries'
import type { HarborView } from '@/modules/vm/api/types'
import { HarborSyncStatus } from '../images/HarborSyncStatus'
import { useHarborSync } from '../images/useHarborSync'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { ScheduleBlock } from '@/platform/collector/ScheduleBlock'
import { Field, FIELD, Section } from '@/platform/collector/ui'

const ABOUT =
  'Образы контейнеров из Harbor: список образов, их уязвимости по отчётам Trivy и риск по формуле VM. Подключение — робот-аккаунт Harbor с правом чтения; секрет робота хранится в базе и наружу не показывается: пустое поле при сохранении оставляет прежнее значение. Синхронизация читает указанные проекты (пусто — все, доступные роботу) и несколько последних тегов каждого репозитория.'

const when = (iso: string) => new Date(iso).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })
const splitList = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

/** Ответ API на смену адреса без нового секрета (`SECRETS_AGAIN`); по тексту, а не по состоянию формы: такой же 422 дают и другие поля. */
const SECRETS_AGAIN = 'при смене адреса секрет робота нужно ввести заново'
const isSecretsAgain = (message: string) => message === SECRETS_AGAIN || /секрет/i.test(message)

const validTags = (n: number) => Number.isInteger(n) && n >= 1 && n <= 100

/** Подключение к Harbor, проверка, синхронизация образов сейчас и по расписанию. */
export function HarborSection() {
  const harbor = useHarbor()
  const loadError = errorText(harbor.error, 'Не удалось загрузить настройки Harbor')
  return (
    <Section id="harbor" title="Harbor: образы контейнеров" about={ABOUT}>
      {harbor.isLoading && <Spinner />}
      {loadError && <ErrorState message={loadError} onRetry={() => harbor.refetch()} />}
      {harbor.data && <HarborForm h={harbor.data} />}
    </Section>
  )
}

function HarborForm({ h }: { h: HarborView }) {
  // Страницу настроек открывают аналитик и администратор модуля (аудитору она недоступна). У аналитика
  // поля закрыты: сервер ответил бы 403. Синхронизация — работа аналитика; сохранение, проверка и
  // расписание — администратора.
  const { write, admin } = useCan()
  const save = useSaveHarbor()
  const test = useTestHarbor()
  const harborSync = useHarborSync()
  const saveSchedule = useSaveHarborSchedule()
  const removeSchedule = useRemoveHarborSchedule()

  const projectsText = h.projects.join(', ')
  const [form, setForm] = useState({
    url: h.url, robot_name: h.robot_name, robot_secret: '', verify_tls: h.verify_tls, projects: projectsText, tags_per_repo: h.tags_per_repo,
  })
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    setForm({ url: h.url, robot_name: h.robot_name, robot_secret: '', verify_tls: h.verify_tls, projects: projectsText, tags_per_repo: h.tags_per_repo })
    setDirty(false)
  }, [h.url, h.robot_name, h.verify_tls, projectsText, h.tags_per_repo])

  function patch(p: Partial<typeof form>) {
    setDirty(true)
    // Результат проверки и прежняя ошибка сохранения относились к другим значениям.
    test.reset()
    save.reset()
    setForm((f) => ({ ...f, ...p }))
  }

  function submit() {
    save.mutate(
      { ...form, projects: splitList(form.projects) },
      // Секрет после сохранения не держим в состоянии: иначе он уйдёт с любым следующим сохранением.
      { onSuccess: () => { setDirty(false); test.reset(); setForm((f) => ({ ...f, robot_secret: '' })) } },
    )
  }

  // Требование ввести секрет заново — подсказка у поля секрета, остальные ошибки — у кнопок.
  const secretAgain = save.error && isSecretsAgain(save.error.message) ? save.error.message : null
  const rowError = (secretAgain ? null : errorText(save.error, 'Не удалось сохранить')) ?? errorText(test.error, 'Проверка не удалась')
  const tagsOk = validTags(form.tags_per_repo)
  const ls = h.last_sync

  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Адрес Harbor" hint="Без «/» в конце, например https://harbor.corp.local. Со стенда на этом компьютере Harbor виден как http://host.docker.internal:8082; укажите адрес так, как его видит сервер STools.">
          <input className={FIELD} value={form.url} onChange={(e) => patch({ url: e.target.value })} placeholder="https://harbor.corp.local" spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="Имя робота" hint="Например robot$stools">
          <input className={FIELD} value={form.robot_name} onChange={(e) => patch({ robot_name: e.target.value })} spellCheck={false} autoComplete="off" disabled={!admin} />
        </Field>
        <Field label="Секрет робота" hint={h.robot_secret_set ? undefined : 'не задан'}>
          <input
            className={FIELD} type="password" value={form.robot_secret} onChange={(e) => patch({ robot_secret: e.target.value })}
            placeholder={h.robot_secret_set ? 'задан; введите, чтобы заменить' : ''} autoComplete="new-password" spellCheck={false} disabled={!admin}
            aria-invalid={secretAgain ? true : undefined}
          />
          {secretAgain && <span className="mt-1 block text-xs text-kind-1" role="alert">{secretAgain}</span>}
        </Field>
        <Field label="Проекты" hint="Через запятую; пусто — все проекты, доступные роботу">
          <input className={FIELD} value={form.projects} onChange={(e) => patch({ projects: e.target.value })} placeholder="library, prod" spellCheck={false} disabled={!admin} />
        </Field>
        <Field label="Тегов на репозиторий" hint={tagsOk ? '1–100; берутся последние по времени загрузки' : undefined}>
          <input
            className={FIELD} type="number" min={1} max={100} value={Number.isNaN(form.tags_per_repo) ? '' : form.tags_per_repo}
            onChange={(e) => patch({ tags_per_repo: e.target.value === '' ? NaN : Number(e.target.value) })} disabled={!admin}
            aria-invalid={tagsOk ? undefined : true}
          />
          {!tagsOk && <span className="mt-1 block text-xs text-kind-1" role="alert">Введите целое число от 1 до 100</span>}
        </Field>
        <div className="flex flex-col justify-end pb-1">
          <label className="flex items-center gap-2 text-xs text-text">
            <input type="checkbox" checked={form.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} className="accent-primary" disabled={!admin} />
            <span>Проверять сертификат TLS</span>
          </label>
          <span className="mt-1 text-[11px] text-text-secondary">Выключите, если Harbor отдаёт самоподписанный сертификат; надёжнее добавить доверенный CA.</span>
        </div>
      </div>

      {write && (
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-grid pt-3">
          {admin && (
            <>
              <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!dirty || !tagsOk}>
                <Save size={13} aria-hidden /> Сохранить
              </Button>
              <Button onClick={() => test.mutate()} loading={test.isPending} disabled={!h.configured || dirty} title={dirty ? 'Сначала сохраните' : undefined}>
                <PlugZap size={13} aria-hidden /> Проверить подключение
              </Button>
            </>
          )}
          <Button onClick={harborSync.start} loading={harborSync.busy} disabled={!h.configured || dirty || harborSync.busy} title={dirty ? 'Сначала сохраните' : !h.configured ? 'Сначала задайте адрес, имя и секрет робота' : undefined}>
            <RefreshCw size={13} aria-hidden /> Синхронизировать сейчас
          </Button>
          {test.data && (
            <span className={cn('inline-flex items-center gap-1.5 text-xs', test.data.ok ? 'text-kind-accepted' : 'text-kind-1')}>
              {test.data.ok ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
              {test.data.message}
            </span>
          )}
          {rowError && <span className="text-xs text-kind-1">{rowError}</span>}
        </div>
      )}

      <HarborSyncStatus state={harborSync} className="mt-2" />

      <p className="mt-3 text-xs text-text-secondary">
        {ls ? (
          <>
            Последняя синхронизация: {when(ls.finished_at)}, образов: {ls.images}, пар образ–находка: {ls.cves}
            {ls.skipped_unscanned > 0 && `, без готового скана: ${ls.skipped_unscanned}`}
            {ls.errors.length > 0 && <span className="text-kind-1">; ошибки: {ls.errors.join(', ')}</span>}
          </>
        ) : 'Синхронизаций ещё не было.'}
      </p>

      {admin && (
        <ScheduleBlock
          title="Расписание синхронизации" enableLabel="Синхронизировать по расписанию"
          note="Пока подключение не настроено или идёт другая задача VM, запуск по расписанию пропускается."
          current={h.schedule} save={saveSchedule} remove={removeSchedule}
        />
      )}
    </>
  )
}
