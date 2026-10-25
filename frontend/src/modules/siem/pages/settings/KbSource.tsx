import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, PlugZap, Save, ServerCog, XCircle } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useJobStatus, useKbConnection, useSaveKbConnection, useStartKbCollect, useTestKb } from '@/modules/siem/api/queries'
import type { JobStage, KbConnectionView } from '@/modules/siem/api/types'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { useRouter } from '@/lib/router'
import { Field, FIELD, Section } from '@/platform/collector/ui'

/**
 * Сбор правил из базы знаний MaxPatrol по API.
 *
 * Та же рамка, что у подключения к VM: одно подключение на инсталляцию,
 * секреты не показываются, проверка и сбор — по сохранённому. Ход сбора
 * показывается здесь же: три стадии до появления снапшота (подключение,
 * список объектов, экспорт) и три стадии обычного разбора.
 */
const STAGES: { key: JobStage; label: string }[] = [
  { key: 'connecting', label: 'Подключение' },
  { key: 'listing', label: 'Объекты' },
  { key: 'exporting', label: 'Экспорт' },
  { key: 'parsing', label: 'Разбор' },
  { key: 'analyzing', label: 'Анализ' },
  { key: 'persisting', label: 'Запись' },
]

export function KbSource() {
  const connection = useKbConnection()
  if (connection.isLoading) return <Spinner />
  if (connection.isError || !connection.data) {
    return (
      <Section id="kb" title="Подключение к MaxPatrol" about="Не удалось загрузить подключение.">
        <span className="text-xs text-kind-1">{connection.error instanceof ApiRequestError ? connection.error.message : 'ошибка'}</span>
      </Section>
    )
  }
  return <KbForm c={connection.data} />
}

function KbForm({ c }: { c: KbConnectionView }) {
  // Аудитору поля видны, но закрыты, а кнопок нет: сервер ответит 403.
  const { write } = useCan()
  const { navigate } = useRouter()
  const save = useSaveKbConnection()
  const test = useTestKb()
  const start = useStartKbCollect()
  const [jobId, setJobId] = useState<number | undefined>(undefined)
  const job = useJobStatus(jobId, { enabled: jobId !== undefined })

  const [form, setForm] = useState({ host: c.host, kb_port: c.kb_port, api_token: '', verify_tls: c.verify_tls })
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    setForm({ host: c.host, kb_port: c.kb_port, api_token: '', verify_tls: c.verify_tls })
    setDirty(false)
  }, [c.host, c.kb_port, c.verify_tls])

  useEffect(() => {
    if (job.data?.status === 'done' && job.data.snapshot_id !== null) {
      navigate(`/siem/snapshots/${job.data.snapshot_id}/rules`, { replace: true })
    }
  }, [job.data?.status, job.data?.snapshot_id, navigate])

  function patch(p: Partial<typeof form>) {
    // Старый результат проверки и старая ошибка описывали прежние настройки.
    test.reset()
    start.reset()
    setDirty(true)
    setForm((f) => ({ ...f, ...p }))
  }

  // До первого ответа опроса данных ещё нет, но сбор уже запущен: без isLoading кнопка на этот миг включается снова.
  const running = jobId !== undefined && (job.isLoading || job.data?.status === 'running')
  // Стадия «done» не входит в STAGES: на готовом сборе подсвечены все шесть.
  const stageIndex = job.data?.stage === 'done' ? STAGES.length : job.data ? STAGES.findIndex((s) => s.key === job.data?.stage) : -1
  const err = (e: unknown, fallback: string) => (e instanceof ApiRequestError ? e.message : e ? fallback : null)
  const errorMessage = err(save.error, 'Не удалось сохранить') ?? err(test.error, 'Проверка не удалась') ?? err(start.error, 'Сбор не запущен') ?? job.data?.error ?? null

  return (
    <Section
      id="kb"
      title="Подключение к MaxPatrol"
      about="Правила корреляции забираются из базы знаний MaxPatrol: наборы установки и статус установки каждого правила — из списка объектов, тела правил — экспортом в формате kb, который разбирается как загруженный файл. Только чтение. Персональный API-токен MaxPatrol хранится в базе и наружу не показывается: пустое поле при сохранении оставляет прежнее значение."
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Сервер MaxPatrol" hint="Имя или адрес Core без https://">
          <input className={FIELD} value={form.host} onChange={(e) => patch({ host: e.target.value })} placeholder="mp.corp.local" spellCheck={false} disabled={!write} />
        </Field>
        <Field label="Порт базы знаний" hint="Обычно 8091">
          <input className={FIELD} type="number" min={1} max={65535} value={form.kb_port} onChange={(e) => patch({ kb_port: Number(e.target.value) })} disabled={!write} />
        </Field>
        <Field label="API-токен" hint={c.api_token_set ? 'задан; введите, чтобы заменить' : 'не задан. Персональный токен доступа MaxPatrol (pat_…); выпускается в консоли управления; подойдёт тот же, что у подключения к MaxPatrol VM'}>
          <input className={FIELD} type="password" value={form.api_token} onChange={(e) => patch({ api_token: e.target.value })} autoComplete="new-password" spellCheck={false} disabled={!write} />
        </Field>
        <div className="flex flex-col justify-end pb-1">
          <label className="flex items-center gap-2 text-xs text-text">
            <input type="checkbox" checked={form.verify_tls} onChange={(e) => patch({ verify_tls: e.target.checked })} className="accent-primary" disabled={!write} />
            <span>Проверять TLS-сертификат</span>
          </label>
          <span className="mt-1 text-[11px] text-text-secondary">Выключено — сертификат MaxPatrol не проверяется; включите за доверенным CA.</span>
        </div>
      </div>

      {write && (
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-grid pt-3">
          <Button variant="primary" onClick={() => save.mutate(form, {
              // Токен после сохранения не держим в состоянии: подсказка снова скажет «задан».
              onSuccess: () => {
                setDirty(false)
                setForm((f) => ({ ...f, api_token: '' }))
              },
            })} loading={save.isPending} disabled={!dirty || !form.host}>
            <Save size={13} aria-hidden /> Сохранить
          </Button>
          <Button onClick={() => test.mutate()} loading={test.isPending} disabled={!c.configured || dirty} title={dirty ? 'Сначала сохраните' : undefined}>
            <PlugZap size={13} aria-hidden /> Проверить
          </Button>
          <Button onClick={() => start.mutate(undefined, { onSuccess: (res) => setJobId(res.job_id) })} loading={start.isPending} disabled={!c.configured || dirty || running}>
            <ServerCog size={13} aria-hidden /> Собрать правила
          </Button>
          {test.data && (
            <div className="flex flex-col gap-0.5">
              {[
                { label: 'База знаний', ok: test.data.ok, message: test.data.message },
                { label: 'События', ok: test.data.events_ok, message: test.data.events_message },
              ].map((r) => (
                <span key={r.label} className={cn('inline-flex items-center gap-1.5 text-xs', r.ok ? 'text-kind-accepted' : 'text-kind-1')}>
                  {r.ok ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
                  {r.label}: {r.message}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {jobId !== undefined && job.data && job.data.status !== 'failed' && (
        <div className="mt-4 max-w-md">
          <div className="flex justify-between text-xs text-text-secondary">
            {STAGES.map((s, i) => (
              <span key={s.key} className={cn(i <= stageIndex && 'text-text')}>
                {s.label}
              </span>
            ))}
          </div>
          <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-grid">
            <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${job.data.progress}%` }} />
          </div>
          <div className="mt-2 font-mono text-xs tabular-nums text-text-secondary">
            {job.data.status === 'done' ? 'готово, открываю снапшот…' : `${job.data.progress}%`}
          </div>
        </div>
      )}

      {errorMessage && (
        <div role="alert" className="mt-4 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />
          <span>{errorMessage}</span>
        </div>
      )}
    </Section>
  )
}
