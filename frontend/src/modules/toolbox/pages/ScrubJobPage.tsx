import { ArrowLeft, Download, FileX, Trash2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link, useRouter } from '@/lib/router'
import { Section } from '@/platform/collector/ui'
import { downloadUrl, useCancelJob, useDeleteJob, useJobInfo, useScrubJob } from '../api/queries'
import { formatSize as size, JOB_KIND_LABELS, KIND_LABELS, KIND_ORDER, STAGE_LABELS, STATUS_CLASS, STATUS_LABELS, type JobInfo, type ScrubJob } from '../api/types'
import { FindingsPreview } from './FindingsPreview'
import { JobRun } from './JobRun'

const LINK_BUTTON =
  'inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm font-medium text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

function Progress({ job, canCancel, onCancel }: { job: ScrubJob; canCancel: boolean; onCancel: () => void }) {
  return (
    <Section title={job.kind === 'apply' ? 'Идёт очистка' : 'Идёт сканирование'} about="Страница обновляется сама; уходить с неё можно — задание идёт на сервере.">
      <div className="max-w-xl">
        <div className="mb-1 text-sm font-medium text-text">{STAGE_LABELS[job.stage] ?? job.stage}</div>
        {job.message && job.message !== STAGE_LABELS[job.stage] && <div className="mb-2 text-xs text-text-secondary">{job.message}</div>}
        <JobRun job={job} large />
        {canCancel && (
          <div className="mt-3">
            {job.cancel_requested ? <span className="text-xs text-text-secondary">отменяется…</span> : <Button variant="ghost" onClick={onCancel}><XCircle size={13} aria-hidden />Отменить</Button>}
          </div>
        )}
      </div>
    </Section>
  )
}

/** Итог применения: три файла и счётчики по категориям — без настоящих значений. */
function Result({ id, info, canDownload }: { id: number; info: JobInfo; canDownload: boolean }) {
  const found = info.stats.findings ?? {}
  const replaced = info.stats.replaced ?? {}
  const kinds = [...KIND_ORDER, ...Object.keys({ ...found, ...replaced }).filter((k) => !KIND_ORDER.includes(k))]
    .filter((k) => found[k] || replaced[k])
  return (
    <Section title="Результат" about="Найдено — уникальных значений при сканировании; заменено — вхождений в результате. Псевдонимы этого задания записаны в таблицу соответствий; секреты — нет.">
      {info.files_deleted ? (
        <p className="mb-4 flex items-center gap-1.5 text-sm text-text-secondary"><FileX size={15} aria-hidden />Файлы удалены — скачать результат больше нельзя.</p>
      ) : canDownload ? (
        <div className="mb-4 flex flex-wrap gap-2">
          <a href={downloadUrl(id, 'result')} download className={LINK_BUTTON}><Download size={14} aria-hidden />{info.result_name || 'Результат'}</a>
          <a href={downloadUrl(id, 'report')} download className={LINK_BUTTON}><Download size={14} aria-hidden />Отчёт</a>
          <a href={downloadUrl(id, 'mapping')} download className={LINK_BUTTON}><Download size={14} aria-hidden />Соответствия (csv)</a>
        </div>
      ) : (
        <p className="mb-4 text-xs text-text-secondary">Скачивание — аналитику и администратору.</p>
      )}
      <table className="w-full max-w-lg text-xs">
        <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          <tr className="border-b border-grid"><th className="py-1.5 pr-3 text-left">Категория</th><th className="py-1.5 pr-3 text-right">Найдено</th><th className="py-1.5 text-right">Заменено</th></tr>
        </thead>
        <tbody>
          {kinds.map((k) => (
            <tr key={k} className="border-b border-grid">
              <td className="py-1.5 pr-3 text-text">{KIND_LABELS[k] ?? k}</td>
              <td className="py-1.5 pr-3 text-right font-mono tabular-nums text-text">{(found[k] ?? 0).toLocaleString('ru-RU')}</td>
              <td className="py-1.5 text-right font-mono tabular-nums text-text">{(replaced[k] ?? 0).toLocaleString('ru-RU')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {info.stats.files !== undefined && (
        <p className="mt-2 text-xs text-text-secondary">Файлов: {info.stats.files}{info.stats.skipped ? `, пропущено (не текст): ${info.stats.skipped}` : ''}</p>
      )}
    </Section>
  )
}

function stopTitle(job: ScrubJob): string {
  if (job.kind === 'apply') return job.status === 'cancelled' ? 'Очистка отменена' : 'Очистка не удалась'
  return job.status === 'cancelled' ? 'Сканирование отменено' : 'Сканирование не удалось'
}

/**
 * Карточка задания: ход скана → предпросмотр → ход применения → результат. Неудачное или отменённое
 * применение возвращает к предпросмотру: находки можно поправить и запустить очистку снова.
 */
export function ScrubJobPage({ id }: { id: number }) {
  const { write } = useCan()
  const job = useScrubJob(id)
  const info = useJobInfo(id)
  const cancel = useCancelJob()
  const del = useDeleteJob()
  const { navigate } = useRouter()

  if (job.isLoading || info.isLoading) return <FullPageSpinner />
  if (job.isError || info.isError || !job.data || !info.data) {
    const err = job.error ?? info.error
    return <div className="p-6"><ErrorState message={err?.message ?? 'Не удалось загрузить задание'} onRetry={() => { job.refetch(); info.refetch() }} /></div>
  }
  const j = job.data
  const i = info.data
  const running = j.status === 'running'
  const scanDone = j.kind === 'scan' && j.status === 'done'
  const applyStopped = j.kind === 'apply' && (j.status === 'failed' || j.status === 'cancelled')
  const editable = write && !i.files_deleted && (scanDone || applyStopped)

  function deleteJob() {
    if (window.confirm(`Удалить задание #${id} вместе с файлами и находками? Псевдонимы в таблице соответствий останутся.`)) del.mutate(id, { onSuccess: () => navigate('/toolbox') })
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <Link to="/toolbox" className="mb-3 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text"><ArrowLeft size={13} aria-hidden />Задания</Link>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-text">
            Задание <span className="font-mono">#{j.id}</span> · {JOB_KIND_LABELS[j.kind] ?? j.kind} · <span className={STATUS_CLASS[j.status]}>{STATUS_LABELS[j.status]}</span>
          </h2>
          <p className="text-xs text-text-secondary">
            {i.input_kind === 'text' ? 'вставленный текст' : <span className="font-mono text-text">{i.input_name}</span>}
            {' · '}{size(i.input_size)}
            {' · '}<span className="font-mono">{j.started_by}</span>, {new Date(j.started_at).toLocaleString('ru-RU')}
            {i.users_from_ad && ' · учётные записи из AD'}
            {i.files_deleted && ' · файлы удалены'}
          </p>
        </div>
        {write && !running && (
          <Button variant="danger" onClick={deleteJob} loading={del.isPending}><Trash2 size={14} aria-hidden />Удалить задание</Button>
        )}
      </div>

      <div className="space-y-4">
        {del.error && <ErrorState message={del.error.message} />}
        {cancel.error && <ErrorState message={cancel.error.message} />}
        {running && <Progress job={j} canCancel={write} onCancel={() => cancel.mutate(id)} />}
        {(j.status === 'failed' || j.status === 'cancelled') && (
          <ErrorState message={`${stopTitle(j)}${j.error ? `: ${j.error}` : ''}.${applyStopped && editable ? ' Поправьте находки и нажмите «Очистить» снова.' : ''}`} />
        )}
        {j.kind === 'apply' && j.status === 'done' && <Result id={id} info={i} canDownload={write} />}
        {(scanDone || applyStopped) && (
          <Section title="Находки" about={editable ? 'Отметьте, что заменять, поправьте псевдонимы, добавьте свои слова; сохраните и нажмите «Очистить».' : i.files_deleted ? 'Значения, контексты и секреты задания удалены из базы; остались счётчики по категориям.' : 'Только просмотр.'}>
            {i.files_deleted ? (
              <p className="flex items-center gap-1.5 text-sm text-text-secondary"><FileX size={15} aria-hidden />Находки удалены вместе с файлами.</p>
            ) : (
              <FindingsPreview id={id} readOnly={!editable} showContexts={write} />
            )}
          </Section>
        )}
      </div>
    </div>
  )
}
