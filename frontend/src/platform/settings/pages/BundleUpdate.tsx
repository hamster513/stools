import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, CloudDownload, Languages, Upload } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  useApplyPendingBundle,
  useAttackBundle,
  useAttackJob,
  useDiscardPendingBundle,
  useDownloadBundle,
  usePendingBundle,
  usePreviewBundle,
  useTranslateBundle,
  useTranslationGaps,
  useUploadBundle,
} from '@/modules/attack/api/queries'
import type { AttackBundleDiff } from '@/modules/attack/api/types'
import { Button } from '@/components/ui/Button'
import { ReplacementNotice } from '@/modules/attack/components/ReplacementNotice'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

function message(error: unknown, fallback: string): string {
  return error instanceof ApiRequestError ? error.message : fallback
}

/** Откуда взялась действующая матрица — словами. */
const SOURCE_WORDS: Record<string, string> = {
  builtin: 'из поставки',
  online: 'скачана с сайта MITRE',
}

function Count({ label, value, tone }: { label: string; value: number; tone?: 'warn' | 'bad' }) {
  return (
    <div className="rounded border border-grid px-2.5 py-1.5">
      <div className="text-[11px] text-text-secondary">{label}</div>
      <div
        className={cn(
          'font-mono text-sm',
          tone === 'bad' && value > 0 && 'text-kind-1',
          tone === 'warn' && value > 0 && 'text-kind-3',
          !tone && 'text-text',
        )}
      >
        {value}
      </div>
    </div>
  )
}

/** Счётчики разницы: одни и те же и для выбранного файла, и для скачанного. */
function DiffCounts({ diff }: { diff: AttackBundleDiff }) {
  return (
    <div className="mb-2 grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
      <Count label="Новых техник" value={diff.added.length} />
      <Count label="Изменились" value={diff.changed.length} tone="warn" />
      <Count label="Исчезли" value={diff.removed.length} tone="bad" />
      <Count label="Без перевода" value={diff.untranslated} tone="warn" />
      <Count label="Перевод устареет" value={diff.stale_translations} tone="bad" />
    </div>
  )
}

/**
 * Обновление матрицы ATT&CK.
 *
 * Матрицу можно скачать с сайта MITRE или загрузить файлом. Скачанное не
 * применяется само: человек сперва видит разницу с действующей матрицей и
 * подтверждает — молчаливая подмена оставила бы его гадать, откуда взялась
 * другая версия.
 *
 * Перевод живёт здесь же не случайно: та же модель и переводит то, чего в
 * матрице ещё нет по-русски.
 *
 * Состояние матрицы видят все; скачать, загрузить, применить и перевести —
 * только администратор: матрица одна на все модули.
 */
export function BundleUpdate() {
  const { admin } = useCan('attack')
  const state = useAttackBundle()
  const gaps = useTranslationGaps()
  const preview = usePreviewBundle()
  const upload = useUploadBundle()
  const translate = useTranslateBundle()
  const download = useDownloadBundle()
  const pending = usePendingBundle()
  const applyPending = useApplyPendingBundle()
  const discardPending = useDiscardPendingBundle()

  const [file, setFile] = useState<File | null>(null)
  const [diff, setDiff] = useState<AttackBundleDiff | null>(null)
  const [jobId, setJobId] = useState<number | undefined>()
  const [downloadJobId, setDownloadJobId] = useState<number | undefined>()
  const [outcome, setOutcome] = useState<{ failed: boolean; text: string } | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const job = useAttackJob(jobId)
  const translating = job.data?.status === 'running'
  const settled = jobId !== undefined && job.data && job.data.status !== 'running'

  const downloadJob = useAttackJob(downloadJobId)
  const downloading = downloadJob.data?.status === 'running'
  const downloadSettled =
    downloadJobId !== undefined && downloadJob.data && downloadJob.data.status !== 'running'

  useEffect(() => {
    if (!settled || !job.data) return
    const failed = job.data.status === 'failed'
    // Итог частичного перевода приходит в `message`: задание завершилось,
    // но не всё переведено — это не ошибка, а отчёт, и потерять его нельзя.
    setOutcome({
      failed,
      text: job.data.error || job.data.message || (failed ? 'перевод не удался' : 'перевод завершён'),
    })
    setJobId(undefined)
    void state.refetch()
    void gaps.refetch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settled])

  useEffect(() => {
    if (!downloadSettled || !downloadJob.data) return
    const failed = downloadJob.data.status === 'failed'
    // База не менялась ни при удаче, ни при ошибке: скачанное ждёт
    // подтверждения, и об этом надо сказать словами.
    setOutcome({
      failed,
      text:
        downloadJob.data.error ||
        (failed ? 'скачать не удалось' : 'матрица скачана — посмотрите разницу и подтвердите'),
    })
    setDownloadJobId(undefined)
    void pending.refetch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [downloadSettled])

  function choose(next: File | null) {
    setFile(next)
    setDiff(null)
    setOutcome(null)
    if (next) preview.mutate(next, { onSuccess: setDiff })
  }

  const s = state.data
  const waiting = pending.data ?? null

  return (
    <section className="rounded border border-grid bg-surface p-4">
      <h2 className="mb-1 text-sm font-semibold text-text">Матрица ATT&CK</h2>
      <p className="mb-4 text-xs text-text-secondary">
        Матрица вложена в поставку и работает без сети. Более новую можно скачать с сайта MITRE
        или загрузить файлом — обновление матрицы не трогает разметку: она привязана к
        идентификаторам техник, а не к версии. Разметка, подтверждённая на прежней версии,
        помечается на пересмотр.
      </p>

      <ReplacementNotice className="mb-4" />

      {state.isLoading && (
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <Spinner size={14} /> читаю состояние матрицы…
        </div>
      )}

      {s && (
        <>
          <div className="mb-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
            <Count label="Версия" value={Number(s.version) || 0} />
            <Count label="Техник" value={s.technique_count} />
            <Count label="Переведено" value={s.translated} />
            <Count label="Без перевода" value={s.missing} tone="warn" />
            <Count label="Перевод устарел" value={s.stale} tone="bad" />
          </div>
          <p className="mb-4 text-xs text-text-secondary">
            Версия <span className="font-mono text-text">{s.version}</span>,{' '}
            {SOURCE_WORDS[s.source] ?? `загружена ${s.loaded_by ?? 'вручную'}`}.
            {s.stale > 0 && (
              <>
                {' '}
                Устаревший перевод опаснее отсутствующего: отсутствие видно сразу, а устаревший
                выглядит нормальным русским текстом и просто описывает не ту технику.
              </>
            )}
          </p>
        </>
      )}

      {/* Загрузка с сайта MITRE. Скачанное кладётся рядом с действующей
          матрицей и ждёт подтверждения — до него в продукте ничего
          не меняется. */}
      {admin && (
        <div className="flex flex-wrap items-center gap-2 border-t border-grid pt-3">
          <Button
            loading={download.isPending || downloading}
            // Между ответом на запуск и первым опросом задания кнопка
            // осталась бы нажимаемой, а вторую загрузку сервер отвергнет.
            disabled={download.isPending || downloadJobId !== undefined}
            onClick={() =>
              download.mutate(undefined, {
                onSuccess: (r) => {
                  setOutcome(null)
                  setDownloadJobId(r.job_id)
                },
                onError: (e) => setOutcome({ failed: true, text: message(e, 'не удалось начать загрузку') }),
              })
            }
            title="Скачать enterprise-attack.json с сайта MITRE. Применится только после подтверждения"
          >
            <CloudDownload size={14} aria-hidden />
            {downloading ? 'Скачиваю…' : 'Скачать с сайта MITRE'}
          </Button>
          {downloading && (
            <span className="text-xs text-text-secondary">
              {downloadJob.data?.message || 'соединяюсь с сайтом MITRE…'}
            </span>
          )}
        </div>
      )}

      {waiting && (
        <div className="mt-3 rounded border border-grid bg-app-bg p-3">
          <div className="mb-2 text-xs text-text">
            Скачано: версия <span className="font-mono text-primary">{waiting.version ?? '—'}</span>,{' '}
            {new Date(waiting.downloaded_at).toLocaleString('ru')}. Действующая —{' '}
            <span className="font-mono">{waiting.diff.current_version ?? '—'}</span>.
          </div>
          <DiffCounts diff={waiting.diff} />
          {(waiting.diff.tactics_added.length > 0 || waiting.diff.tactics_removed.length > 0) && (
            <p className="mb-2 flex items-start gap-1.5 text-xs text-kind-3">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden />
              Меняется состав тактик — это меняет колонки матрицы. Появились:{' '}
              {waiting.diff.tactics_added.join(', ') || '—'}; исчезли:{' '}
              {waiting.diff.tactics_removed.join(', ') || '—'}.
            </p>
          )}
          <div className="flex items-center gap-2">
            {admin && (
              <>
                <Button
                  variant="primary"
                  loading={applyPending.isPending}
                  onClick={() =>
                    applyPending.mutate(undefined, {
                      onSuccess: () => {
                        setOutcome({ failed: false, text: 'матрица обновлена' })
                        void gaps.refetch()
                      },
                    })
                  }
                >
                  Применить
                </Button>
                <Button
                  variant="ghost"
                  loading={discardPending.isPending}
                  onClick={() => discardPending.mutate()}
                >
                  Отбросить
                </Button>
              </>
            )}
            <span className="ml-auto truncate font-mono text-[11px] text-text-secondary">
              {waiting.url}
            </span>
          </div>
          {applyPending.isError && (
            <p className="mt-2 text-xs text-kind-1">
              {message(applyPending.error, 'не удалось применить скачанное')}
            </p>
          )}
          {discardPending.isError && (
            <p className="mt-2 text-xs text-kind-1">
              {message(discardPending.error, 'не удалось отбросить скачанное')}
            </p>
          )}
        </div>
      )}

      {admin && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-grid pt-3">
          <input
            ref={inputRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={(e) => choose(e.target.files?.[0] ?? null)}
          />
          <Button onClick={() => inputRef.current?.click()} loading={preview.isPending}>
            <Upload size={14} aria-hidden />
            Выбрать enterprise-attack.json
          </Button>
          {file && <span className="font-mono text-xs text-text-secondary">{file.name}</span>}
          <Button
            variant="primary"
            className="ml-auto"
            disabled={!s || (s.missing === 0 && s.stale === 0) || translating}
            loading={translate.isPending || translating}
            onClick={() =>
              translate.mutate(undefined, {
                onSuccess: (r) => {
                  setOutcome(null)
                  setJobId(r.job_id)
                },
                onError: (e) => setOutcome({ failed: true, text: message(e, 'не удалось запустить') }),
              })
            }
            title="Перевести локальной моделью то, чего нет по-русски или чей исходник изменился"
          >
            <Languages size={14} aria-hidden />
            {translating ? 'Перевожу…' : 'Перевести недостающее'}
          </Button>
        </div>
      )}

      {preview.isError && (
        <p className="mt-2 text-xs text-kind-1">
          {message(preview.error, 'файл не разбирается как бандл ATT&CK')}
        </p>
      )}

      {diff && (
        <div className="mt-3 rounded border border-grid bg-app-bg p-3">
          <div className="mb-2 text-xs text-text">
            Версия <span className="font-mono">{diff.current_version ?? '—'}</span> →{' '}
            <span className="font-mono text-primary">{diff.version ?? '—'}</span>
          </div>
          <DiffCounts diff={diff} />
          {(diff.tactics_added.length > 0 || diff.tactics_removed.length > 0) && (
            <p className="mb-2 flex items-start gap-1.5 text-xs text-kind-3">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden />
              Меняется состав тактик — это меняет колонки матрицы. Появились:{' '}
              {diff.tactics_added.join(', ') || '—'}; исчезли:{' '}
              {diff.tactics_removed.join(', ') || '—'}.
            </p>
          )}
          {diff.removed.length > 0 && (
            <p className="mb-2 text-xs text-text-secondary">
              Разметка на исчезнувшие техники сохранится и будет помечена на пересмотр —
              стирать её из-за обновления нельзя.
            </p>
          )}
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              loading={upload.isPending}
              onClick={() => {
                if (!file) return
                upload.mutate(file, {
                  onSuccess: () => {
                    setDiff(null)
                    setFile(null)
                    setOutcome({ failed: false, text: 'матрица обновлена' })
                    void gaps.refetch()
                  },
                })
              }}
            >
              Принять эту матрицу
            </Button>
            <Button variant="ghost" onClick={() => choose(null)}>
              Отменить
            </Button>
          </div>
          {upload.isError && (
            <p className="mt-2 text-xs text-kind-1">
              {message(upload.error, 'не удалось принять бандл')}
            </p>
          )}
        </div>
      )}

      {outcome && (
        <p
          className={cn(
            'mt-3 flex items-center gap-1.5 text-xs',
            outcome.failed ? 'text-kind-1' : 'text-kind-accepted',
          )}
          role="status"
        >
          {outcome.failed ? (
            <AlertTriangle size={13} aria-hidden />
          ) : (
            <CheckCircle2 size={13} aria-hidden />
          )}
          {outcome.text}
        </p>
      )}

      {gaps.data && gaps.data.total > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-text-secondary hover:text-text">
            Что не переведено ({gaps.data.total})
          </summary>
          <ul className="mt-1.5 flex flex-col gap-1">
            {gaps.data.items.slice(0, 40).map((g) => (
              <li key={g.technique_id} className="flex items-baseline gap-2 text-xs">
                <span className="font-mono text-primary">{g.technique_id}</span>
                <span className="truncate text-text-secondary">{g.name}</span>
                <span className={cn('ml-auto', g.reason === 'stale' ? 'text-kind-1' : 'text-kind-3')}>
                  {g.reason === 'stale' ? 'перевод устарел' : 'нет перевода'}
                </span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}
