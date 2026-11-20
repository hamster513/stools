import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Download, Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { useCan } from '@/lib/can'
import { STATUS } from '@/platform/syncQueue/types'
import { invalidateData } from '../../api/queries'
import { activeBatch, useArchiveBatches, useCancelArchiveBatch, useUploadArchives } from '../../api/archiveBatches'

const FILE_STATUS: Record<string, string> = {
  queued: 'В очереди', running: 'Обрабатывается', done: 'Загружен', partial: 'Загружен с ограничениями',
  failed: 'Ошибка', cancelled: 'Отменён',
}
const STAGE: Record<string, string> = { running: 'выполняется', done: 'готово', failed: 'ошибка' }

export function ArchiveBatchUpload() {
  const { admin } = useCan('vm')
  const history = useArchiveBatches(), upload = useUploadArchives(), cancel = useCancelArchiveBatch()
  const input = useRef<HTMLInputElement>(null)
  const [error, setError] = useState('')
  const qc = useQueryClient()
  const completed = history.data?.items.filter(batch => !activeBatch(batch.status))
    .map(batch => `${batch.run_id}:${batch.status}:${batch.finished_at}`).join('|') ?? ''
  useEffect(() => {
    if (!completed) return
    invalidateData(qc)
    for (const key of ['vm-jobs', 'vm-trends', 'vm-news-imports', 'th-intel']) {
      qc.invalidateQueries({ queryKey: [key] })
    }
  }, [completed, qc])

  function select(files: FileList | null) {
    if (!files?.length) return
    const selected = Array.from(files)
    setError('')
    upload.reset()
    if (selected.length > 64) { setError('Не более 64 архивов в одной пачке'); return }
    if (selected.some(file => !file.name.toLowerCase().endsWith('.zip'))) { setError('Выберите ZIP-архивы; отчёты и журналы загружать не нужно'); return }
    if (selected.some(file => file.size > 500 * 1024 ** 2)) { setError('Один архив не должен превышать 500 МиБ'); return }
    if (selected.reduce((size, file) => size + file.size, 0) > 2 * 1024 ** 3) { setError('Размер пачки не должен превышать 2 ГиБ'); return }
    upload.mutate(selected)
  }
  return <div className="mb-4 space-y-3 text-xs">
    <p><a className="inline-flex items-center gap-1 text-primary hover:underline" href="/offline/stools-download-kit.zip" download><Download size={14} />Единый загрузчик — Linux и PowerShell</a></p>
    <p>Выберите несколько ZIP из папки загрузчика: справочники, новости и правила. Сервер обработает их по очереди и один раз пересчитает уязвимости по итогам пачки.</p>
    <details>
      <summary className="cursor-pointer text-text-secondary">Как подготовить архивы</summary>
      <div className="mt-2 space-y-2 text-text-secondary">
        <p>Распакуйте комплект на компьютере с интернетом. Нужен Python 3.11+, для обновлений GHSA и правил — Git. Запуск без параметров открывает меню: полный сбор или обновления за день, неделю либо три календарных месяца.</p>
        <code className="block overflow-x-auto rounded bg-app-bg p-2">sh download-stools.sh --datasets nvd,ghsa,news --mode updates --period 7d --lang ru --quiet</code>
        <code className="block overflow-x-auto rounded bg-app-bg p-2">.\download-stools.ps1 -Datasets nvd,ghsa,news -Mode Updates -Period 7d -Lang ru -Quiet</code>
        <p>Проверьте давность справочников: импорт периода не подтверждает полноту всей базы. Файлы report.json и журналы переносить в STools не нужно.</p>
      </div>
    </details>
    {admin && <div className="flex flex-wrap items-center gap-3">
      <input ref={input} type="file" multiple accept=".zip,application/zip" className="hidden" aria-label="Архивы справочников, новостей и правил" onChange={event => { select(event.target.files); event.target.value = '' }} />
      <Button loading={upload.isPending} onClick={() => input.current?.click()}><Upload size={14} />Загрузить архивы</Button>
      <span className="text-text-secondary">До 64 ZIP и 2 ГиБ на пачку. Справочник — до 500 МиБ, новости и правила — до 64 МиБ на ZIP.</span>
    </div>}
    {upload.isPending ? <p role="status">Передаём {upload.variables?.length} архивов на сервер. Дождитесь подтверждения перед закрытием страницы.</p>
      : upload.isSuccess && <p role="status" className="text-risk-low">Пачка №{upload.data.run_id} принята в общую очередь. Страницу можно закрыть.</p>}
    {(error || upload.error || cancel.error) && <p role="alert" className="text-kind-1">{error || upload.error?.message || cancel.error?.message}</p>}
    {history.isError && <ErrorState message={history.error.message} onRetry={() => history.refetch()} />}
    {!!history.data?.items.length && <div className="space-y-2" aria-label="Пачки архивов">
      <p className="font-medium">Очередь и результаты импорта · последние 20 пачек</p>
      {history.data.items.map((batch, index) => <details key={batch.run_id} open={activeBatch(batch.status) || index === 0} className="rounded border border-grid p-3">
        <summary className="cursor-pointer font-medium">Пачка №{batch.run_id} · {STATUS[batch.status] ?? batch.status} · {batch.files.filter(file => ['done', 'partial'].includes(file.status)).length}/{batch.files.length}</summary>
        <div className="mt-2 space-y-2">
          <p className="text-text-secondary">{new Date(batch.created_at).toLocaleString('ru-RU')}{batch.message && ` · ${batch.message}`}</p>
          <ol className="max-h-72 space-y-2 overflow-y-auto">
            {batch.files.map((file, position) => <li key={position} className="rounded bg-app-bg p-2">
              <div className="flex flex-wrap justify-between gap-2"><span className="break-all">{position + 1}. {file.name}</span><span className={file.status === 'failed' ? 'text-kind-1' : file.status === 'partial' ? 'text-risk-medium' : 'text-text-secondary'}>{FILE_STATUS[file.status] ?? file.status}</span></div>
              {file.error && <p className="mt-1 text-kind-1">{file.error}</p>}
              {file.warning && <p className="mt-1 text-risk-medium">{file.warning}</p>}
              {file.duplicate ? <p className="mt-1 text-text-secondary">Архив уже был импортирован</p> : file.added !== undefined && <p className="mt-1 text-text-secondary">Материалов добавлено: {file.added}; обновлено: {file.updated ?? 0}</p>}
            </li>)}
          </ol>
          {batch.rebuild && STAGE[batch.rebuild] && <p>Пересчёт уязвимостей: {STAGE[batch.rebuild]}</p>}
          {batch.news_projection && STAGE[batch.news_projection] && <p>Обновление публикаций: {STAGE[batch.news_projection]}</p>}
          {admin && activeBatch(batch.status) && <Button variant="ghost" disabled={batch.cancel_requested || cancel.isPending} onClick={() => cancel.mutate(batch.run_id)}>{batch.cancel_requested ? 'Отмена запрошена' : 'Отменить оставшиеся архивы'}</Button>}
        </div>
      </details>)}
      <p className="text-text-secondary">Файлы обрабатываются в порядке выбора. Ошибка одного не мешает остальным. При отмене уже загруженные данные пересчитываются. Ошибочные архивы можно загрузить повторно.</p>
    </div>}
  </div>
}
