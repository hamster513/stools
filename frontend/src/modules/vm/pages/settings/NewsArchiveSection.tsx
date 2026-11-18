import { useRef, useState } from 'react'
import { Download, Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { Section } from '@/platform/collector/ui'
import { useImportNews, useNewsImports, type NewsImport } from '../../api/newsArchive'

function date(value: string | null) { return value ? new Date(value).toLocaleString('ru-RU') : 'Нет данных' }

function ImportResult({ result }: { result: NewsImport }) {
  const failed = result.sources.filter((s) => s.status !== 'ok')
  return <div className="rounded border border-grid p-3 text-xs">
    <p className="mb-1 font-medium text-text">Последний успешный импорт</p>
    <p role="status">{result.duplicate ? 'Этот архив уже импортирован.' : `Добавлено: ${result.added}; обновлено: ${result.updated}; без изменений: ${result.unchanged}; устаревших пропущено: ${result.stale}.`}</p>
    {result.news_total !== undefined && <p className="mt-1 text-text-secondary">Новостей в VM: {result.news_total}.</p>}
    <p className="mt-1 text-text-secondary">Архив собран: {date(result.generated_at)}. Источников: {result.sources.length}.</p>
    <details className="mt-2">
      <summary className="cursor-pointer">Результаты источников{failed.length > 0 ? ` — с ошибками или ограничениями: ${failed.length}` : ''}</summary>
      <ul className="mt-2 max-h-48 space-y-2 overflow-y-auto">
        {result.sources.map((s) => <li key={s.id}>
          <span className="font-medium">{s.name}</span>: {s.items} материалов; {s.status === 'ok' ? 'загружен' : s.status === 'partial' ? 'частично' : 'не загружен'}
          {s.error && <span className="block text-kind-1">{s.error}</span>}
        </li>)}
      </ul>
    </details>
  </div>
}

export function NewsArchiveSection() {
  const admin = useCan('vm').admin
  const file = useRef<HTMLInputElement>(null)
  const [localError, setLocalError] = useState('')
  const history = useNewsImports(), upload = useImportNews()
  const result = upload.data ?? history.data?.items[0]
  return <Section id="news-archive" title="Архив новостей" about="Загрузка публикаций в VM из ZIP, собранного автономным скриптом на компьютере с интернетом.">
    <div className="space-y-4">
    <div className="space-y-2 text-xs">
      <a className="inline-flex items-center gap-1 text-primary hover:underline" href="/offline/stools-download-kit.zip" download><Download size={14} />Единый загрузчик — Linux и PowerShell</a>
      <p>Запустите на компьютере с интернетом (Python 3.11+), затем перенесите ZIP сюда:</p>
      <code className="block overflow-x-auto rounded bg-app-bg p-2">sh download-stools.sh --datasets news --mode updates --period 7d</code>
      <p className="text-text-secondary">Без параметров открывается меню: новости, SigmaHQ и Elastic выбираются отдельно. Доступны полный сбор и обновления за день, неделю или три календарных месяца. RSS отдаёт только доступное издателю окно; неполный сбор отмечается в отчёте.</p>
    </div>
    {admin && <div className="flex flex-wrap items-center gap-3">
      <input ref={file} type="file" accept=".zip,application/zip" className="hidden" aria-label="Архив новостей" onChange={(e) => {
        const selectedFile = e.target.files?.[0]; e.target.value = ''; setLocalError('')
        if (!selectedFile) return
        if (selectedFile.size > 64 * 1024 * 1024) { setLocalError('Архив превышает 64 МиБ'); return }
        upload.mutate(selectedFile)
      }} />
      <Button loading={upload.isPending} onClick={() => file.current?.click()}><Upload size={14} />Импортировать архив</Button>
      <span className="text-xs text-text-secondary">ZIP до 64 МиБ, распакованный items.jsonl до 128 МиБ. Повторная загрузка не создаёт копий.</span>
    </div>}
    {(localError || upload.isError) && <p role="alert" className="text-xs text-kind-1">{localError || upload.error?.message}</p>}
    {history.isError && <ErrorState message={history.error.message} onRetry={() => history.refetch()} />}
    {result && <ImportResult result={result} />}
    <Link to="/vm/trends?view=archive&period=all&from_archive=true" className="inline-block text-sm text-primary hover:underline">Открыть загруженные публикации в VM → Трендовые уязвимости</Link>
    <p className="text-xs text-text-secondary">Новости проходят извлечение CVE и обычную фильтрацию. Упоминание CVE само по себе не подтверждает эксплуатацию. Если в архиве есть правила Sigma/Elastic, они остаются справочными материалами Threat Hunting.</p>
    </div>
  </Section>
}
