import { ErrorState } from '@/components/ui/ErrorState'
import { Link } from '@/lib/router'
import { Section } from '@/platform/collector/ui'
import { useNewsImports, type NewsImport } from '../../api/newsArchive'

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
  const history = useNewsImports()
  const result = history.data?.items[0]
  return <Section id="news-archive" title="Архив новостей" about="Публикации из автономных ZIP. Новости и правила загружаются общей пачкой вместе со справочниками в блоке выше.">
    <div className="space-y-4">
    {history.isError && <ErrorState message={history.error.message} onRetry={() => history.refetch()} />}
    {result && <ImportResult result={result} />}
    <Link to="/vm/trends?view=archive&period=all&from_archive=true" className="inline-block text-sm text-primary hover:underline">Открыть загруженные публикации в VM → Трендовые уязвимости</Link>
    <p className="text-xs text-text-secondary">Новости проходят извлечение CVE и обычную фильтрацию. Упоминание CVE само по себе не подтверждает эксплуатацию. Если в архиве есть правила Sigma/Elastic, они остаются справочными материалами Threat Hunting.</p>
    </div>
  </Section>
}
