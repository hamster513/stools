import { useRef, useState } from 'react'
import { Download, ExternalLink, Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { useImportIntel, useIntel, useIntelDetail, useIntelImports, type IntelDetail, type IntelImport } from '../../api/intel'

function date(value: string | null) { return value ? new Date(value).toLocaleString('ru-RU') : 'Дата публикации неизвестна' }

function ImportResult({ result }: { result: IntelImport }) {
  const failed = result.sources.filter((s) => s.status !== 'ok')
  return <div className="rounded border border-grid p-3 text-xs">
    <p role="status">{result.duplicate ? 'Этот архив уже импортирован.' : `Добавлено: ${result.added}; обновлено: ${result.updated}; без изменений: ${result.unchanged}; устаревших пропущено: ${result.stale}.`}</p>
    <p className="mt-1 text-text-secondary">Архив собран: {date(result.generated_at)}. Источников: {result.sources.length}.</p>
    <details className="mt-2">
      <summary className="cursor-pointer">Результаты источников{failed.length > 0 ? ` — с ошибками или ограничениями: ${failed.length}` : ''}</summary>
      <ul className="mt-2 max-h-48 space-y-2 overflow-y-auto">
        {result.sources.map((s) => <li key={s.id}>
          <span className="font-medium">{s.name}</span>: {s.items} материалов; {s.status === 'ok' ? 'загружен' : s.status === 'partial' ? 'частично' : 'не загружен'}
          {s.error && <span className="block text-text-secondary">{s.error}</span>}
        </li>)}
      </ul>
    </details>
  </div>
}

function Material({ item, close }: { item: IntelDetail; close: () => void }) {
  function download() {
    const url = URL.createObjectURL(new Blob([item.text], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a'); link.href = url
    link.download = `${item.id}.${item.format === 'sigma' ? 'yml' : item.format === 'elastic' ? 'toml' : 'txt'}`
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <article aria-label="Материал Threat Hunting" className="space-y-3 rounded border border-primary/40 bg-app-bg p-4">
    <div className="flex items-start justify-between gap-3"><h3 className="text-sm font-semibold">{item.title}</h3><Button onClick={close}>Закрыть</Button></div>
    <p className="text-xs text-text-secondary">{item.source.name} · {item.format} · {date(item.published_at)}</p>
    {item.kind === 'news' && !item.full_text && <p className="text-xs text-text-secondary">Текст из RSS/Atom; он может быть сокращён издателем. Полная публикация доступна по ссылке.</p>}
    {item.kind === 'rule' && <p className="text-xs text-text-secondary">Исходное правило для изучения и адаптации. Оно не является готовым PDQL-запросом и не запускается в SIEM.</p>}
    <div className="flex flex-wrap items-center gap-3 text-xs">
      <a className="inline-flex items-center gap-1 text-primary hover:underline" href={item.url} target="_blank" rel="noreferrer">Открыть оригинал <ExternalLink size={12} /></a>
      <Button onClick={download}><Download size={12} />Скачать текст</Button>
    </div>
    {item.technique_ids.length > 0 && <p className="text-xs">Техники из материала: {item.technique_ids.join(', ')}</p>}
    <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words text-xs leading-relaxed">{item.text || 'Источник не передал текст публикации.'}</pre>
    {item.source.revision && <p className="break-all text-xs text-text-secondary">Версия репозитория: {item.source.revision}</p>}
    {(item.source.license_text || item.source.license_url) && <details className="text-xs">
      <summary className="cursor-pointer">Лицензия источника</summary>
      {item.source.license_url && <a className="mt-2 block text-primary hover:underline" href={item.source.license_url} target="_blank" rel="noreferrer">Лицензия в репозитории</a>}
      <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap">{item.source.license_text}</pre>
    </details>}
  </article>
}

export function IntelSection() {
  const admin = useCan('siem').admin
  const [query, setQuery] = useState(''), [search, setSearch] = useState('')
  const [kind, setKind] = useState<'' | 'news' | 'rule'>('')
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<string | null>(null)
  const file = useRef<HTMLInputElement>(null)
  const [localError, setLocalError] = useState('')
  const list = useIntel(search, kind, offset), detail = useIntelDetail(selected)
  const history = useIntelImports(), upload = useImportIntel()
  const result = upload.data ?? history.data?.items[0]
  return <section id="materials" className="scroll-mt-6 space-y-4 rounded border border-grid bg-surface p-4">
    <div>
      <h2 className="text-sm font-semibold">Материалы для Threat Hunting</h2>
      <p className="mt-1 text-xs text-text-secondary">Новости, отчёты и исходные правила из внешних источников. Они помогают готовить ханты; импорт не изменяет библиотеку и расписание запусков.</p>
    </div>
    <div className="space-y-2 text-xs">
      <a className="inline-flex items-center gap-1 text-primary hover:underline" href="/siem/download-intel.py" download><Download size={14} />Скачать скрипт сбора</a>
      <p>Запустите на компьютере с интернетом (Python 3.11+), затем перенесите ZIP сюда:</p>
      <code className="block overflow-x-auto rounded bg-app-bg p-2">python3 download-intel.py --output hunting.zip</code>
      <p className="text-text-secondary">По умолчанию — доступные публикации RSS за 30 дней и правила SigmaHQ/Elastic. --days 0 сохраняет всё доступное в лентах; --articles дополнительно загружает текст HTML-статей. Полная история интернета недоступна через RSS.</p>
    </div>
    {admin && <div className="flex flex-wrap items-center gap-3">
      <input ref={file} type="file" accept=".zip,application/zip" className="hidden" aria-label="Архив материалов Threat Hunting" onChange={(e) => {
        const selectedFile = e.target.files?.[0]; e.target.value = ''; setLocalError('')
        if (!selectedFile) return
        if (selectedFile.size > 64 * 1024 * 1024) { setLocalError('Архив превышает 64 МиБ'); return }
        upload.mutate(selectedFile, { onSuccess: () => { setOffset(0); setSelected(null) } })
      }} />
      <Button loading={upload.isPending} onClick={() => file.current?.click()}><Upload size={14} />Импортировать архив</Button>
      <span className="text-xs text-text-secondary">ZIP до 64 МиБ. Повторная загрузка не создаёт копии.</span>
    </div>}
    {(localError || upload.isError) && <p role="alert" className="text-xs text-kind-1">{localError || upload.error?.message}</p>}
    {history.isError && <ErrorState message={history.error.message} onRetry={() => history.refetch()} />}
    {result && <ImportResult result={result} />}
    <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); setSearch(query.trim()); setOffset(0); setSelected(null) }}>
      <div className="min-w-40 flex-1"><Field label="Поиск материалов"><input className={FIELD} maxLength={200} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Название, техника ATT&CK, CVE или текст" /></Field></div>
      <Field label="Вид материала"><select className={FIELD} value={kind} onChange={(e) => { setKind(e.target.value as typeof kind); setOffset(0); setSelected(null) }}><option value="">Все</option><option value="news">Новости и отчёты</option><option value="rule">Правила</option></select></Field>
      <Button type="submit">Найти</Button>
    </form>
    {list.isPending && <Spinner />}
    {list.isError && <ErrorState message={list.error.message} onRetry={() => list.refetch()} />}
    {list.data && <>
      <p className="text-xs text-text-secondary">Найдено: {list.data.total}</p>
      {list.data.total === 0 && <p className="text-sm">{search || kind ? 'Нет материалов по выбранным условиям.' : 'Материалы ещё не загружены. Соберите и импортируйте первый архив.'}</p>}
      <ul className="divide-y divide-grid">{list.data.items.map((row) => <li key={row.id} className="py-2">
        <button className="text-left text-sm text-primary hover:underline focus-visible:outline focus-visible:outline-focus-ring" onClick={() => setSelected(row.id)}>{row.title}</button>
        <p className="mt-1 text-xs text-text-secondary">{row.kind === 'news' ? 'Публикация' : 'Правило'} · {row.format} · {date(row.published_at)}</p>
      </li>)}</ul>
      {list.data.total > 20 && <div className="flex items-center gap-2"><Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 20))}>Назад</Button><span className="text-xs">{offset + 1}–{Math.min(offset + 20, list.data.total)}</span><Button disabled={offset + 20 >= list.data.total} onClick={() => setOffset(offset + 20)}>Далее</Button></div>}
    </>}
    {selected && detail.isPending && <Spinner />}
    {selected && detail.isError && <ErrorState message={detail.error.message} onRetry={() => detail.refetch()} />}
    {selected && detail.data && <Material item={detail.data} close={() => setSelected(null)} />}
  </section>
}
