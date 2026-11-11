import { useState } from 'react'
import { Download, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { useIntel, useIntelDetail, type IntelDetail } from '../../api/intel'

function date(value: string | null) { return value ? new Date(value).toLocaleString('ru-RU') : 'Дата публикации неизвестна' }

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
  const [query, setQuery] = useState(''), [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0), [selected, setSelected] = useState<string | null>(null)
  const list = useIntel(search, 'rule', offset), detail = useIntelDetail(selected)
  return <section id="materials" className="scroll-mt-6 space-y-4 rounded border border-grid bg-surface p-4">
    <div>
      <h2 className="text-sm font-semibold">Исходные правила Threat Hunting</h2>
      <p className="mt-1 text-xs text-text-secondary">Правила Sigma/Elastic для изучения и адаптации. Импорт не изменяет библиотеку и расписание запусков.</p>
    </div>
    <p className="text-xs text-text-secondary">Скрипт и загрузка ZIP перенесены в <Link to="/settings/vm#news-archive" className="text-primary hover:underline">настройки VM</Link>. Новости доступны в <Link to="/vm/trends?view=archive&period=all&from_archive=true" className="text-primary hover:underline">трендовых уязвимостях</Link>.</p>
    <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); setSearch(query.trim()); setOffset(0); setSelected(null) }}>
      <div className="min-w-40 flex-1"><Field label="Поиск материалов"><input className={FIELD} maxLength={200} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Название, техника ATT&CK, CVE или текст" /></Field></div>
      <Button type="submit">Найти</Button>
    </form>
    {list.isPending && <Spinner />}
    {list.isError && <ErrorState message={list.error.message} onRetry={() => list.refetch()} />}
    {list.data && <>
      <p className="text-xs text-text-secondary">Найдено: {list.data.total}</p>
      {list.data.total === 0 && <p className="text-sm">{search ? 'Нет материалов по выбранным условиям.' : 'Материалы ещё не загружены. Загрузите архив в настройках VM.'}</p>}
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
