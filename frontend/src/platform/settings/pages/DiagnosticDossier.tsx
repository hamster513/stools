import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD, Field } from '@/components/ui/Field'
import { DossierSections } from '@/platform/search/DossierSections'
import { EvidenceTable } from '@/platform/search/EvidenceTable'
import { ObjectIcon } from '@/platform/search/ObjectIcon'
import type { Entity, Kind, SearchInput } from '@/platform/search/api'
import { diagnosticApi, type DiagnosticImport } from '../api/diagnostics'
import { DiagnosticSummary } from './DiagnosticSummary'

const KINDS: Partial<Record<Kind, string>> = { auto: 'Любой объект', host: 'Хост', user: 'Пользователь', group: 'Группа', ip: 'IP-адрес', domain: 'Домен' }
export function DiagnosticDossier({ dataset }: { dataset: DiagnosticImport }) {
  const root: SearchInput = { query: dataset.root.title, kind: dataset.root.kind, entity_id: `${dataset.root.kind}:${dataset.root.id}` }
  const [input, setInput] = useState<SearchInput>(root)
  const [query, setQuery] = useState(root.query)
  const [kind, setKind] = useState<Kind>(root.kind)
  const [history, setHistory] = useState<SearchInput[]>([])
  const search = useQuery({
    queryKey: ['diagnostic-dossier', dataset.id, input],
    queryFn: () => diagnosticApi.search(dataset.id, input),
    gcTime: 0,
    retry: false,
  })
  const result = search.data
  const dossier = result?.dossier
  function show(next: SearchInput, remember = true) {
    if (remember) setHistory(items => [...items, input])
    setInput(next); setQuery(next.query); setKind(next.kind)
  }
  function open(entity: Entity) { show({ query: entity.title, kind: entity.kind, entity_id: entity.id }) }
  function submit(event: FormEvent) { event.preventDefault(); show({ query: query.trim(), kind }) }
  function back() { const previous = history.at(-1); if (previous) { setHistory(items => items.slice(0, -1)); show(previous, false) } }
  return <section className="space-y-4" aria-labelledby="diagnostic-dossier-title">
    <div className="rounded border border-grid bg-surface p-4 space-y-3">
      <h2 id="diagnostic-dossier-title" className="break-all text-lg font-medium">Пакет: {dataset.root.title}</h2>
      <p className="text-sm text-text-secondary">Досье и переходы по связям используют только сведения этого пакета. Рабочие данные и источники здесь недоступны.</p>
      <DiagnosticSummary summary={dataset.summary} />
    </div>
    <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
      <div className="min-w-48 flex-1"><Field label="Поиск внутри пакета"><input className={FIELD} value={query} onChange={e => setQuery(e.target.value)} required maxLength={255} autoComplete="off" placeholder="Псевдоним, группа или идентификатор из пакета" /></Field></div>
      <div className="w-48"><Field label="Тип объекта"><select className={FIELD} value={kind} onChange={e => setKind(e.target.value as Kind)}>{Object.entries(KINDS).map(([value, title]) => <option key={value} value={value}>{title}</option>)}</select></Field></div>
      <Button type="submit" disabled={!query.trim()} loading={search.isFetching}>Найти в пакете</Button>
    </form>
    <div className="flex flex-wrap gap-2"><Button onClick={back} disabled={!history.length || search.isFetching}>Назад к досье</Button><Button onClick={() => show(root)} disabled={search.isFetching}>Исходный объект</Button></div>
    {search.isFetching && <p role="status" className="text-sm text-text-secondary">Собираем досье из сведений пакета…</p>}
    {search.isError && <div role="alert" className="text-sm text-kind-1">{errorText(search.error, 'Не удалось открыть досье в пакете.')} <Button onClick={() => void search.refetch()}>Повторить</Button></div>}
    {!search.isFetching && !search.isError && result && <>
      {result.notes.map((note, index) => <p key={index} className="text-sm text-text-secondary">{note}</p>)}
      {!dossier && result.matches.length > 0 && <section className="space-y-2"><h3 className="font-medium">Выберите объект</h3>{result.matches.map(entity => <button key={entity.id} type="button" className="flex min-h-12 w-full items-center gap-3 rounded border border-grid p-3 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" onClick={() => open(entity)}><ObjectIcon kind={entity.kind} /><span className="break-all"><span className="font-medium text-primary">{entity.title}</span>{entity.domain && <span className="ml-2 text-sm text-text-secondary">{entity.domain}</span>}</span></button>)}</section>}
      {dossier && <>
        <div className="border-y border-grid py-4"><h3 className="flex items-center gap-2 break-all text-lg font-medium"><ObjectIcon kind={dossier.entity.kind} />{dossier.entity.title}</h3>
          <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-sm">{[...(dossier.entity.domain ? [{ label: 'Домен', value: dossier.entity.domain }] : []), ...dossier.entity.facts].map((fact, index) => <div key={index}><dt className="inline text-text-secondary">{fact.label}: </dt><dd className="inline break-all">{fact.value}</dd></div>)}</dl>
        </div>
        <DossierSections key={`${dataset.id}:${dossier.entity.id}`} dossier={dossier} onOpen={open} showSourceLinks={false} />
      </>}
      {!dossier && result.groups.filter(group => group.items.length > 0).map(group => <section key={group.id} className="space-y-2"><h3 className="font-medium">{group.title}</h3><p className="text-sm text-text-secondary">{group.note}</p><EvidenceTable rows={group.items} onOpen={open} showSourceLinks={false} />{group.has_more && <p className="text-xs text-text-secondary">Показана часть совпадений. Уточните запрос внутри пакета.</p>}</section>)}
      {result.has_more && <p className="text-sm text-text-secondary">Показана часть результатов. Уточните имя или идентификатор.</p>}
      {!dossier && !result.matches.length && !result.groups.some(group => group.items.length) && <p role="status" className="text-sm text-text-secondary">В этом пакете совпадений нет. Пакет содержит ограниченный срез данных.</p>}
    </>}
  </section>
}
