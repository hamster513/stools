import { useEffect, useMemo, useRef, useState } from 'react'
import { GitBranch, FileText, X } from 'lucide-react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Link } from '@/lib/router'
import { EvidenceTable } from '../EvidenceTable'
import type { Dossier, Entity, SearchResult } from '../api'
import { GraphCanvas } from './GraphCanvas'
import { buildGraph, connections, filterGraph, KIND_LABELS, MAX_EDGES, MAX_NODES, PAGE_SIZE, sources } from './model'

type Action = 'expand' | 'preview'
export function GraphWorkspace({ dossier }: { dossier: Dossier }) {
  const rootId = dossier.entity.id
  const [dossiers, setDossiers] = useState<Record<string, Dossier>>({ [rootId]: dossier })
  const [shown, setShown] = useState<Record<string, number>>({ [rootId]: PAGE_SIZE })
  const [selectedId, setSelected] = useState(rootId)
  const [hiddenKinds, setHiddenKinds] = useState<string[]>([])
  const [hiddenSources, setHiddenSources] = useState<string[]>([])
  const [preview, setPreview] = useState<string | null>(null)
  const [pending, setPending] = useState<string | null>(null)
  const [failure, setFailure] = useState<{ message: string; entity: Entity; action: Action } | null>(null)
  const alive = useRef(true), busy = useRef(false)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const graph = useMemo(() => buildGraph(rootId, dossiers, shown), [rootId, dossiers, shown])
  const sourceNames = useMemo(() => [...new Set(graph.edges.flatMap(e => e.evidence.flatMap(item => sources(item.source))))].sort(), [graph])
  const visible = useMemo(() => filterGraph(graph, new Set(Object.keys(KIND_LABELS).filter(k => !hiddenKinds.includes(k))), new Set(sourceNames.filter(s => !hiddenSources.includes(s)))), [graph, sourceNames, hiddenKinds, hiddenSources])
  const selected = visible.nodes.find(n => n.id === selectedId) ?? visible.nodes[0]
  const selectedDossier = selected ? dossiers[selected.id] : undefined
  const related = selected ? visible.edges.filter(e => e.from === selected.id || e.to === selected.id) : []
  const total = selectedDossier ? connections(selectedDossier).length : null
  const count = selected ? Math.min(shown[selected.id] ?? 0, total ?? 0) : 0
  async function load(entity: Entity, action: Action) {
    if (busy.current) return
    busy.current = true; setPending(entity.id); setFailure(null)
    try {
      let next = dossiers[entity.id]
      if (!next) {
        const result = await api.post<SearchResult>('/api/search', { query: entity.title.slice(0, 255) || entity.id, kind: entity.kind, entity_id: entity.id })
        if (!alive.current) return
        if (!result.dossier || result.dossier.entity.id !== entity.id) throw new Error('Объект больше не доступен в собранных данных или по вашим правам.')
        next = result.dossier
        setDossiers(cache => ({ ...cache, [entity.id]: next }))
      }
      if (action === 'preview') setPreview(entity.id)
      else setShown(current => ({ ...current, [entity.id]: (current[entity.id] ?? 0) + PAGE_SIZE }))
    } catch (error) {
      if (alive.current) setFailure({ message: error instanceof Error ? error.message : 'Не удалось загрузить связи.', entity, action })
    } finally {
      busy.current = false
      if (alive.current) setPending(null)
    }
  }
  const toggle = (items: string[], value: string) => items.includes(value) ? items.filter(i => i !== value) : [...items, value]
  const previewDossier = preview ? dossiers[preview] : null
  return <section aria-label="Рабочее поле графа" className="space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <p role="status">Узлы: {visible.nodes.length} / {graph.nodes.length} · Связи: {visible.edges.length} / {graph.edges.length}</p>
      <span className="text-xs text-text-secondary">Граф хранится до нового поиска или ухода со страницы</span>
    </div>
    <div className="space-y-2 rounded border border-grid p-3 text-xs">
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2"><legend className="mb-2 font-medium">Типы объектов</legend>{Object.entries(KIND_LABELS).map(([id, label]) => <label key={id} className="flex items-center gap-1.5"><input type="checkbox" checked={!hiddenKinds.includes(id)} onChange={() => setHiddenKinds(k => toggle(k, id))} className="accent-primary" />{label}</label>)}</fieldset>
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2"><legend className="mb-2 font-medium">Источники связей</legend>{sourceNames.length ? sourceNames.map(source => <label key={source} className="flex items-center gap-1.5"><input type="checkbox" checked={!hiddenSources.includes(source)} onChange={() => setHiddenSources(s => toggle(s, source))} className="accent-primary" />{source}</label>) : <span className="text-text-secondary">Нет раскрытых связей</span>}</fieldset>
      {(hiddenKinds.length > 0 || hiddenSources.length > 0) && <button className="text-primary hover:underline" onClick={() => { setHiddenKinds([]); setHiddenSources([]) }}>Сбросить фильтры</button>}
    </div>
    {graph.limited && <p role="status" className="text-sm text-text-secondary">Достигнут предел графа: {MAX_NODES} узлов или {MAX_EDGES} связей. Сверните ненужные ветки, чтобы раскрыть другие. Фильтры только скрывают узлы.</p>}
    {graph.sourceTruncated.length > 0 && <p className="text-xs text-text-secondary">Часть списков ограничена исходным досье. Все сведения смотрите по ссылке на источник в панели узла.</p>}
    {failure && <div role="alert" className="flex flex-wrap items-center gap-3 rounded border border-kind-1/50 p-3 text-sm"><span>{failure.entity.title}: {failure.message}</span><Button disabled={!!pending} onClick={() => void load(failure.entity, failure.action)}>Повторить загрузку</Button></div>}
    <div className="grid min-w-0 overflow-hidden rounded border border-grid xl:grid-cols-[minmax(0,1fr)_320px]">
      <GraphCanvas graph={visible} selected={selected?.id ?? rootId} onSelect={setSelected} />
      {selected && <aside aria-label="Сведения об узле" className="max-h-[650px] min-w-0 space-y-4 overflow-y-auto border-t border-grid bg-surface p-4 xl:border-l xl:border-t-0">
        <div><p className="mb-1 text-xs text-text-secondary">Выбранный объект{selected.id === rootId ? ' · начало графа' : ''}</p><h3 className="break-words font-semibold">{selected.title}</h3>{selected.entity?.domain && <p className="mt-1 break-all text-xs text-text-secondary">{selected.entity.domain}</p>}</div>
        <dl className="space-y-1 text-xs">{(selected.entity?.facts ?? selected.row?.facts ?? []).map(f => <div key={f.label}><dt className="inline text-text-secondary">{f.label}: </dt><dd className="inline break-words">{f.value}</dd></div>)}</dl>
        {selected.entity && <div className="space-y-2">
          <div className="flex flex-wrap gap-2"><Button disabled={!!pending || (total !== null && count >= total)} loading={pending === selected.id} onClick={() => void load(selected.entity!, 'expand')}><GitBranch size={14} />{total !== null && count >= total ? (total ? 'Все связи раскрыты' : 'Нет связей') : count ? `Ещё ${PAGE_SIZE} связей` : 'Раскрыть связи'}</Button>
            {count > 0 && <Button onClick={() => setShown(s => ({ ...s, [selected.id]: 0 }))}>Свернуть ветку</Button>}
            <Button disabled={!!pending} onClick={() => void load(selected.entity!, 'preview')}><FileText size={14} />Досье узла</Button></div>
          {total !== null && <p className="text-xs text-text-secondary">Раскрыто записей: {count} из {total}. Повторные связи объединены.{total === 0 ? ' Доступных связей в досье нет.' : ''}</p>}
        </div>}
        {(selected.entity?.href || selected.row?.href) && <Link to={(selected.entity?.href ?? selected.row?.href)!} className="inline-block text-xs text-primary hover:underline">Открыть источник ↗</Link>}
        <div className="space-y-3"><h4 className="text-sm font-medium">Основания видимых связей ({related.length})</h4>{related.length === 0 && <p className="text-xs text-text-secondary">Связи ещё не раскрыты, отсутствуют в досье или скрыты фильтрами.</p>}{related.map(edge => <div key={edge.id} className="space-y-2 border-t border-grid pt-3 text-xs">
          <p className="font-medium">{edge.label} · {visible.nodes.find(n => n.id === (edge.from === selected.id ? edge.to : edge.from))?.title}</p>
          {edge.evidence.map((item, i) => <div key={i} className="space-y-1 break-words"><p>{item.reason}</p><p className="text-text-secondary">{item.note}</p><p className="text-text-secondary">Контекст: {item.context}</p>{item.facts.map(f => <p key={f.label}>{f.label}: {f.value}</p>)}<p><Link className="text-primary hover:underline" to={item.href}>{item.source} ↗</Link> · {item.date_label}: {item.observed_at ? new Date(item.observed_at).toLocaleString('ru-RU') : 'дата не указана'}</p></div>)}
        </div>)}</div>
      </aside>}
    </div>
    <p className="text-xs text-text-secondary">Связи основаны на сохранённых данных и ваших правах доступа. Область GPO не подтверждает применение политики; связь пользователя с хостом не всегда означает сеанс входа.</p>
    {dossier.notes.map(note => <p key={note} className="text-xs text-text-secondary">{note}</p>)}
    {previewDossier && <section aria-label="Досье выбранного узла" className="space-y-4 border-t border-grid pt-4">
      <div className="flex items-start justify-between gap-3"><div><h3 className="break-words text-lg font-semibold">Досье: {previewDossier.entity.title}</h3><p className="text-xs text-text-secondary">Граф и раскрытые ветки сохранены выше.</p></div><Button aria-label="Закрыть досье узла" onClick={() => setPreview(null)}><X size={16} /></Button></div>
      {previewDossier.sections.map(s => <section key={s.id}><h4 className="font-medium">{s.title} ({s.items.length}{s.has_more ? '+' : ''})</h4><p className="my-2 text-xs text-text-secondary">{s.note}</p>{s.items.length ? <EvidenceTable rows={s.items} onOpen={entity => void load(entity, 'preview')} /> : <p className="text-sm text-text-secondary">Нет доступных сведений.</p>}</section>)}
      {previewDossier.notes.map(note => <p key={note} className="text-xs text-text-secondary">{note}</p>)}
    </section>}
  </section>
}
