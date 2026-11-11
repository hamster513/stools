import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Search, X } from 'lucide-react'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { DossierSections } from '../DossierSections'
import { ObjectIcon } from '../ObjectIcon'
import type { Dossier, Entity, SearchResult } from '../api'
import { GraphCanvas, type CanvasHandle } from './GraphCanvas'
import { NodeDetails } from './NodeDetails'
import { NodeMenu, type MenuState } from './NodeMenu'
import { buildGraph, categories, expandNode, filterGraph, hideNode, initialState, KIND_LABELS, MAX_EDGES, MAX_NODES, revealHit, searchGraph, sources, type GraphNode, type SearchHit } from './model'

type Action = 'expand' | 'preview'
export function GraphWorkspace({ dossier }: { dossier: Dossier }) {
  const rootId = dossier.entity.id
  const [dossiers, setDossiers] = useState<Record<string, Dossier>>({ [rootId]: dossier })
  const [state, setState] = useState(() => initialState(rootId))
  const [selectedId, setSelected] = useState<string | null>(null)
  const [menu, setMenu] = useState<MenuState | null>(null)
  const [query, setQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [hiddenKinds, setHiddenKinds] = useState<string[]>([])
  const [hiddenSources, setHiddenSources] = useState<string[]>([])
  const [preview, setPreview] = useState<string | null>(null)
  const [pending, setPending] = useState<string | null>(null)
  const [failure, setFailure] = useState<{ message: string; entity: Entity; action: Action } | null>(null)
  const [notice, setNotice] = useState('')
  const alive = useRef(true), busy = useRef(false), canvas = useRef<CanvasHandle>(null)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const closeMenu = useCallback(() => setMenu(null), [])
  const graph = useMemo(() => buildGraph(rootId, dossiers, state), [rootId, dossiers, state])
  const sourceNames = useMemo(() => [...new Set(graph.edges.flatMap(e => e.evidence.flatMap(item => sources(item.source))))].sort(), [graph])
  const visible = useMemo(() => filterGraph(graph, new Set(Object.keys(KIND_LABELS).filter(k => !hiddenKinds.includes(k))), new Set(sourceNames.filter(s => !hiddenSources.includes(s)))), [graph, sourceNames, hiddenKinds, hiddenSources])
  const selected = visible.nodes.find(n => n.id === selectedId)
  const detailsNode = selected && !selected.category && (selected.entity || selected.row) ? selected : null
  const hits = useMemo(() => searchGraph(rootId, dossiers, query), [rootId, dossiers, query])
  const menuNode = menu ? graph.nodes.find(n => n.id === menu.node.id) : undefined
  const canExpand = !!menuNode && !pending && (menuNode.category ? !state.expanded[menuNode.id] || menuNode.category.visible < menuNode.category.count : !!menuNode.entity && !state.expanded[menuNode.id] && (!dossiers[menuNode.id] || categories(dossiers[menuNode.id]).length > 0))
  const canHide = !!menuNode && !pending && (menuNode.category ? menuNode.category.visible > 0 || !!state.expanded[menuNode.id] : menuNode.id !== rootId || graph.nodes.length > 1)
  async function load(entity: Entity, action: Action) {
    if (busy.current) return
    busy.current = true; setPending(entity.id); setFailure(null); setNotice('')
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
      else {
        setState(current => expandNode(current, { ...entity, entity }, { ...dossiers, [entity.id]: next }))
        if (!categories(next).length) setNotice(`${entity.title}: доступных связей в досье нет.`)
      }
    } catch (error) {
      if (alive.current) setFailure({ message: error instanceof Error ? error.message : 'Не удалось загрузить связи.', entity, action })
    } finally {
      busy.current = false
      if (alive.current) setPending(null)
    }
  }
  function expand(node: GraphNode) {
    closeMenu()
    if (node.category) { setState(s => expandNode(s, node, dossiers)); setNotice('') }
    else if (node.entity) void load(node.entity, 'expand')
  }
  function hide(node: GraphNode) {
    closeMenu(); setState(s => hideNode(s, node, rootId)); setNotice('')
    if (selectedId === node.id) setSelected(null)
    if (preview === node.id) setPreview(null)
  }
  function select(id: string | null) { setSelected(id); closeMenu(); setSearchOpen(false) }
  function showHit(hit: SearchHit) {
    const next = revealHit(state, hit), candidate = buildGraph(rootId, dossiers, next)
    if (!candidate.nodes.some(n => n.id === hit.node.id)) { setNotice('Недостаточно места для этой ветки. Скройте ненужные объекты и повторите поиск.'); return }
    setState(next); setSelected(hit.node.id); setSearchOpen(false); closeMenu()
    setNotice(hiddenKinds.length || hiddenSources.length ? 'Фильтры сброшены, чтобы показать найденный объект и путь к нему.' : '')
    setHiddenKinds([]); setHiddenSources([])
    requestAnimationFrame(() => { if (alive.current) canvas.current?.focus(hit.node.id) })
  }
  const toggle = (items: string[], value: string) => items.includes(value) ? items.filter(i => i !== value) : [...items, value]
  const previewDossier = preview ? dossiers[preview] : null
  return <section aria-label="Рабочее поле графа" className="space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2 text-sm"><p role="status">Объекты: {visible.nodes.filter(n => !n.category).length} · Категории: {visible.nodes.filter(n => n.category).length}</p><span className="text-xs text-text-secondary">Состояние сохраняется до нового поиска или ухода со страницы</span></div>
    <div className="space-y-2">
      <label className="block text-sm"><span className="mb-1 block text-text-secondary">Поиск в графе</span><span className="relative block"><Search size={16} aria-hidden className="absolute left-3 top-2.5 text-text-secondary" /><input className={`${FIELD} pl-9`} value={query} onFocus={() => setSearchOpen(true)} onChange={e => { setQuery(e.target.value); setSearchOpen(true) }} placeholder="Название, группа, политика, хост или идентификатор" onKeyDown={e => { if (e.key === 'Escape') setSearchOpen(false) }} /></span></label>
      <p className="text-xs text-text-secondary">Поиск по загруженным досье, включая свёрнутые связи. Выберите результат, чтобы показать выбранный объект и путь к нему; активные фильтры будут сброшены.</p>
      {query.trim() && searchOpen && <div className="rounded border border-grid"><p role="status" className="border-b border-grid px-3 py-2 text-xs text-text-secondary">Найдено: {hits.length}{hits.length > 100 ? '. Показаны первые 100 — уточните запрос.' : ''}</p><ul aria-label="Результаты поиска в графе" className="max-h-64 overflow-y-auto">{hits.slice(0, 100).map(hit => <li key={hit.node.id}><button className="flex min-h-11 w-full items-center gap-3 px-3 py-2 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary" onClick={() => showHit(hit)} aria-label={`Показать ${hit.node.title}`}><ObjectIcon kind={hit.node.category?.objectKind ?? hit.node.kind} /><span className="min-w-0"><span className="block break-words text-sm font-medium">{hit.node.title}</span><span className="block text-xs text-text-secondary">{hit.context}</span></span></button></li>)}</ul></div>}
    </div>
    <details className="rounded border border-grid p-3 text-xs"><summary className="cursor-pointer font-medium">Фильтры типов и источников{hiddenKinds.length || hiddenSources.length ? ' · активны' : ''}</summary><div className="mt-3 space-y-3">
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2"><legend className="mb-2 font-medium">Типы объектов</legend>{Object.entries(KIND_LABELS).map(([id, label]) => <label key={id} className="flex items-center gap-1.5"><input type="checkbox" checked={!hiddenKinds.includes(id)} onChange={() => setHiddenKinds(k => toggle(k, id))} className="accent-primary" />{label}</label>)}</fieldset>
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2"><legend className="mb-2 font-medium">Источники связей</legend>{sourceNames.length ? sourceNames.map(source => <label key={source} className="flex items-center gap-1.5"><input type="checkbox" checked={!hiddenSources.includes(source)} onChange={() => setHiddenSources(s => toggle(s, source))} className="accent-primary" />{source}</label>) : <span className="text-text-secondary">Нет доступных связей</span>}</fieldset>
      {(hiddenKinds.length > 0 || hiddenSources.length > 0) && <button className="text-primary hover:underline" onClick={() => { setHiddenKinds([]); setHiddenSources([]) }}>Сбросить фильтры</button>}
    </div></details>
    {graph.limited && <p role="status" className="text-sm text-text-secondary">Категория не раскрыта целиком: предел рабочего поля — {MAX_NODES} узлов и {MAX_EDGES} связей. Скройте ненужные ветки или найдите и покажите отдельный объект. Частичный список вместо полного не выводится.</p>}
    {graph.sourceTruncated.length > 0 && <p className="text-xs text-text-secondary">В исходном досье есть ограниченные списки. Число с «+» означает, что получены не все записи; поиск работает по полученным данным.</p>}
    {pending && <p role="status" className="text-sm text-text-secondary">Загружаем досье и категории связей…</p>}
    {notice && <p role="status" className="text-sm text-text-secondary">{notice}</p>}
    {failure && <div role="alert" className="flex flex-wrap items-center gap-3 rounded border border-kind-1/50 p-3 text-sm"><span>{failure.entity.title}: {failure.message}</span><Button disabled={!!pending} onClick={() => void load(failure.entity, failure.action)}>Повторить загрузку</Button></div>}
    <div className={`grid min-w-0 overflow-hidden rounded border border-grid ${detailsNode ? 'xl:grid-cols-[minmax(0,1fr)_320px]' : ''}`}>
      <GraphCanvas ref={canvas} graph={visible} selected={selected?.id ?? null} onSelect={select} onMenu={(node, point, trigger) => { setSearchOpen(false); setMenu({ node, point, trigger }) }} />
      {detailsNode && <NodeDetails key={detailsNode.id} node={detailsNode} graph={visible} pending={!!pending} onPreview={() => detailsNode.entity && void load(detailsNode.entity, 'preview')} onClose={() => setSelected(null)} />}
    </div>
    {menu && menuNode && <NodeMenu menu={menu} canExpand={canExpand} canHide={canHide} onClose={closeMenu} onExpand={() => expand(menuNode)} onHide={() => hide(menuNode)} />}
    <p className="text-xs text-text-secondary">Категории объединяют сведения из досье. Подписи и основания раскрытых связей сохраняют их смысл: область GPO не подтверждает применение, связь с хостом не всегда означает вход пользователя.</p>
    {previewDossier && <section aria-label="Досье выбранного узла" className="space-y-4 border-t border-grid pt-4"><div className="flex items-start justify-between gap-3"><h3 className="break-words text-lg font-semibold">Досье: {previewDossier.entity.title}</h3><Button aria-label="Закрыть досье узла" onClick={() => setPreview(null)}><X size={16} /></Button></div><DossierSections key={previewDossier.entity.id} dossier={previewDossier} onOpen={entity => void load(entity, 'preview')} /></section>}
  </section>
}
