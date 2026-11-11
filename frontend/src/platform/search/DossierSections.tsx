import { useId, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Search } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FIELD } from '@/components/ui/Field'
import { EvidenceTable } from './EvidenceTable'
import { ObjectIcon } from './ObjectIcon'
import { SECTION_KINDS } from './sectionKinds'
import { matchesRow } from './searchText'
import type { Dossier, Entity } from './api'


export function DossierSections({ dossier, onOpen }: { dossier: Dossier; onOpen: (entity: Entity) => void }) {
  const prefix = useId()
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const sections = useMemo(() => dossier.sections.map(section => ({ ...section, matches: section.items.filter(row => matchesRow(row, query)) })), [dossier, query])
  const count = sections.reduce((total, s) => total + s.matches.length, 0)
  function search(value: string) {
    setQuery(value)
    setExpanded(value.trim() ? Object.fromEntries(dossier.sections.map(s => [s.id, s.items.some(row => matchesRow(row, value))])) : {})
  }
  return <div className="min-w-0 space-y-3">
    <div className="flex flex-wrap items-end gap-2">
      <label className="min-w-56 flex-1 text-sm"><span className="mb-1 block text-text-secondary">Поиск в досье</span><span className="relative block"><Search size={16} aria-hidden className="absolute left-3 top-2.5 text-text-secondary" /><input className={`${FIELD} pl-9`} value={query} onChange={e => search(e.target.value)} placeholder="Группа, политика, хост, источник или идентификатор" /></span></label>
      {query && <Button onClick={() => search('')}>Очистить поиск</Button>}
      <Button onClick={() => setExpanded(Object.fromEntries(sections.map(s => [s.id, true])))}>Развернуть все</Button>
      <Button onClick={() => setExpanded({})}>Свернуть все</Button>
    </div>
    {query.trim() && <p role="status" className="text-xs text-text-secondary">Найдено записей: {count}. Поиск по полученным данным досье.</p>}
    <div className="divide-y divide-grid rounded border border-grid">
      {sections.map(section => {
        const open = !!expanded[section.id], panelId = `${prefix}-${section.id}`
        return <section key={section.id}>
          <h3><button type="button" aria-expanded={open} aria-controls={panelId} onClick={() => setExpanded(s => ({ ...s, [section.id]: !open }))} className="flex min-h-12 w-full items-center gap-3 px-3 py-3 text-left hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary">
            {open ? <ChevronDown size={17} aria-hidden /> : <ChevronRight size={17} aria-hidden />}
            <ObjectIcon kind={section.id === 'observations' ? 'observations' : SECTION_KINDS[section.id] ?? 'evidence'} />
            <span className="min-w-0 flex-1 font-medium">{section.title}</span>
            <span className="shrink-0 rounded bg-app-bg px-2 py-0.5 text-xs tabular-nums text-text-secondary">{query.trim() ? `${section.matches.length} из ` : ''}{section.items.length}{section.has_more ? '+' : ''}</span>
          </button></h3>
          <div id={panelId} hidden={!open} className="min-w-0 px-3 pb-3">
            <p className="mb-3 text-xs text-text-secondary">{section.note}</p>
            {section.matches.length ? <EvidenceTable rows={section.matches} onOpen={onOpen} /> : <p className="py-3 text-sm text-text-secondary">{query.trim() ? 'Совпадений в этом разделе нет.' : 'Нет доступных сведений.'}</p>}
            {section.has_more && <p className="mt-2 text-xs text-text-secondary">Показаны первые {section.items.length} записей источника. Поиск охватывает этот список; дополнительные сведения доступны в исходном модуле.</p>}
          </div>
        </section>
      })}
    </div>
    {dossier.notes.map(note => <p key={note} className="text-xs text-text-secondary">{note}</p>)}
  </div>
}
