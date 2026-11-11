import { useState, type FormEvent } from 'react'
import { ArrowLeft, Search, Network, FileText } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { FIELD, Field } from '@/components/ui/Field'
import { ErrorState } from '@/components/ui/ErrorState'
import { Link } from '@/lib/router'
import { EvidenceTable } from './EvidenceTable'
import { DossierSections } from './DossierSections'
import { ObjectIcon } from './ObjectIcon'
import { GraphWorkspace } from './graph/GraphWorkspace'
import { useSearch, type Kind, type Entity, type SearchInput } from './api'
const KINDS: Record<Kind, string> = { auto: 'Любой объект', host: 'Хост', user: 'Пользователь', group: 'Группа', ip: 'IP-адрес', domain: 'Домен', cve: 'CVE' }
const TYPES = { host: 'Хост', user: 'Пользователь', group: 'Группа' }
export function SearchPage() {
  const [mode, setMode] = useState<'dossier' | 'graph'>('dossier')
  const [input, setInput] = useState('')
  const [kind, setKind] = useState<Kind>('auto')
  const [history, setHistory] = useState<SearchInput[]>([])
  const search = useSearch()
  const data = search.data
  const dossier = data?.dossier
  function submit(e: FormEvent) { e.preventDefault(); setHistory([]); search.mutate({ query: input.trim(), kind }) }
  function open(entity: Entity) {
    if (search.variables) setHistory(h => [...h, search.variables!])
    setInput(entity.title); setKind(entity.kind)
    search.mutate({ query: entity.title, kind: entity.kind, entity_id: entity.id })
  }
  function back() {
    const previous = history.at(-1)
    if (!previous) return
    setHistory(h => h.slice(0, -1)); setInput(previous.query); setKind(previous.kind); search.mutate(previous)
  }
  const groups = data?.groups.filter(g => g.items.length) ?? []
  return <div className="h-full overflow-y-auto p-4 sm:p-6"><div className="mx-auto max-w-7xl space-y-6">
    <header><h1 className="flex items-center gap-2 text-xl font-semibold"><Search size={22} aria-hidden />Поиск</h1>
      <p className="mt-2 text-sm text-text-secondary">Всё известное о хосте, пользователе, группе или угрозе — по собранным данным STools.</p></header>
    <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
      <div className="min-w-64 flex-1"><Field label="Имя, IP, логин, UPN, SID или CVE"><input className={FIELD} value={input} onChange={e => setInput(e.target.value)} maxLength={255} required autoComplete="off" placeholder="srv01 · DOMAIN\user · user@company.ru · Domain Admins" /></Field></div>
      <div className="w-52"><Field label="Тип объекта"><select className={FIELD} value={kind} onChange={e => setKind(e.target.value as Kind)}>{Object.entries(KINDS).map(([id,title]) => <option key={id} value={id}>{title}</option>)}</select></Field></div>
      <Button type="submit" loading={search.isPending} disabled={!input.trim() || search.isPending}>Найти</Button>
    </form>
    {search.isError && <ErrorState message={search.error.message} onRetry={() => search.variables && search.mutate(search.variables)} />}
    {search.isPending && <p role="status" className="text-sm text-text-secondary">Собираем досье из доступных источников…</p>}
    {!search.isPending && !search.isError && data && <>
      {history.length > 0 && <button onClick={back} className="inline-flex items-center gap-1 text-sm text-primary"><ArrowLeft size={14} />Назад к результату</button>}
      {data.notes.map(note => <p key={note} className="text-sm text-text-secondary">{note}</p>)}
      {data.matches.length > 1 && !dossier && <section><h2 className="font-medium">Выберите объект ({data.matches.length}{data.has_more ? '+' : ''})</h2><p className="my-2 text-sm text-text-secondary">Совпадение имени или IP не означает, что это один объект.</p>
        <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs text-text-secondary"><tr><th className="py-2">Объект</th><th>Тип</th><th>Домен / идентификаторы</th></tr></thead><tbody>{data.matches.map(e => <tr key={e.id} className="border-t border-grid"><td className="py-3 pr-4"><button className="text-primary hover:underline" onClick={() => open(e)}>{e.title}</button></td><td className="pr-4">{TYPES[e.kind]}</td><td>{[e.domain,...e.facts.filter(f => ['IP','Логин','SID','UPN'].includes(f.label)).map(f => f.value)].filter(Boolean).join(' · ')}</td></tr>)}</tbody></table></div>
        {data.has_more && <p className="text-xs text-text-secondary">Показаны первые 20 объектов. Уточните домен, UPN или SID.</p>}
      </section>}
      {dossier && <>
        <section className="border-y border-grid py-4"><div className="flex flex-wrap items-baseline gap-3"><ObjectIcon kind={dossier.entity.kind} /><span className="text-xs text-text-secondary">{TYPES[dossier.entity.kind]}</span><h2 className="break-all text-lg font-semibold">{dossier.entity.title}</h2><Link to={dossier.entity.href} className="text-xs text-primary hover:underline">Открыть источник ↗</Link></div>
          <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-sm">{[...(dossier.entity.domain ? [{label:'Домен',value:dossier.entity.domain}] : []),...dossier.entity.facts].map(f => <div key={f.label}><dt className="inline text-text-secondary">{f.label}: </dt><dd className="inline break-all">{f.value}</dd></div>)}</dl>
        </section>
        <div role="group" aria-label="Режим просмотра" className="flex gap-2">
          <Button aria-pressed={mode === 'dossier'} variant={mode === 'dossier' ? 'primary' : 'secondary'} onClick={() => setMode('dossier')}><FileText size={15} />Досье</Button>
          <Button aria-pressed={mode === 'graph'} variant={mode === 'graph' ? 'primary' : 'secondary'} onClick={() => setMode('graph')}><Network size={15} />Граф</Button>
        </div>
        <div hidden={mode !== 'graph'}><GraphWorkspace key={`${dossier.entity.id}:${search.submittedAt}`} dossier={dossier} /></div>
        <div hidden={mode !== 'dossier'} className="space-y-6">
        <DossierSections key={`${dossier.entity.id}:${search.submittedAt}`} dossier={dossier} onOpen={open} />
        </div>
      </>}
      {!data.matches.length && groups.map(g => <section key={g.id}><h2 className="font-semibold">{g.title}</h2><p className="my-2 text-xs text-text-secondary">{g.note}</p><EvidenceTable rows={g.items} onOpen={open} />{g.has_more && <p className="text-xs text-text-secondary">Первые 20 совпадений. Уточните запрос или откройте источник.</p>}</section>)}
      {!data.matches.length && !groups.length && <p className="text-sm text-text-secondary">Совпадений в доступных данных нет. Попробуйте другой идентификатор или тип объекта.</p>}
      {!data.matches.length && data.groups.some(g => g.status === 'denied') && <p className="text-xs text-text-secondary">Часть источников недоступна по вашим правам: {data.groups.filter(g => g.status === 'denied').map(g => g.title).join(', ')}.</p>}
    </>}
  </div></div>
}
