import { useState, type FormEvent } from 'react'
import { ArrowUpRight, Search } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/components/ui/Field'
import { Link } from '@/lib/router'
import { useLookup, type LookupEvidence, type LookupGroup, type LookupKind } from '../api/lookup'

const KINDS: Record<LookupKind, string> = {
  auto: 'Определить автоматически', ip: 'IP-адрес', host: 'Имя хоста / FQDN', domain: 'Домен', cve: 'CVE',
}
const STATUS = { searched: 'Проверено', denied: 'Нет доступа', not_applicable: 'Не применимо' }

function date(value: string | null) {
  if (!value) return 'не указана источником'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? 'не указана источником' : parsed.toLocaleString('ru-RU')
}

function EvidenceCard({ item }: { item: LookupEvidence }) {
  return (
    <article className="min-w-0 rounded border border-border bg-panel p-4">
      <div className="flex items-start justify-between gap-3">
        <h3 className="min-w-0 break-words font-mono text-sm font-medium text-text">{item.title}</h3>
        <Link to={item.href} className="inline-flex shrink-0 items-center gap-1 rounded text-xs text-accent hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-focus-ring">
          Открыть<ArrowUpRight size={14} aria-hidden />
          <span className="sr-only">: {item.title}</span>
        </Link>
      </div>
      <p className="mt-2 text-xs text-text-secondary">{item.reason}</p>
      <dl className="mt-3 space-y-1.5 text-xs">
        {item.facts.map(fact => <div key={fact.label} className="grid grid-cols-[minmax(100px,1fr)_2fr] gap-3">
          <dt className="text-text-secondary">{fact.label}</dt>
          <dd className="min-w-0 whitespace-pre-wrap break-words text-text">{fact.value}</dd>
        </div>)}
      </dl>
      <div className="mt-3 border-t border-border pt-2 text-xs text-text-secondary">
        <p>{item.source}</p>
        <p>{item.date_label}: {date(item.observed_at)}</p>
      </div>
    </article>
  )
}

function ResultGroup({ group }: { group: LookupGroup }) {
  return (
    <section id={`lookup-${group.id}`} aria-labelledby={`lookup-title-${group.id}`} className="scroll-mt-4">
      <h2 id={`lookup-title-${group.id}`} className="text-sm font-semibold text-text">{group.title} <span className="ml-1 font-normal text-text-secondary">{group.items.length}{group.has_more ? '+' : ''}</span></h2>
      {group.note && <p className="mt-1 text-xs text-text-secondary">{group.note}</p>}
      <div className="mt-3 grid gap-3 xl:grid-cols-2">{group.items.map(item => <EvidenceCard key={item.id} item={item} />)}</div>
      {group.has_more && <p className="mt-2 text-sm text-text-secondary">Показаны первые 20 совпадений. Уточните запрос до IP или полного имени; полный список доступен в модуле-источнике.</p>}
    </section>
  )
}

export function LookupPage() {
  const [input, setInput] = useState('')
  const [kind, setKind] = useState<LookupKind>('auto')
  const lookup = useLookup()
  const data = lookup.data
  const matched = data?.groups.filter(g => g.items.length > 0) ?? []
  const empty = data?.groups.filter(g => g.status === 'searched' && !g.items.length) ?? []
  const searched = data?.groups.filter(g => g.status === 'searched').length ?? 0

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    lookup.reset()
    lookup.mutate({ query: input.trim(), kind })
  }

  return (
    <div className="h-full overflow-y-auto p-4 sm:p-6">
      <div className="mx-auto max-w-6xl space-y-6">
        <div>
          <h1 className="text-xl font-semibold text-text">Что мы знаем об этом?</h1>
          <p className="mt-2 max-w-3xl text-sm text-text-secondary">Найдите актив, сведения AD и AV, уязвимости и публикации по одному идентификатору. Поиск выполняется по собранным данным внутри STools.</p>
        </div>
        <form onSubmit={submit}>
          <fieldset disabled={lookup.isPending} className="flex flex-col gap-3 rounded border border-border bg-panel p-4 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1">
              <Field label="IP, имя хоста, домен или CVE">
                <input className={`${FIELD} font-mono`} value={input} maxLength={255} onChange={e => { setInput(e.target.value); lookup.reset() }} autoComplete="off" spellCheck={false} placeholder="10.0.0.10 · srv01.corp.local · CVE-2026-12345" required />
              </Field>
            </div>
            <div className="sm:w-60"><Field label="Тип запроса">
              <select className={FIELD} value={kind} onChange={e => { setKind(e.target.value as LookupKind); lookup.reset() }}>
                {Object.entries(KINDS).map(([id, title]) => <option key={id} value={id}>{title}</option>)}
              </select>
            </Field></div>
            <Button type="submit" variant="primary" loading={lookup.isPending} disabled={!input.trim()}><Search size={16} aria-hidden />Найти</Button>
          </fieldset>
          <p className="mt-2 text-xs text-text-secondary">Точные совпадения, без учёта регистра. В режиме «Автоматически» имя проверяется и как хост, и как домен. Запросы не сохраняются в истории поиска.</p>
        </form>
        {lookup.isPending && <p role="status" className="text-sm text-text-secondary">Проверяем доступные источники…</p>}
        {lookup.error && <div role="alert" className="rounded border border-kind-1/40 bg-kind-1/5 p-4 text-sm text-text">{lookup.error.message || 'Не удалось выполнить поиск. Повторите запрос.'}</div>}
        {!data && !lookup.isPending && !lookup.error && <div className="rounded border border-border p-5 text-sm text-text-secondary">
          <p className="font-medium text-text">Начните с известного идентификатора</p>
          <p className="mt-2">IP или имя — карточки инфраструктуры и CVE хостов. Домен — компьютеры этого домена. CVE — сведения об уязвимости, затронутые по импорту хосты и образы, публикации.</p>
          <p className="mt-2">AD проверяется по наблюдениям компьютеров, синхронизированным в Assets. Публикации и образы проверяются по CVE.</p>
        </div>}
        {data && <>
          <div className="rounded border border-border p-4">
            <p role="status" className="text-sm text-text">Результаты для <strong className="break-all font-mono">{data.query}</strong> · {data.kind === 'name' ? 'Имя / домен' : KINDS[data.kind]}</p>
            <p className="mt-1 text-xs text-text-secondary">Поиск: {date(data.searched_at)}. Даты исходных данных указаны в карточках.</p>
            <div className="mt-3 flex flex-wrap gap-2" aria-label="Покрытие поиска">
              {data.groups.map(g => <span key={g.id} className="rounded border border-border px-2 py-1 text-xs text-text-secondary">{g.title}: {g.items.length ? `${g.items.length}${g.has_more ? '+' : ''}` : STATUS[g.status]}</span>)}
            </div>
            <p className="mt-3 text-xs text-text-secondary">Совпадение имени или IP не доказывает, что записи из разных источников относятся к одному устройству. Отсутствие совпадений не доказывает отсутствие угрозы.</p>
          </div>
          {!matched.length && <div className="rounded border border-border p-5 text-sm text-text">
            <p className="font-medium">{searched ? 'В проверенных источниках совпадений нет' : 'Для этого запроса нет доступных источников'}</p>
            <p className="mt-2 text-text-secondary">{searched ? 'Проверьте полное имя, тип запроса и актуальность синхронизаций. Поиск охватывает только загруженные данные и доступные вам модули.' : 'Для поиска нужны права чтения модулей-источников. Проверьте отметки доступа выше.'}</p>
          </div>}
          {matched.map(g => <ResultGroup key={g.id} group={g} />)}
          {!!empty.length && <details className="rounded border border-border p-4 text-xs text-text-secondary" open={!matched.length}>
            <summary className="cursor-pointer text-sm text-text">Проверено без совпадений ({empty.length})</summary>
            <ul className="mt-3 space-y-2">{empty.map(g => <li key={g.id}><strong>{g.title}.</strong> {g.note || 'Точных совпадений нет.'}</li>)}</ul>
          </details>}
        </>}
      </div>
    </div>
  )
}
