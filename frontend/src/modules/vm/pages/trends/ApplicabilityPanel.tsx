import { when } from '../../api/trends'
import { safeUrl } from './publicationUrl'
export interface Enrichment {
  cvss: number | null; epss: number | null; known_exploited: boolean | null; description: string; affected_products: string[]
  fetched_at: string; expires_at: string | null; provenance: Record<string, string>
  providers: Record<string, { status: string; fetched_at: string; expires_at: string | null; url: string; error: string }>
}
export interface Applicability { local_ref: string; state: string; confidence_kind: string; reasons: string[]; product?: string; version?: string }
export function ApplicabilityPanel({ enrichment, items }: { enrichment?: Enrichment | null; items: Applicability[] }) {
  if (!enrichment && !items.length) return null
  return <section className="space-y-2"><h3 className="font-semibold">Затронутые продукты и применимость</h3>
    {enrichment && <>
      {!!enrichment.affected_products?.length && <p className="text-xs">{enrichment.affected_products.join(', ')}</p>}
      <details className="text-xs text-text-secondary"><summary className="cursor-pointer">Источники и свежесть данных</summary>
        {Object.entries(enrichment.providers ?? {}).map(([name, provider]) => <p className="mt-2" key={name}><a href={safeUrl(provider.url)} target="_blank" rel="noopener noreferrer" className="underline">{name}</a> · {provider.status} · Получено {when(provider.fetched_at)} · Срок кэша {when(provider.expires_at)} {provider.error}</p>)}</details></>}
    {items.length > 0 && <details><summary>Проверка локальных совпадений ({items.length})</summary>{items.map((item, i) => <div key={i} className="border-b border-grid py-2 text-sm"><p>{item.local_ref} {item.product} {item.version} · {item.state === 'affected' ? 'Затронуто' : item.state === 'not_affected' ? 'Вне диапазона' : 'Нужна проверка'}</p><p>{item.reasons.join('; ')}</p></div>)}</details>}
  </section>
}
