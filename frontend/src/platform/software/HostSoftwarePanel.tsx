import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api, buildQuery, errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { FIELD } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

const LABELS = {
  checked: 'Сопоставлено', unrecognized: 'Не распознано', missing_version: 'Нет версии',
  pending: 'Ожидает проверки', uncertain: 'Неясные условия',
} as const
const NOTES: Record<keyof typeof LABELS, string> = {
  checked: 'Есть результат сравнения версии с условиями NVD. Это не означает отсутствие уязвимостей.',
  unrecognized: 'Продукт не найден в индексе NVD по названию и издателю. Возможны другие названия или отсутствие записей NVD.',
  missing_version: 'KSC не передал версию. Для этих записей нельзя завершить проверку версии.',
  pending: 'Сопоставление ещё не выполнено или условия применимости NVD загружены не полностью.',
  uncertain: 'Продукт распознан, но условия применимости требуют дополнительных данных.',
}
type Coverage = keyof typeof LABELS
interface Software { id: number; name: string; version: string; publisher: string; coverage: Coverage; product_id?: string; installed_on?: string | null; install_dir?: string }
interface Finding {
  id: number; name: string; version: string; publisher: string; cve_id: string;
  state: 'affected' | 'unknown'; reason: string; evidence: string[]; checked_at: string;
  cvss: number | null; epss: number | null; kev: boolean;
}
interface HostSoftware {
  snapshot_id: number; collected_at: string; inventory_status: 'complete' | 'not_collected' | 'error';
  inventory_error: string | null; nvd_ready: boolean;
  coverage: Record<Coverage | 'total', number>;
  finding_counts: Record<'affected' | 'unknown', number>;
  software: { items: Software[]; total: number };
  vulnerabilities: { items: Finding[]; total: number };
}
const LIMIT = 50
const date = (value: string) => new Date(value).toLocaleString('ru-RU')

function Pager({ label, offset, total, busy, onChange }: {
  label: string; offset: number; total: number; busy: boolean; onChange: (value: number) => void;
}) {
  return <nav aria-label={label} className="flex flex-wrap items-center justify-between gap-2 py-2 text-text-secondary">
    <span>{total ? `${offset + 1}–${Math.min(offset + LIMIT, total)} из ${total}` : '0 записей'}</span>
    {total > LIMIT && <div className="flex gap-2">
      <Button disabled={busy || offset === 0} onClick={() => onChange(Math.max(0, offset - LIMIT))}>Назад</Button>
      <Button disabled={busy || offset + LIMIT >= total} onClick={() => onChange(offset + LIMIT)}>Далее</Button>
    </div>}
  </nav>
}

/** Shared evidence view; the caller selects an API endpoint with its own access boundary. */
export function HostSoftwarePanel({ endpoint, source }: { endpoint: string; source?: { server_id: number; host_id: string } }) {
  const [filter, setFilter] = useState<Coverage | ''>('')
  const [search, setSearch] = useState('')
  const q = useDebouncedValue(search, 250)
  const [state, setState] = useState('')
  const [softwarePage, setSoftwarePage] = useState({ q: '', filter: '', offset: 0 })
  const [vulnPage, setVulnPage] = useState({ state: '', offset: 0 })
  const softwareOffset = softwarePage.q === q && softwarePage.filter === filter ? softwarePage.offset : 0
  const vulnOffset = vulnPage.state === state ? vulnPage.offset : 0
  const query = useQuery<HostSoftware>({
    queryKey: ['host-software', endpoint, source, q, filter, state, softwareOffset, vulnOffset],
    queryFn: () => api.get(`${endpoint}${buildQuery({
      ...source,
      q, coverage: filter || undefined, state: state || undefined, limit: LIMIT,
      software_offset: softwareOffset, vuln_offset: vulnOffset,
    })}`),
    placeholderData: keepPreviousData,
  })
  const data = query.data
  if (query.isError) return <ErrorState message={errorText(query.error, 'Не удалось загрузить ПО и уязвимости') ?? 'Не удалось загрузить ПО и уязвимости'} onRetry={() => query.refetch()} />
  if (!data) return <div className="flex justify-center py-8"><Spinner /></div>
  const busy = query.isFetching
  return <section aria-label="ПО и уязвимости хоста" aria-busy={busy} className="space-y-4 text-text">
    <div className="space-y-1 text-text-secondary">
      <p>Снимок KSC #{data.snapshot_id} · {date(data.collected_at)}</p>
      <p>Показаны сохранённые результаты этого снимка. После обновления NVD автоматически пересчитывается последний снимок каждого сервера.</p>
      {!data.nvd_ready && <p role="status" className="text-risk-medium">Условия применимости NVD загружены не полностью. Обновите справочник NVD; оценка пока неполная.</p>}
      {busy && <p role="status">Обновление…</p>}
    </div>
    {data.inventory_status !== 'complete' ? <div role="status" className="rounded border border-grid p-3">
      <h3 className="font-semibold">{data.inventory_status === 'error' ? 'Не удалось собрать инвентарь ПО' : 'Инвентарь ПО не собран'}</h3>
      <p className="mt-1 text-text-secondary">{data.inventory_error || 'В этом снимке нет списка установленного ПО. Нужен новый сбор инвентаря KSC.'}</p>
      <p className="mt-1 text-text-secondary">Отсутствие данных не означает отсутствие уязвимостей.</p>
    </div> : <>
      <section aria-label="Полнота проверки ПО" className="space-y-2">
        <h3 className="font-semibold">Полнота проверки ПО · {data.coverage.total} записей</h3>
        <div className="flex flex-wrap gap-2">
          <Button variant={filter === '' ? 'primary' : 'secondary'} aria-pressed={filter === ''} onClick={() => { setFilter(''); setSoftwarePage({ q, filter: '', offset: 0 }) }}>Все: {data.coverage.total}</Button>
          {(Object.keys(LABELS) as Coverage[]).map((key) => <Button key={key} variant={filter === key ? 'primary' : 'secondary'} aria-pressed={filter === key} title={NOTES[key]}
            onClick={() => { setFilter(key); setSoftwarePage({ q, filter: key, offset: 0 }) }}>{LABELS[key]}: {data.coverage[key]}</Button>)}
        </div>
        <p className="text-text-secondary">Категории не пересекаются: сначала выделяем ПО без версии, затем ожидание проверки. «Сопоставлено» означает наличие результата сравнения версии, а не безопасность ПО.</p>
        {filter && <p className="text-text-secondary">{NOTES[filter]}</p>}
      </section>
      <section aria-label="Уязвимости ПО" className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-semibold">Совпадения CVE: {data.finding_counts.affected} · кандидаты: {data.finding_counts.unknown}</h3>
          <label className="text-text-secondary">Результат сопоставления
            <select className={`${FIELD} ml-2`} value={state} onChange={(e) => { setState(e.target.value); setVulnPage({ state: e.target.value, offset: 0 }) }}>
              <option value="">Все результаты</option><option value="affected">Совпала версия</option><option value="unknown">Нужна проверка</option>
            </select>
          </label>
        </div>
        <p className="text-text-secondary">Одна строка — CVE для одной записи ПО. Совпадение версии не подтверждает возможность эксплуатации.</p>
        {!data.vulnerabilities.total ? <p className="rounded border border-grid p-3">По выбранным условиям совпадений CVE нет. Это не гарантирует отсутствие уязвимостей — учитывайте полноту проверки ПО.</p> :
          <div className="max-h-96 overflow-auto"><table className="w-full text-left text-xs">
            <caption className="sr-only">CVE для ПО хоста</caption>
            <thead className="sticky top-0 bg-surface text-text-secondary"><tr>{['CVE / приоритет', 'ПО / версия', 'Результат и основание'].map((name) => <th key={name} scope="col" className="p-2 font-medium">{name}</th>)}</tr></thead>
            <tbody>{data.vulnerabilities.items.map((item) => <tr key={item.id} className="border-t border-grid align-top">
              <td className="p-2"><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`} target="_blank" rel="noreferrer" className="font-mono underline">{item.cve_id}</a>
                <div className="mt-1 text-text-secondary">CVSS: {item.cvss ?? '—'} · EPSS: {item.epss === null ? '—' : `${(item.epss * 100).toFixed(2)}%`}</div>
                {item.kev && <span className="text-risk-high">CISA KEV</span>}
              </td>
              <td className="break-words p-2">{item.name || 'Без названия'}<div className="font-mono">{item.version.trim() || 'Версия неизвестна'}</div><div className="text-text-secondary">{item.publisher || 'Издатель неизвестен'}</div></td>
              <td className="p-2"><div className="font-medium">{item.state === 'affected' ? 'Совпала версия' : 'Нужна проверка'}</div>
                <p className="mt-1 break-words text-text-secondary">{item.reason}</p>
                {item.evidence.length > 0 && <details className="mt-1"><summary className="cursor-pointer">Условия сопоставления</summary><ul className="mt-1 list-inside list-disc break-all text-text-secondary">{item.evidence.map((line, i) => <li key={i}>{line}</li>)}</ul></details>}
                <div className="mt-1 text-text-secondary">Проверено: {date(item.checked_at)}</div>
              </td>
            </tr>)}</tbody>
          </table></div>}
        <Pager label="Страницы уязвимостей" offset={vulnOffset} total={data.vulnerabilities.total} busy={busy} onChange={(offset) => setVulnPage({ state, offset })} />
      </section>
      <section aria-label="Инвентарь ПО" className="space-y-2">
        <h3 className="font-semibold">Программы · {filter ? LABELS[filter] : 'Все'}</h3>
        <label className="block text-text-secondary">Поиск по названию, издателю или версии
          <input type="search" maxLength={255} className={`${FIELD} mt-1 w-full`} value={search} onChange={(e) => { setSearch(e.target.value); setSoftwarePage({ q: e.target.value, filter, offset: 0 }) }} />
        </label>
        {!data.software.total ? <p>{data.coverage.total === 0 ? 'KSC вернул пустой список ПО. Это не подтверждает отсутствие установленного ПО или уязвимостей.' : 'Программ по выбранным условиям нет.'}</p> :
          <div className="max-h-96 overflow-auto"><table className="w-full text-left text-xs">
            <caption className="sr-only">Программы и полнота проверки</caption>
            <thead className="sticky top-0 bg-surface text-text-secondary"><tr>{['Программа / издатель', 'Версия KSC', 'Проверка'].map((name) => <th key={name} scope="col" className="p-2 font-medium">{name}</th>)}</tr></thead>
            <tbody>{data.software.items.map((item) => <tr key={item.id} className="border-t border-grid align-top">
              <td className="break-words p-2">{item.name || 'Без названия'}<div className="text-text-secondary">{item.publisher || 'Издатель неизвестен'}</div>
                {(item.product_id || item.installed_on || item.install_dir) && <details className="mt-1 text-text-secondary"><summary className="cursor-pointer">Данные установки</summary>
                  <p>Установлено: {item.installed_on || 'неизвестно'}</p>{item.product_id && <p className="break-all">Идентификатор: {item.product_id}</p>}{item.install_dir && <p className="break-all">Путь: {item.install_dir}</p>}
                </details>}
              </td>
              <td className="break-all p-2 font-mono">{item.version.trim() || 'Не указана'}</td>
              <td className="p-2" title={NOTES[item.coverage]}>{LABELS[item.coverage]}</td>
            </tr>)}</tbody>
          </table></div>}
        <Pager label="Страницы ПО" offset={softwareOffset} total={data.software.total} busy={busy} onChange={(offset) => setSoftwarePage({ q, filter, offset })} />
      </section>
    </>}
  </section>
}
