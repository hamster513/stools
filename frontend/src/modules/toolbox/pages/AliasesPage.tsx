import { useEffect, useMemo, useState } from 'react'
import { BookKey, Download, Lock, Search } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { aliasesExportUrl, useAliases, useForgetAlias } from '../api/queries'
import { KIND_LABELS, KIND_ORDER } from '../api/types'

const CELL = 'px-3 py-2 align-top'
// Секреты в таблицу соответствий не попадают (хранится только их отпечаток), в фильтре их нет.
const KINDS = KIND_ORDER.filter((k) => k !== 'secret')

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })
}

/**
 * Таблица соответствий «настоящее значение — псевдоним». Настоящие значения видны, поэтому аудитору
 * страница закрыта. «Забыть» — только администратору: освободившийся псевдоним может достаться
 * другому значению, и старые файлы переведутся обратно иначе.
 */
export function AliasesPage() {
  const { write } = useCan()
  if (!write) {
    return <div className="p-6"><EmptyState icon={Lock} title="Доступно аналитику и администратору" description="В таблице соответствий — настоящие значения, аудитору она не открывается." /></div>
  }
  return <AliasesTable />
}

function AliasesTable() {
  const { admin } = useCan()
  const filtersPanel = useFiltersPanel('toolbox-aliases')
  const [search, setSearch] = useState('')
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('')
  const aliases = useAliases({ q: q || undefined, kind: kind || undefined })
  const forget = useForgetAlias()

  // Поиск уходит на сервер не на каждую букву.
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 300)
    return () => clearTimeout(t)
  }, [search])

  const items = useMemo(() => aliases.data?.pages.flatMap((p) => p.items) ?? [], [aliases.data])
  const total = aliases.data?.pages[0]?.total ?? 0

  const chips: FilterChip[] = []
  if (kind) chips.push({ label: `вид: ${KIND_LABELS[kind] ?? kind}`, clear: () => setKind('') })

  function onForget(id: number) {
    if (!window.confirm('Файлы, очищенные с этим псевдонимом, перестанут переводиться обратно. Забыть?')) return
    forget.mutate(id)
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-base font-semibold text-text">Соответствия</h1>
            <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
            <div className="relative">
              <Search size={13} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-text-secondary" aria-hidden />
              <input className={cn(FIELD, 'w-64 py-1 pl-7 text-xs')} value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Значение или псевдоним" aria-label="Поиск по значению и псевдониму" spellCheck={false} />
            </div>
          </div>
          <p className="mt-1 max-w-2xl text-xs text-text-secondary">Какому настоящему значению соответствует какой псевдоним. По этой таблице работает обратный перевод.</p>
        </div>
        <a href={aliasesExportUrl()} download className="inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <Download size={14} aria-hidden />Экспорт csv
        </a>
        {!filtersPanel.open && <FilterChips chips={chips} />}
      </div>

      {filtersPanel.open && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Вид">
            <select className={FIELD} value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">все</option>
              {KINDS.map((k) => <option key={k} value={k}>{KIND_LABELS[k] ?? k}</option>)}
            </select>
          </Field>
        </div>
      )}

      {forget.error && <div role="alert" className="mb-4 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text">{forget.error.message}</div>}

      {aliases.isLoading ? (
        <FullPageSpinner />
      ) : aliases.isError || !aliases.data ? (
        <ErrorState message={aliases.error?.message ?? 'Не удалось загрузить таблицу соответствий'} onRetry={() => aliases.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState icon={BookKey} title={q || kind ? 'Ничего не найдено' : 'Таблица пуста'} description={q || kind ? 'Измените запрос или снимите фильтр.' : 'Псевдонимы появятся после первой очистки файла.'} />
      ) : (
        <>
          <div className="overflow-x-auto rounded border border-grid">
            <table className="w-full min-w-[900px] text-xs">
              <thead className="bg-surface text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                <tr>
                  <th className="px-3 py-2 text-left">Вид</th>
                  <th className="px-3 py-2 text-left">Настоящее</th>
                  <th className="px-3 py-2 text-left">Псевдоним</th>
                  <th className="px-3 py-2 text-left">Когда</th>
                  <th className="px-3 py-2 text-left">Кто</th>
                  <th className="px-3 py-2 text-left">Задание</th>
                  {admin && <th className="w-24 px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className="border-t border-grid hover:bg-row-hover">
                    <td className={cn(CELL, 'whitespace-nowrap text-text-secondary')}>{KIND_LABELS[a.kind] ?? a.kind}</td>
                    <td className={cn(CELL, 'max-w-[320px] font-mono break-all text-text')}>{a.real}</td>
                    <td className={cn(CELL, 'max-w-[320px] font-mono break-all text-text')}>{a.alias}</td>
                    <td className={cn(CELL, 'whitespace-nowrap text-text-secondary')}>{when(a.created_at)}</td>
                    <td className={cn(CELL, 'font-mono text-text-secondary')}>{a.created_by}</td>
                    <td className={cn(CELL, 'font-mono')}>
                      {a.first_job_id !== null ? <Link to={`/toolbox/scrub/${a.first_job_id}`} className="text-primary hover:underline">#{a.first_job_id}</Link> : <span className="text-text-secondary">—</span>}
                    </td>
                    {admin && (
                      <td className={cn(CELL, 'text-right')}>
                        <Button variant="danger" className="px-2 py-0.5 text-xs" onClick={() => onForget(a.id)} disabled={forget.isPending} aria-label={`Забыть псевдоним ${a.alias}`}>Забыть</Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex items-center gap-3 text-xs text-text-secondary">
            <span className="font-mono tabular-nums">{items.length} из {total}</span>
            {aliases.hasNextPage && <Button onClick={() => aliases.fetchNextPage()} loading={aliases.isFetchingNextPage}>Показать ещё</Button>}
          </div>
        </>
      )}
    </div>
  )
}
