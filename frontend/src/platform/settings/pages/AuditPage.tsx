import { useState } from 'react'
import { ChevronLeft, ChevronRight, Download, ScrollText } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Button } from '@/components/ui/Button'
import { auditCsvUrl, useAudit, useUsers } from '@/platform/settings/api/queries'
import { FiltersButton, FilterChips, type FilterChip } from '@/platform/filters/FiltersBar'
import { useFiltersPanel } from '@/platform/filters/useFiltersPanel'
import { ROLE_TITLES, type AuditFilters } from '@/platform/settings/api/types'

const PAGE_SIZE = 50

const CELL = 'py-1.5 pr-3 align-top'

/** Поле `datetime-local` даёт местное время без зоны — в API уходит UTC. */
function toIso(local: string): string | undefined {
  return local === '' ? undefined : new Date(local).toISOString()
}

function localLabel(local: string): string {
  return new Date(local).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/**
 * Журнал действий: кто, когда и что менял, и кому отказали в правах.
 * Записи только читаются — ни на этом экране, ни в API их нельзя
 * поправить или удалить поштучно, иначе журналу незачем верить.
 */
export function AuditPage() {
  const users = useUsers()

  const [userId, setUserId] = useState('')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const [deniedOnly, setDeniedOnly] = useState(false)
  const [page, setPage] = useState(1)
  const filtersPanel = useFiltersPanel('settings-audit')

  const filters: AuditFilters = {
    user_id: userId === '' ? undefined : Number(userId),
    since: toIso(since),
    until: toIso(until),
    denied_only: deniedOnly ? true : undefined,
    page,
    page_size: PAGE_SIZE,
  }
  const audit = useAudit(filters)

  /** Любая правка отбора возвращает на первую страницу: иначе человек
   *  меняет фильтр и попадает на пустую седьмую. */
  function change(apply: () => void) {
    setPage(1)
    apply()
  }

  // Что выбрано, пока отбор свёрнут.
  const chips: FilterChip[] = []
  if (userId !== '') {
    const u = users.data?.find((x) => String(x.id) === userId)
    chips.push({ label: `пользователь ${u ? (u.display_name ? `${u.display_name} (${u.login})` : u.login) : `#${userId}`}`, clear: () => change(() => setUserId('')) })
  }
  if (since !== '') chips.push({ label: `с ${localLabel(since)}`, clear: () => change(() => setSince('')) })
  if (until !== '') chips.push({ label: `по ${localLabel(until)}`, clear: () => change(() => setUntil('')) })
  if (deniedOnly) chips.push({ label: 'только отказы', clear: () => change(() => setDeniedOnly(false)) })

  const total = audit.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Журнал действий</h1>
            <FiltersButton open={filtersPanel.open} onToggle={filtersPanel.toggle} count={chips.length} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Изменяющие запросы и отказы по правам. Записи хранятся столько, сколько задано в
            разделе «Безопасность».
          </p>
        </div>
        <a
          href={auditCsvUrl(filters)}
          download
          className="inline-flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm font-medium text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
        >
          <Download size={14} aria-hidden />
          Скачать CSV
        </a>
      </div>

      {!filtersPanel.open && chips.length > 0 && <div className="mb-4 flex"><FilterChips chips={chips} /></div>}
      {filtersPanel.open && (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Пользователь">
            <select
              className={FIELD}
              value={userId}
              onChange={(e) => change(() => setUserId(e.target.value))}
            >
              <option value="">все</option>
              {(users.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.display_name ? `${u.display_name} (${u.login})` : u.login}
                </option>
              ))}
            </select>
          </Field>
          <Field label="С">
            <input
              className={FIELD}
              type="datetime-local"
              value={since}
              onChange={(e) => change(() => setSince(e.target.value))}
            />
          </Field>
          <Field label="По">
            <input
              className={FIELD}
              type="datetime-local"
              value={until}
              onChange={(e) => change(() => setUntil(e.target.value))}
            />
          </Field>
          <label className="flex items-end gap-2 pb-2 text-xs text-text">
            <input
              type="checkbox"
              checked={deniedOnly}
              onChange={(e) => change(() => setDeniedOnly(e.target.checked))}
            />
            <span>Только отказы</span>
          </label>
        </div>
      )}

      {audit.isError ? (
        <ErrorState
          message={audit.error?.message ?? 'Не удалось загрузить журнал'}
          onRetry={() => audit.refetch()}
        />
      ) : !audit.data ? (
        <FullPageSpinner />
      ) : audit.data.items.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="Записей нет"
          description="Под выбранный отбор не попало ни одного события. Снимите фильтры или расширьте период."
        />
      ) : (
        <>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
                <th className={`${CELL} font-medium`}>Время</th>
                <th className={`${CELL} font-medium`}>Пользователь</th>
                <th className={`${CELL} font-medium`}>Запрос</th>
                <th className={`${CELL} font-medium`}>Код</th>
                <th className={`${CELL} font-medium`}>IP</th>
                <th className="py-2 font-medium">Сводка</th>
              </tr>
            </thead>
            <tbody>
              {audit.data.items.map((e) => (
                <tr key={e.id} className="border-b border-grid hover:bg-row-hover">
                  <td className={`${CELL} tabular-nums whitespace-nowrap text-text-secondary`}>
                    {new Date(e.at).toLocaleString('ru-RU')}
                  </td>
                  <td className={CELL}>
                    <div className="text-text">{e.login}</div>
                    {e.role && (
                      <div className="text-[11px] text-text-secondary">{ROLE_TITLES[e.role]}</div>
                    )}
                  </td>
                  <td className={`${CELL} font-mono text-text`}>
                    <span className="text-text-secondary">{e.method}</span> {e.path}
                  </td>
                  <td
                    className={`${CELL} font-mono tabular-nums ${e.status === 403 ? 'text-kind-1' : 'text-text'}`}
                  >
                    {e.status}
                  </td>
                  <td className={`${CELL} font-mono text-text-secondary`}>{e.ip ?? '—'}</td>
                  <td className="py-1.5 text-text-secondary">{e.summary ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="mt-3 flex items-center gap-2">
            <Button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
              <ChevronLeft size={14} aria-hidden />
              Назад
            </Button>
            <Button disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
              Вперёд
              <ChevronRight size={14} aria-hidden />
            </Button>
            <span className="text-xs text-text-secondary">
              {page} из {pages} · всего {total}
            </span>
          </div>
        </>
      )}
    </div>
  )
}
