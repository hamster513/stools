import { useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'
import { useProfileFields } from '@/modules/siem/api/queries'
import type { FieldRole, FieldRoleSource, InstallationProfile } from '@/modules/siem/api/types'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'

const ROLE_LABEL: Record<FieldRole, string> = {
  environmental: 'средовое',
  technical: 'техническое',
  unknown: 'роль не задана',
}

//: Откуда роль. Источник важен не меньше самой роли: описанию поля
//: в таксономии выгрузки можно верить, встроенному списку инструмента —
//: с оговоркой, а решение человека всегда весомее обоих.
const SOURCE_LABEL: Record<FieldRoleSource, string> = {
  profile: 'задано здесь',
  taxonomy: 'из таксономии',
  documentation: 'по документации',
  builtin: 'встроено',
  none: '',
}

const ROLE_COLOR: Record<FieldRole, string> = {
  environmental: 'text-kind-2',
  technical: 'text-text-secondary',
  unknown: 'text-kind-3',
}

/**
 * Роли полей таксономии.
 *
 * Поле без роли не анализируется вовсе: захардкоженное в нём значение
 * проходит мимо молча. На эталонной выгрузке правила используют 123 поля,
 * а роль встроенно задана двадцати шести — то есть по умолчанию инструмент
 * смотрит в пятую часть того, что правила трогают.
 *
 * Средовое поле — то, чьё значение зависит от инсталляции: имя узла,
 * учётная запись, адрес. Литерал в нём — кандидат в замечание.
 * Техническое — то, где литерал и есть суть детекта: код события,
 * действие, тип объекта.
 */
export function FieldRolesSection({
  snapshotId,
  profile,
  environmental,
  technical,
  onChange,
}: {
  snapshotId: number
  profile: InstallationProfile
  environmental: string[]
  technical: string[]
  onChange: (next: { environmental: string[]; technical: string[] }) => void
}) {
  const fields = useProfileFields(snapshotId)
  const [search, setSearch] = useState('')
  const [onlyUnknown, setOnlyUnknown] = useState(true)
  const query = useDebouncedValue(search, 200)
  // Роль поля — решение о профиле. Аудитору остаётся её читать: сама
  // роль и её источник в строке названы словами.
  const { write } = useCan()

  const builtin = profile.field_roles_default

  const items = useMemo(() => {
    const own = new Map<string, FieldRole>()
    for (const f of environmental) own.set(f, 'environmental')
    for (const f of technical) own.set(f, 'technical')

    const needle = query.trim().toLowerCase()
    return (fields.data?.items ?? [])
      .map((i) => ({ ...i, role: own.get(i.field) ?? i.role }))
      .filter((i) => {
        if (onlyUnknown && i.role !== 'unknown' && !own.has(i.field)) return false
        if (needle && !i.field.toLowerCase().includes(needle)) return false
        return true
      })
  }, [fields.data, environmental, technical, onlyUnknown, query])

  function setRole(field: string, role: FieldRole) {
    const env = environmental.filter((f) => f !== field)
    const tech = technical.filter((f) => f !== field)
    if (role === 'environmental') env.push(field)
    if (role === 'technical') tech.push(field)
    onChange({ environmental: env, technical: tech })
  }

  const unknown = fields.data?.unknown ?? 0

  return (
    <section className="mb-4 rounded border border-grid bg-surface p-4">
      <div className="mb-1 text-xs font-semibold tracking-wide text-text-secondary uppercase">
        Роли полей таксономии
      </div>
      <p className="mb-3 max-w-3xl text-xs text-text-secondary">
        <span className="text-text">Средовое</span> поле — то, чьё значение зависит от
        инсталляции: имя узла, учётная запись, адрес. Литерал в нём считается замечанием.{' '}
        <span className="text-text">Техническое</span> — то, где литерал и есть суть детекта: код
        события, действие, тип объекта.{' '}
        <span className="text-kind-3">Поле без роли не анализируется вовсе</span>, и зашитое
        в нём значение проходит мимо молча.
        {fields.data && (
          <>
            {' '}
            Правила этой выгрузки используют {fields.data.total} полей. Роль{' '}
            <span className="text-text">{fields.data.from_taxonomy}</span> из них взята из
            описания в <span className="font-mono">taxonomy.json</span> самой выгрузки — это то,
            что вендор написал о своих полях. Не задана у{' '}
            <span className="text-kind-3">{unknown}</span>.
          </>
        )}
      </p>

      {builtin && (
        <p className="mb-3 text-[11px] text-text-secondary">
          Сверх того встроено {builtin.environmental.length} средовых и{' '}
          {builtin.technical.length} технических полей — там, где таксономия молчит.
        </p>
      )}

      <div className="mb-2 flex flex-wrap items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <Search
            size={13}
            className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary"
            aria-hidden
          />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Поиск по имени поля…"
            className="w-full rounded border border-border bg-app-bg py-1 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-text-secondary">
          <input
            type="checkbox"
            checked={onlyUnknown}
            onChange={(e) => setOnlyUnknown(e.target.checked)}
            className="accent-primary"
          />
          <span>только без роли</span>
        </label>
      </div>

      {fields.isLoading && <p className="text-xs text-text-secondary">загрузка полей…</p>}

      <div className="max-h-80 overflow-y-auto">
        <ul className="flex flex-col divide-y divide-grid/60">
          {items.map((i) => (
            <li key={i.field} className="flex items-center gap-3 py-1.5 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono text-text" title={i.field}>
                {i.field}
              </span>
              <span className="w-24 shrink-0 text-right font-mono tabular-nums text-text-secondary">
                {i.rule_count} правил
              </span>
              <span className={cn('w-32 shrink-0 text-right', ROLE_COLOR[i.role])}>
                {ROLE_LABEL[i.role]}
              </span>
              <span className="w-28 shrink-0 text-right text-[11px] text-text-secondary">
                {SOURCE_LABEL[i.source]}
              </span>
              {write && (
              <div className="flex w-56 shrink-0 justify-end gap-1">
                {(['environmental', 'technical'] as const).map((role) => (
                  <button
                    key={role}
                    type="button"
                    onClick={() => setRole(i.field, i.role === role ? 'unknown' : role)}
                    className={cn(
                      'rounded border px-1.5 py-0.5 text-[11px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                      i.role === role
                        ? 'border-primary/60 bg-primary/10 text-text'
                        : 'border-grid text-text-secondary hover:bg-row-hover hover:text-text',
                    )}
                    aria-pressed={i.role === role}
                  >
                    {ROLE_LABEL[role]}
                  </button>
                ))}
                {i.from_profile && (
                  <button
                    type="button"
                    onClick={() => setRole(i.field, 'unknown')}
                    className="rounded p-0.5 text-text-secondary hover:text-kind-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                    aria-label={`Снять роль с ${i.field}`}
                    title="Снять роль, заданную здесь"
                  >
                    <X size={12} aria-hidden />
                  </button>
                )}
              </div>
              )}
            </li>
          ))}
        </ul>
        {items.length === 0 && !fields.isLoading && (
          <p className="py-2 text-xs text-text-secondary">
            {onlyUnknown ? 'Все поля этой выгрузки имеют роль.' : 'Ничего не найдено.'}
          </p>
        )}
      </div>
    </section>
  )
}
