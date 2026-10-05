import { useMemo, useState } from 'react'
import { FileQuestion, FileWarning, Search, ShieldQuestion } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { usePolicySettings } from '@/modules/ksc/api/queries'
import type { DescribedSetting, OtherSetting, PolicyCard, SettingsComponentGroup } from '@/modules/ksc/api/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { Link } from '@/lib/router'
import { PartialNote } from '../objects/ObjectsParts'
import { LockMark } from './RawTab'

function SettingRow({ s }: { s: DescribedSetting }) {
  return (
    <tr className="border-t border-grid align-top">
      <td className="py-1.5 pr-3 pl-3 text-text" title={`${s.section} · ${s.path}`}>{s.title}</td>
      <td className="py-1.5 pr-3 break-words text-text" title={s.raw}>
        {s.value}
        {!s.verified && <span className="ml-2 text-[11px] whitespace-nowrap text-text-secondary italic" title="значение показано кодом: подпись не подтверждена">код не расшифрован</span>}
      </td>
      <td className="py-1.5 pr-3 whitespace-nowrap"><LockMark locked={s.locked} /></td>
    </tr>
  )
}

function GroupBlock({ group }: { group: SettingsComponentGroup }) {
  return (
    <details className="rounded border border-grid bg-surface" open>
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-text select-none">
        {group.title}{' '}
        <span className="font-normal text-text-secondary">
          {group.enabled !== null && <><span className={group.enabled ? 'text-kind-accepted' : 'text-risk-high'}>{group.enabled ? 'включён' : 'выключен'}</span> · </>}
          настроек {group.settings.length}
        </span>
      </summary>
      <table className="w-full table-fixed text-xs">
        <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          <tr>
            <th className="w-1/2 py-1 pr-3 pl-3 text-left">Настройка</th>
            <th className="py-1 pr-3 text-left">Значение</th>
            <th className="w-16 py-1 pr-3 text-left">Замок</th>
          </tr>
        </thead>
        <tbody>
          {group.settings.map((s) => <SettingRow key={`${s.section}|${s.path}`} s={s} />)}
        </tbody>
      </table>
    </details>
  )
}

/** «Прочее»: настройки, которые словарь не распознал, в техническом виде; свёрнуто. */
function OtherBlock({ items }: { items: OtherSetting[] }) {
  return (
    <details className="rounded border border-grid bg-surface">
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-text select-none">
        Прочее <span className="font-normal text-text-secondary">— не распознано словарём, технический вид · настроек {items.length}</span>
      </summary>
      <table className="w-full table-fixed text-xs">
        <thead className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          <tr>
            <th className="w-1/2 py-1 pr-3 pl-3 text-left">Секция · путь</th>
            <th className="py-1 pr-3 text-left">Значение</th>
            <th className="w-16 py-1 pr-3 text-left">Замок</th>
          </tr>
        </thead>
        <tbody>
          {items.map((s) => (
            <tr key={`${s.section}|${s.path}`} className="border-t border-grid align-top">
              <td className="py-1.5 pr-3 pl-3 font-mono break-all text-text"><span className="text-text-secondary">{s.section} · </span>{s.path}</td>
              <td className="py-1.5 pr-3 font-mono break-all text-text">{s.value}</td>
              <td className="py-1.5 pr-3 whitespace-nowrap"><LockMark locked={s.locked} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}

/**
 * Вкладка «Настройки»: содержимое политики по компонентам защиты человеческим языком (словарь продукта), нераспознанное — в «Прочее».
 * «Не собрано» (нет содержимого) и «словаря нет» отличаются от «настроек нет».
 */
export function SettingsTab({ serverId, snapshotId, policy }: { serverId: number; snapshotId: number; policy: PolicyCard }) {
  const settings = usePolicySettings(snapshotId, policy.id, policy.has_contents)
  const [onlyUnlocked, setOnlyUnlocked] = useState(false)
  const [query, setQuery] = useState('')
  const q = useDebouncedValue(query, 200).trim().toLowerCase()

  const filtered = useMemo(() => {
    if (!settings.data) return { groups: [], other: [] }
    const keep = (s: { path: string; value: string; locked: boolean | null }, title = '') =>
      // «Незамкнутые» — замок явно снят (`false`); `null` — признак замка не пришёл, это не «без замка».
      (!onlyUnlocked || s.locked === false) && (!q || title.toLowerCase().includes(q) || s.path.toLowerCase().includes(q) || s.value.toLowerCase().includes(q))
    return {
      groups: settings.data.groups.map((g) => ({ ...g, settings: g.settings.filter((s) => keep(s, s.title)) })).filter((g) => g.settings.length > 0),
      other: settings.data.other.filter((s) => keep(s)),
    }
  }, [settings.data, onlyUnlocked, q])

  if (!policy.has_contents) {
    return <EmptyState icon={FileWarning} title="Содержимое политики не собрано" description="Без содержимого настройки не показываются; это не значит, что их нет. Причина, если пришла, — в ошибках сбора в шапке карточки." />
  }
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) {
    const msg = settings.error instanceof ApiRequestError ? settings.error.message : 'Не удалось загрузить настройки политики'
    return <ErrorState message={msg} onRetry={() => settings.refetch()} />
  }
  const data = settings.data
  const rawLink = `/ksc/servers/${serverId}/policies/${policy.id}?tab=raw`

  if (!data.described) {
    return (
      <div className="flex flex-col items-center">
        <EmptyState icon={FileQuestion} title="Структура продукта не описана" description={`Для продукта ${policy.product} нет словаря настроек: показать их человеческим языком нельзя. Все настройки политики в техническом виде — на вкладке «Все поля».`} />
        <Link to={rawLink} className="text-xs text-primary hover:underline">открыть «Все поля»</Link>
      </div>
    )
  }
  if (data.total === 0) return <EmptyState icon={ShieldQuestion} title="Настроек нет" description="Содержимое политики собрано, но настроек в нём нет." />

  const nothing = filtered.groups.length === 0 && filtered.other.length === 0
  return (
    <>
      {policy.contents_partial && <PartialNote />}
      <p className="mb-3 text-xs text-text-secondary">
        Распознано словарём <span className="font-mono tabular-nums text-text">{data.known}</span> из <span className="font-mono tabular-nums text-text">{data.total}</span> настроек;
        остальные — в «Прочее». Технический путь — во всплывающей подсказке названия, значение как есть — у значения.
      </p>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <label className="relative flex items-center">
          <Search size={13} className="pointer-events-none absolute left-2 text-text-secondary" aria-hidden />
          <input
            className="w-64 rounded border border-border bg-app-bg py-1.5 pr-2 pl-7 text-xs text-text placeholder:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            placeholder="название, путь или значение"
            aria-label="Поиск настроек"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs text-text">
          <input type="checkbox" className="accent-primary" checked={onlyUnlocked} onChange={(e) => setOnlyUnlocked(e.target.checked)} />
          <span>только незамкнутые</span>
        </label>
      </div>
      {nothing ? (
        <EmptyState icon={ShieldQuestion} title="Ничего не найдено" description="Измените поиск или фильтр." />
      ) : (
        <div className="flex flex-col gap-2">
          {filtered.groups.map((g) => <GroupBlock key={g.component} group={g} />)}
          {filtered.other.length > 0 && <OtherBlock items={filtered.other} />}
        </div>
      )}
    </>
  )
}
