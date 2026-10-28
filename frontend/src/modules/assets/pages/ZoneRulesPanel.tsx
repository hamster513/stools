import { useState } from 'react'
import { ArrowDown, ArrowUp, Pencil, Play, Plus, Trash2 } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useApplyZoneRules, useDeleteZoneRule, usePreviewZoneRule, useReorderZoneRules, useSaveZoneRule, useZoneRules, useZones } from '@/modules/assets/api/queries'
import { num, RULE_MATCH_LABELS, RULE_MATCHES, type RuleMatch, type ZoneRule, type ZoneRuleIn } from '@/modules/assets/api/types'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { FIELD } from '@/platform/collector/ui'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'

const COLUMNS: ColumnDef[] = [
  { key: 'position', label: '№', width: 48, align: 'right' },
  { key: 'match', label: 'Условие', width: 176 },
  { key: 'value', label: 'Значение', width: 200, flex: true },
  { key: 'zone', label: 'Группа', width: 140 },
  { key: 'networks', label: 'Сетей', width: 72, align: 'right' },
  { key: 'enabled', label: 'Включено', width: 88 },
  { key: 'note', label: 'Заметка', width: 200 },
]
const WRITE_COLUMNS: ColumnDef[] = [...COLUMNS, { key: 'actions', label: 'Действия', width: 136, resizable: false }]

const PLACEHOLDERS: Record<RuleMatch, string> = {
  name_prefix: 'APP_DMZ_',
  name_contains: 'DMZ',
  name_glob: 'APP_DMZ_*',
  tag: 'dmz',
  cidr: '10.10.0.0/16',
}

/** В выпадающем списке шаблон объясняется сразу: в таблице и карточке сети — короткая подпись. */
const OPTION_LABELS: Record<RuleMatch, string> = { ...RULE_MATCH_LABELS, name_glob: 'имя по шаблону: * — любые символы, ? — один символ' }

/** Подсказка под полем значения. */
function valueHint(match: RuleMatch): string {
  if (match === 'name_glob') return ' · всё имя, без учёта регистра; например APP_DMZ_* или *DMZ*'
  if (match === 'cidr') return ' · сеть внутри этого CIDR или равна ему'
  return ' · без учёта регистра'
}

const EMPTY: ZoneRuleIn = { match: 'name_prefix', value: '', zone: '', enabled: true, note: '' }

function message(error: unknown, fallback: string): string {
  return error instanceof ApiRequestError ? error.message : fallback
}

/** Правило: условие, значение, группа; «Проверить» — сколько не ручных сетей подпадёт на этом месте, до сохранения. */
function RuleForm({ rule, onDone }: { rule: ZoneRule | null; onDone: () => void }) {
  const zones = useZones()
  const save = useSaveZoneRule()
  const preview = usePreviewZoneRule()
  const [f, setF] = useState<ZoneRuleIn>(() => (rule ? { match: rule.match, value: rule.value, zone: rule.zone, enabled: rule.enabled, note: rule.note } : EMPTY))
  // Проверка — для того, что сейчас в форме: правка полей сбрасывает её результат.
  const patch = (p: Partial<ZoneRuleIn>) => { setF((v) => ({ ...v, ...p })); preview.reset() }
  const ready = f.value.trim() !== '' && f.zone !== ''
  const body = { ...f, value: f.value.trim() }
  return (
    <div className="mb-4 rounded border border-grid bg-surface p-4 text-xs">
      <div className="mb-3 text-sm font-semibold text-text">{rule ? `Правило №${rule.position}` : 'Новое правило'}</div>
      <div className="grid gap-3 sm:grid-cols-[176px_1fr_176px]">
        <label className="block">
          <span className="mb-1 block text-text-secondary">Условие</span>
          <select value={f.match} onChange={(e) => patch({ match: e.target.value as RuleMatch })} className={cn(FIELD, 'text-xs')}>
            {RULE_MATCHES.map((m) => <option key={m} value={m}>{OPTION_LABELS[m]}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="mb-1 block text-text-secondary">Значение{valueHint(f.match)}</span>
          <input value={f.value} onChange={(e) => patch({ value: e.target.value })} placeholder={PLACEHOLDERS[f.match]} maxLength={f.match === 'name_glob' ? 200 : 500} spellCheck={false} className={cn(FIELD, 'font-mono text-xs')} />
        </label>
        <label className="block">
          <span className="mb-1 block text-text-secondary">Группа сетей</span>
          <select value={f.zone} onChange={(e) => patch({ zone: e.target.value })} className={cn(FIELD, 'text-xs')}>
            <option value="">— выберите —</option>
            {(zones.data ?? []).map((z) => <option key={z.name} value={z.name}>{z.title && z.title !== z.name ? `${z.name} — ${z.title}` : z.name}</option>)}
          </select>
        </label>
        <label className="block sm:col-span-2">
          <span className="mb-1 block text-text-secondary">Заметка</span>
          <input value={f.note} onChange={(e) => setF((v) => ({ ...v, note: e.target.value }))} className={cn(FIELD, 'text-xs')} />
        </label>
        <label className="flex items-center gap-2 self-end pb-1.5 text-text">
          <input type="checkbox" className="accent-primary" checked={f.enabled} onChange={(e) => setF((v) => ({ ...v, enabled: e.target.checked }))} /> включено
        </label>
      </div>

      {preview.data && (
        <div className="mt-3 rounded border border-grid px-3 py-2">
          <div className="text-text">
            Подпадут сетей: <span className="font-mono tabular-nums">{num(preview.data.count)}</span>
            <span className="text-text-secondary"> — с учётом правил выше этого; сети с группой, выбранной вручную, не считаются{f.enabled ? '' : '; выключенное правило сетей не заберёт'}</span>
          </div>
          {preview.data.sample.length > 0 && (
            <ul className="mt-1 flex flex-col gap-0.5">
              {preview.data.sample.map((s) => (
                <li key={s.id} className="flex items-baseline gap-2">
                  <span className="font-mono text-text">{s.cidr}</span>
                  <span className="min-w-0 truncate text-text-secondary">{s.title}</span>
                  <span className="ml-auto shrink-0 text-text-secondary">сейчас: {s.zone_before ?? 'без группы'}</span>
                </li>
              ))}
              {preview.data.count > preview.data.sample.length && <li className="text-text-secondary">и ещё {num(preview.data.count - preview.data.sample.length)}</li>}
            </ul>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button disabled={!ready} loading={preview.isPending} onClick={() => preview.mutate({ match: body.match, value: body.value, zone: body.zone, position: rule?.position })}>Проверить</Button>
        <Button variant="primary" disabled={!ready} loading={save.isPending} onClick={() => save.mutate({ id: rule?.id, body }, { onSuccess: onDone })}>Сохранить</Button>
        <Button variant="ghost" onClick={onDone}>Отмена</Button>
        {preview.error && <span className="text-kind-1">{message(preview.error, 'Проверка не удалась')}</span>}
        {save.error && <span className="text-kind-1">{message(save.error, 'Правило не сохранено')}</span>}
      </div>
    </div>
  )
}

function ConfirmDelete({ rule, onDone }: { rule: ZoneRule; onDone: () => void }) {
  const remove = useDeleteZoneRule()
  return (
    <div role="dialog" aria-label="Удалить правило" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded border border-grid bg-surface p-4">
        <div className="mb-2 text-sm font-semibold text-text">Удалить правило №{rule.position}?</div>
        <p className="mb-4 text-xs text-text-secondary">Его сети ({num(rule.networks)}) пересчитаются по остальным правилам; номера правил ниже сдвинутся.</p>
        {remove.error && <p className="mb-2 text-xs text-kind-1">{message(remove.error, 'Не удалось удалить')}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onDone}>Отмена</Button>
          <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(rule.id, { onSuccess: onDone })}>Удалить</Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Вкладка «Правила групп» страницы сетей (спека §4): правила по порядку, срабатывает первое включённое подошедшее;
 * группу, выбранную у сети вручную, правила не трогают. Любая правка правил пересчитывает группы сразу.
 */
export function ZoneRulesPanel() {
  const { admin } = useCan()
  const rules = useZoneRules()
  const zones = useZones()
  const reorder = useReorderZoneRules()
  const apply = useApplyZoneRules()
  // undefined — форма закрыта, null — новое правило, иначе изменяемое.
  const [editing, setEditing] = useState<ZoneRule | null | undefined>(undefined)
  const [deleting, setDeleting] = useState<ZoneRule | null>(null)
  const cols = useColumnWidths('assets-zone-rules-columns', admin ? WRITE_COLUMNS : COLUMNS)

  if (rules.isLoading) return <FullPageSpinner />
  if (rules.isError || !rules.data) return <div className="p-6"><ErrorState message={message(rules.error, 'Не удалось загрузить правила')} onRetry={() => rules.refetch()} /></div>
  const list = rules.data
  const zoneTitle = (name: string) => {
    const z = zones.data?.find((x) => x.name === name)
    return z?.title && z.title !== name ? `${name} — ${z.title}` : name
  }
  function move(index: number, by: -1 | 1) {
    const ids = list.map((r) => r.id)
    ;[ids[index], ids[index + by]] = [ids[index + by], ids[index]]
    reorder.mutate(ids)
  }

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="mb-3 flex flex-wrap items-start gap-3">
        <p className="max-w-3xl text-xs text-text-secondary">
          Правило относит сеть к группе по имени, тегу RackTables или адресу. Правила проверяются по порядку, срабатывает первое
          включённое подошедшее; группу, выбранную у сети вручную, правила не трогают. Публичные сети RackTables без правила — в External.
          Группы и их признаки (расположение, доступ из интернета) — в <Link to="/settings/assets#zones" className="text-primary hover:underline">настройках модуля</Link>.
        </p>
        {admin && (
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {apply.data && !apply.isPending && <span className="text-xs text-text-secondary">изменено сетей: {num(apply.data.changed)}</span>}
            {apply.error && <span className="text-xs text-kind-1">{message(apply.error, 'Не удалось применить')}</span>}
            <Button loading={apply.isPending} onClick={() => apply.mutate()} title="Пересчитать группы всех сетей, кроме выбранных вручную"><Play size={13} aria-hidden /> Применить правила</Button>
            {editing === undefined && <Button onClick={() => setEditing(null)}><Plus size={13} aria-hidden /> Добавить правило</Button>}
          </div>
        )}
      </div>

      {editing !== undefined && <RuleForm key={editing?.id ?? 'new'} rule={editing} onDone={() => setEditing(undefined)} />}
      {reorder.error && <p className="mb-2 text-xs text-kind-1">{message(reorder.error, 'Порядок не изменён')}</p>}

      {list.length === 0 ? (
        <EmptyState icon={Plus} title="Правил ещё нет" description="Без правил группу сети выбирают вручную в её карточке; публичные сети RackTables попадают в External." />
      ) : (
        <div className="overflow-x-auto rounded border border-grid bg-surface">
          <table className="w-full text-xs" style={cols.tableStyle}>
            <ColGroup cols={cols} />
            <thead className="text-[11px] tracking-wide text-text-secondary uppercase">
              <tr className="border-b border-grid"><ResizableHeader cols={cols} className="px-3 py-2" content={{ actions: <span className="sr-only">Действия</span> }} /></tr>
            </thead>
            <tbody>
              {list.map((r, i) => (
                <tr key={r.id} className={cn('border-t border-grid align-top', !r.enabled && 'opacity-60')}>
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{r.position}</td>
                  <td className="truncate px-3 py-2 text-text" title={RULE_MATCH_LABELS[r.match]}>{RULE_MATCH_LABELS[r.match] ?? r.match}</td>
                  <td className="px-3 py-2 font-mono break-all text-text">{r.value}</td>
                  <td className="truncate px-3 py-2 text-text" title={zoneTitle(r.zone)}>{zoneTitle(r.zone)}</td>
                  <td className="px-3 py-2 text-right font-mono tabular-nums text-text-secondary">{num(r.networks)}</td>
                  <td className="px-3 py-2 text-text-secondary">{r.enabled ? 'да' : 'выключено'}</td>
                  <td className="px-3 py-2 break-words text-text-secondary">{r.note || '—'}</td>
                  {admin && (
                    <td className="px-3 py-1.5">
                      <div className="flex items-center justify-end gap-0.5">
                        <Button variant="ghost" className="px-1.5" disabled={i === 0 || reorder.isPending} onClick={() => move(i, -1)} aria-label={`Поднять правило №${r.position}`}><ArrowUp size={13} aria-hidden /></Button>
                        <Button variant="ghost" className="px-1.5" disabled={i === list.length - 1 || reorder.isPending} onClick={() => move(i, 1)} aria-label={`Опустить правило №${r.position}`}><ArrowDown size={13} aria-hidden /></Button>
                        <Button variant="ghost" className="px-1.5" onClick={() => setEditing(r)} aria-label={`Изменить правило №${r.position}`}><Pencil size={13} aria-hidden /></Button>
                        <Button variant="ghost" className="px-1.5" onClick={() => setDeleting(r)} aria-label={`Удалить правило №${r.position}`}><Trash2 size={13} aria-hidden /></Button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {deleting && <ConfirmDelete rule={deleting} onDone={() => setDeleting(null)} />}
    </div>
  )
}
