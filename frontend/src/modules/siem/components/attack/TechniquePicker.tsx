import { useState } from 'react'
import { Check, Plus, Search, X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAttackTechniques } from '@/modules/attack/api/queries'
import { useConfirmAttackGroup } from '@/modules/siem/api/queries'
import type { AttackTechniqueMapping } from '@/modules/siem/api/types'
import { tacticLabel } from '@/modules/siem/api/types'
import { Button } from '@/components/ui/Button'
import { ConfidenceBadge } from '@/modules/siem/components/ui/ConfidenceBadge'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { cn } from '@/lib/cn'

/**
 * Правка разметки группы: убрать лишнее, добавить своё, подтвердить.
 *
 * Тактику отдельно выбрать нельзя, и это не упущение: в ATT&CK тактика —
 * свойство техники, она приходит вместе с ней. Поправить тактику значит
 * выбрать другую технику.
 *
 * Правится вся группа, а не одно правило: разметка ведётся по группам,
 * и об этом сказано на самом экране — иначе человек решит, что меняет
 * одно правило, а изменит двадцать девять.
 */
export function TechniquePicker({
  snapshotId,
  group,
  ruleUuid,
  ruleName,
  current,
  ruleCount,
  onDone,
}: {
  snapshotId: number
  group: string
  /** Правится одно правило. Если не задано — правится вся группа разом. */
  ruleUuid?: string
  ruleName?: string
  current: AttackTechniqueMapping[]
  ruleCount?: number
  onDone?: () => void
}) {
  const [chosen, setChosen] = useState<AttackTechniqueMapping[]>(current)
  const [search, setSearch] = useState('')
  const query = useDebouncedValue(search, 250)
  const found = useAttackTechniques(query)
  const confirm = useConfirmAttackGroup()

  const chosenIds = new Set(chosen.map((t) => t.technique_id))
  const dirty =
    chosen.length !== current.length || current.some((t) => !chosenIds.has(t.technique_id))

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-baseline gap-2 text-xs text-text-secondary">
        {ruleUuid ? (
          <span>
            Правится разметка правила{' '}
            <span className="font-mono text-text">{ruleName ?? ruleUuid}</span>. Остальные
            правила группы <span className="font-mono">{group}</span> не затрагиваются.
          </span>
        ) : (
          /* Групповая правка осталась ради однородных пачек, но теперь она
             честно предупреждает: решение запишется каждому правилу, и для
             каждого в отдельности оно останется непроверенным. */
          <span>
            Правится разметка всей группы <span className="font-mono text-text">{group}</span>
            {ruleCount ? ` — это ${ruleCount} правил` : ''}. Каждое получит её и останется
            помеченным как «не уточнено для правила».
          </span>
        )}
        <span>Тактика следует из техники и отдельно не выбирается.</span>
      </div>

      {chosen.length === 0 ? (
        <p className="rounded border border-dashed border-grid px-2.5 py-2 text-xs text-text-secondary">
          Техник не назначено. Подтвердить пустой список — тоже решение: «эта группа ни одной
          технике не соответствует» отличается от «ещё не смотрели».
        </p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {chosen.map((t) => (
            <li
              key={t.technique_id}
              className="flex flex-wrap items-baseline gap-x-2 gap-y-1 rounded border border-grid px-2 py-1.5"
            >
              <span className="font-mono text-xs text-primary">{t.technique_id}</span>
              <span className="text-sm text-text">{t.name_ru ?? t.name}</span>
              {t.tactics.map((tactic) => (
                <span key={tactic} className="text-xs text-text-secondary">
                  {tacticLabel(tactic)}
                </span>
              ))}
              {t.confidence && <ConfidenceBadge confidence={t.confidence} />}
              {t.source === 'manual' && (
                <span className="text-xs text-kind-accepted">выбрано человеком</span>
              )}
              {t.missing && <span className="text-xs text-kind-1">нет в матрице</span>}
              <button
                type="button"
                onClick={() =>
                  setChosen((prev) => prev.filter((x) => x.technique_id !== t.technique_id))
                }
                className="ml-auto rounded p-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                aria-label={`Убрать ${t.technique_id}`}
                title="Убрать технику"
              >
                <X size={13} aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="relative">
        <Search
          size={13}
          className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-text-secondary"
          aria-hidden
        />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Найти технику по названию или T-идентификатору…"
          className="w-full rounded border border-border bg-app-bg py-1.5 pr-3 pl-8 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
        />
      </div>

      {query.trim().length > 0 && (
        <div className="max-h-56 overflow-y-auto rounded border border-grid">
          {found.isLoading && <p className="px-2.5 py-2 text-xs text-text-secondary">ищу…</p>}
          {found.data?.items.length === 0 && (
            <p className="px-2.5 py-2 text-xs text-text-secondary">
              Ничего не найдено. Ищите по русскому или английскому названию либо по коду вида
              T1059.
            </p>
          )}
          {found.data?.items.map((t) => {
            const already = chosenIds.has(t.technique_id)
            return (
              <button
                key={t.technique_id}
                type="button"
                disabled={already}
                onClick={() =>
                  setChosen((prev) => [
                    ...prev,
                    {
                      technique_id: t.technique_id,
                      name: t.name,
                      name_ru: t.name_ru,
                      tactics: t.tactics,
                      confidence: '',
                      source: 'manual',
                    },
                  ])
                }
                className={cn(
                  'flex w-full flex-wrap items-baseline gap-x-2 gap-y-0.5 px-2.5 py-1.5 text-left',
                  already
                    ? 'cursor-default opacity-40'
                    : 'hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                )}
              >
                {already ? (
                  <Check size={12} className="text-kind-accepted" aria-hidden />
                ) : (
                  <Plus size={12} className="text-text-secondary" aria-hidden />
                )}
                <span className="font-mono text-xs text-primary">{t.technique_id}</span>
                <span className="text-xs text-text">{t.name_ru ?? t.name}</span>
                {t.is_subtechnique && (
                  <span className="text-[11px] text-text-secondary">подтехника</span>
                )}
                {t.tactics.map((tactic) => (
                  <span key={tactic} className="text-[11px] text-text-secondary">
                    {tacticLabel(tactic)}
                  </span>
                ))}
              </button>
            )
          })}
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button
          variant="primary"
          loading={confirm.isPending}
          onClick={() =>
            confirm.mutate(
              ruleUuid
                ? {
                    snapshot_id: snapshotId,
                    rule_uuid: ruleUuid,
                    techniques: chosen.map((t) => t.technique_id),
                  }
                : {
                    snapshot_id: snapshotId,
                    group,
                    techniques: chosen.map((t) => t.technique_id),
                  },
              { onSuccess: () => onDone?.() },
            )
          }
        >
          <Check size={14} aria-hidden />
          Подтвердить разметку
        </Button>
        {dirty && <span className="text-xs text-text-secondary">есть несохранённые правки</span>}
        {onDone && (
          <Button variant="ghost" className="ml-auto" onClick={onDone}>
            Отмена
          </Button>
        )}
      </div>

      {confirm.isError && (
        <p className="text-xs text-kind-1">
          {confirm.error instanceof ApiRequestError
            ? confirm.error.message
            : 'Не удалось сохранить разметку'}
        </p>
      )}
    </div>
  )
}
