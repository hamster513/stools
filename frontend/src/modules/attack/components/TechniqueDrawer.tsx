import { useEffect, useRef } from 'react'
import { X } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useAttackTechniqueDetail } from '@/modules/attack/api/queries'
import {
  ruWords,
  tacticLabel,
  type AttackSubtechnique,
  type LayerMeta,
} from '@/modules/attack/api/types'
import { plural } from '@/modules/attack/lib/plural'
import { AttackStateBadge, attackDisplayState } from '@/modules/attack/components/AttackStateBadge'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { tint } from '@/lib/tint'

const LEVEL_WORD = ['', 'редко', 'заметно', 'часто', 'очень часто']

/** Подсказка словами: цвет никогда не единственный носитель смысла. */
function describeSub(s: AttackSubtechnique): string {
  if (s.covered) return `${s.technique_id} — закрыта правилом`
  if (s.level === 0) return `${s.technique_id} — данных о распространённости нет`
  const parts = [`применяют ${LEVEL_WORD[s.level]}`]
  if (s.actor_groups > 0) parts.push(`группировок: ${s.actor_groups}`)
  parts.push(s.sightings > 0 ? `наблюдений: ${s.sightings}` : 'сенсорами не замечена')
  if (s.ru) parts.push(ruWords(s.ru))
  return `${s.technique_id} — ${parts.join(', ')}`
}

/**
 * Подробности техники сбоку.
 *
 * Ячейка матрицы отвечает только на вопрос «закрыто или нет». Дальше
 * человеку нужно другое: что это за техника, что внутри неё осталось
 * незакрытым и что о ней говорит каждый модуль — какие правила её ловят,
 * на каких узлах её есть чем выполнить.
 */
export function TechniqueDrawer({
  techniqueId,
  layers,
  onClose,
}: {
  techniqueId: string | null
  /** Описания слоёв берутся из уже загруженной матрицы. */
  layers: LayerMeta[]
  onClose: () => void
}) {
  const open = techniqueId !== null
  const { data, isLoading, isError, error } = useAttackTechniqueDetail(techniqueId ?? undefined)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open, techniqueId])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    if (open) document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  return (
    <>
      <div
        className={cn(
          'fixed inset-0 z-30 bg-black/50 transition-opacity duration-200',
          open ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
        onClick={onClose}
        aria-hidden
      />
      <aside
        role="dialog"
        aria-label="Подробности техники"
        aria-hidden={!open}
        className={cn(
          'fixed top-0 right-0 z-40 flex h-full w-full max-w-[min(720px,92vw)] flex-col',
          'border-l border-grid bg-surface transition-transform duration-200',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        <div className="flex items-center gap-2 border-b border-grid px-4 py-3">
          <span className="font-mono text-xs text-primary">{techniqueId}</span>
          <span className="min-w-0 truncate text-sm text-text">
            {data?.name_ru ?? data?.name ?? '…'}
          </span>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="ml-auto rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            aria-label="Свернуть (Esc)"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-4">
          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-text-secondary">
              <Spinner size={14} /> загрузка техники…
            </div>
          )}
          {isError && (
            <p className="text-xs text-kind-1">
              {error instanceof ApiRequestError ? error.message : 'Не удалось загрузить технику'}
            </p>
          )}

          {data && (
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2">
                {data.tactics.map((t) => (
                  <span
                    key={t}
                    className="rounded border border-grid px-1.5 py-0.5 text-xs text-text-secondary"
                  >
                    {tacticLabel(t)}
                  </span>
                ))}
                {data.name_ru && <span className="text-xs text-text-secondary">{data.name}</span>}
              </div>

              {/* Разрыв называется словами и до всех подробностей: ради
                  него карточку и открывают. */}
              {data.gap && (
                <div className="rounded border border-actor/50 bg-actor/10 px-2.5 py-2 text-xs">
                  Разрыв: техника доступна атакующему по данным модулей, а правил
                  детектирования нет.
                </div>
              )}

              {data.description_ru && (
                <div>
                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Что это за техника
                  </div>
                  <p className="text-xs leading-relaxed text-text">{data.description_ru}</p>
                </div>
              )}

              {data.subtechniques.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Подтехники ({data.subtechniques.filter((s) => s.covered).length} из{' '}
                    {data.subtechniques.length} закрыто)
                  </div>

                  {/* Отсортированы по распространённости, а не по номеру:
                      разбираться человек начинает с того, что чаще
                      применяют, а не с того, что MITRE занумеровала первым. */}
                  <ul className="flex flex-col gap-0.5">
                    {data.subtechniques.map((s) => (
                      <li
                        key={s.technique_id}
                        className="flex items-baseline gap-2 rounded px-1 py-0.5 text-xs"
                        style={
                          s.covered || s.level === 0
                            ? undefined
                            : { backgroundColor: tint('var(--color-actor)', [0, 6, 12, 20, 32][s.level]) }
                        }
                        title={describeSub(s)}
                      >
                        <span
                          className={cn('font-mono', s.covered ? 'text-primary' : 'text-text-secondary')}
                        >
                          {s.technique_id}
                        </span>
                        <span className={s.covered ? 'text-text' : 'text-text-secondary'}>
                          {s.name_ru ?? s.name}
                        </span>
                        {s.ru && (
                          <span className="font-mono text-[9px] font-semibold text-kind-2">РФ</span>
                        )}
                        <span className="ml-auto shrink-0 whitespace-nowrap text-[11px]">
                          {s.covered ? (
                            <span className="text-kind-accepted">закрыта</span>
                          ) : s.level > 0 ? (
                            <span className="text-text-secondary">
                              {LEVEL_WORD[s.level]}
                              {s.actor_groups > 0 && ` · ${s.actor_groups} гр.`}
                            </span>
                          ) : (
                            <span className="text-text-secondary">данных нет</span>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {data.ru_procedures.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Как это делают здесь
                  </div>
                  {/* Процедуры с командой идут первыми: непокрытой технике
                      это готовый материал для правила, а не справка о том,
                      что бывает. Источник — загруженная выгрузка, и мнение
                      это чужое: подписано, а не выдано за факт продукта. */}
                  <ul className="flex flex-col gap-1.5">
                    {data.ru_procedures.map((p, index) => (
                      <li
                        key={`${p.technique_id}-${index}`}
                        className="rounded border border-grid bg-surface px-2 py-1.5 text-xs"
                      >
                        <div className="flex flex-wrap items-baseline gap-x-2">
                          <span className="font-mono text-[11px] text-text-secondary">
                            {p.technique_id}
                          </span>
                          <span className="text-text">{p.procedure}</span>
                        </div>
                        {p.command_line && (
                          <pre className="mt-1 overflow-x-auto rounded bg-app-bg px-2 py-1 font-mono text-[11px] text-text">
                            {p.command_line}
                          </pre>
                        )}
                        {[...p.actors, ...p.malware, ...p.tools].length > 0 && (
                          <div className="mt-1 text-[11px] text-text-secondary">
                            {[...p.actors, ...p.malware, ...p.tools].join(', ')}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Что говорит о технике каждый модуль. Слой без данных
                  показывается наравне с заполненным: «модуль об этом
                  молчит» — такой же ответ, и прятать его значит оставлять
                  человека гадать, спрашивали модуль или нет. */}
              {layers.map((l) => {
                const cell = data.layers[l.id]
                return (
                  <div key={l.id}>
                    <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                      {l.title}
                    </div>
                    {!l.available ? (
                      <p className="text-xs text-text-secondary">{l.note ?? 'данных нет'}</p>
                    ) : !cell ? (
                      <p className="text-xs text-text-secondary">
                        {l.kind === 'coverage'
                          ? 'Ни одна группа правил не закрывает эту технику.'
                          : 'Экспозиции по этому слою нет.'}
                      </p>
                    ) : (
                      <>
                        <div className="mb-1 text-xs text-text">
                          {plural(cell.count, l.unit)}
                          {cell.status && (
                            <> · <AttackStateBadge state={attackDisplayState(cell.status, false)} /></>
                          )}
                        </div>
                        <ul className="flex flex-col gap-0.5">
                          {(cell.items ?? []).map((i) => (
                            <li key={i.href + i.title} className="flex items-baseline gap-2 text-xs">
                              <Link
                                to={i.href}
                                className="font-mono text-primary underline-offset-2 hover:underline"
                              >
                                {i.title}
                              </Link>
                              <span className="text-text-secondary">{i.subtitle}</span>
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
