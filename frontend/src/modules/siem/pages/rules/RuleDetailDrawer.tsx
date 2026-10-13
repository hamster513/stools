import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowRight, CheckCircle2, Pencil, X } from 'lucide-react'
import { useRuleDetail } from '@/modules/siem/api/queries'
import type { FindingKind, RuleFindingSummary } from '@/modules/siem/api/types'
import { FINDING_KIND_ADVICE, FINDING_KIND_EXPLANATION, tacticLabel } from '@/modules/siem/api/types'
import { AttackStateBadge, attackDisplayState } from '@/modules/attack/components/AttackStateBadge'
import { ConfidenceBadge } from '@/modules/siem/components/ui/ConfidenceBadge'
import { HighlightedBody } from '@/modules/siem/components/ui/HighlightedBody'
import { TechniquePicker } from '@/modules/siem/components/attack/TechniquePicker'

import { KindBadge } from '@/modules/siem/components/ui/KindBadge'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

interface RuleDetailDrawerProps {
  uuid: string | null
  snapshotId: number
  onClose: () => void
}

export function RuleDetailDrawer({ uuid, snapshotId, onClose }: RuleDetailDrawerProps) {
  const open = uuid !== null
  const { data, isLoading, isError } = useRuleDetail(uuid ?? undefined, snapshotId)
  const closeRef = useRef<HTMLButtonElement>(null)
  //: Правка разметки открывается по кнопке и закрывается сама после
  //: подтверждения — держать её раскрытой всегда значит предлагать
  //: менять то, что человек ещё не прочитал.
  const [editing, setEditing] = useState(false)
  const { write } = useCan()

  useEffect(() => {
    if (open) closeRef.current?.focus()
    setEditing(false)
  }, [open, uuid])

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
        className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')}
        onClick={onClose}
        aria-hidden
      />
      <aside
        role="dialog"
        aria-label="Детали правила"
        aria-hidden={!open}
        className={cn(
          // Ширина по экрану, а не фиксированные 520 пикселей: в карточке
          // разбираются находки, а их у одного правила бывает под сотню.
          'fixed top-0 right-0 z-40 flex h-full w-full max-w-[min(920px,92vw)] flex-col',
          'border-l border-grid bg-surface transition-transform duration-200',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        <div className="flex items-center justify-between border-b border-grid px-4 py-3">
          <div className="min-w-0 truncate font-mono text-xs text-text" title={data?.name}>
            {data?.name ?? '…'}
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            aria-label="Свернуть (Esc)"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-4">
          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-text-secondary">
              <Spinner size={14} /> загрузка правила…
            </div>
          )}
          {isError && <div className="text-xs text-kind-1">Не удалось загрузить правило.</div>}
          {data && (
            <div className="flex flex-col gap-4">
              {/* Первое, что нужно человеку: что это правило вообще ловит.
                  Берётся из локализации выгрузки — это текст, который
                  правило выдаёт при срабатывании, и он говорит о сути
                  прямее заголовка со служебным кодом. */}
              {(data.description_ru || data.title_ru) && (
                <div className="rounded border border-grid bg-app-bg px-3 py-2">
                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Что обнаруживает
                  </div>
                  {data.description_ru ? (
                    <p className="text-xs leading-relaxed whitespace-pre-line text-text">
                      {data.description_ru}
                    </p>
                  ) : (
                    <p className="text-xs text-text-secondary">
                      Описание в выгрузке не задано — есть только заголовок.
                    </p>
                  )}
                  {data.title_ru && (
                    <p className="mt-1.5 text-xs text-text-secondary">{data.title_ru}</p>
                  )}
                </div>
              )}

              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-xs">
                <dt className="text-text-secondary">Автор</dt>
                <dd className="text-text">{data.author}</dd>
                <dt className="text-text-secondary">Категория / группа</dt>
                <dd className="font-mono text-text">
                  {data.category} / {data.group}
                </dd>
                <dt className="text-text-secondary">Разбор</dt>
                <dd className="text-text">{data.parse_status === 'ok' ? 'без ошибок' : data.parse_status}</dd>
                <dt className="text-text-secondary">Ограничено списком</dt>
                <dd className="text-text">{data.scoped ? 'да' : 'нет'}</dd>
                {data.installed !== null && (
                  <>
                    <dt className="text-text-secondary">В SIEM</dt>
                    <dd className="text-text">{data.installed ? 'установлено' : 'не установлено'}</dd>
                    <dt className="text-text-secondary">Папка</dt>
                    <dd className="font-mono text-text">{data.folder_path ?? '—'}</dd>
                    <dt className="text-text-secondary">Наборы установки</dt>
                    <dd className="text-text">{data.deployment_sets.length ? data.deployment_sets.join(', ') : '—'}</dd>
                  </>
                )}
              </dl>

              {data.attack && (
                <div>
                  <div className="mb-1.5 flex items-center gap-2">
                    <span className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                      ATT&amp;CK
                    </span>
                    <AttackStateBadge state={attackDisplayState(data.attack.status, false)} />
                    {write && !editing && (
                      <button
                        type="button"
                        onClick={() => setEditing(true)}
                        className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                        title="Выбрать техники для этого правила"
                      >
                        <Pencil size={12} aria-hidden />
                        {data.attack.inherited ? 'Уточнить для правила' : 'Поправить'}
                      </button>
                    )}
                  </div>
                  {/* Унаследованная разметка ничего не утверждает об этом
                      правиле: решение принимали, глядя на группу целиком.
                      На сверке с ручной разметкой заказчика в группе
                      `DEMO/HC/002` оказалось девятнадцать разных техник
                      на двадцать одно правило — одна на всех не бывает. */}
                  {data.attack.inherited ? (
                    <div className="mb-1.5 rounded border border-kind-2/50 bg-kind-2/10 px-2 py-1.5 text-xs leading-relaxed text-text">
                      <span className="font-semibold">Разметка группы, для правила не уточнялась.</span>{' '}
                      Досталась от{' '}
                      <span className="font-mono">{data.attack.group ?? 'группы'}</span> и говорит
                      о группе целиком, а не об этом правиле.
                    </div>
                  ) : (
                    <div className="mb-1.5 text-xs text-text-secondary">
                      Выбрано для этого правила
                      {data.attack.group ? ` · группа ${data.attack.group}` : ''}
                    </div>
                  )}
                  {editing ? (
                    <TechniquePicker
                      snapshotId={snapshotId}
                      group={data.attack.group ?? ''}
                      ruleUuid={data.uuid}
                      ruleName={data.name}
                      current={data.attack.techniques}
                      onDone={() => setEditing(false)}
                    />
                  ) : data.attack.techniques.length === 0 ? (
                    <div className="text-xs text-text-secondary">техники не назначены</div>
                  ) : (
                    <ul className="flex flex-col gap-2">
                      {data.attack.techniques.map((t) => (
                        <li key={t.technique_id} className="rounded border border-grid px-2 py-1.5">
                          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                            <span className="font-mono text-xs text-primary">{t.technique_id}</span>
                            <span className="text-xs text-text">{t.name_ru ?? t.name}</span>
                            {t.confidence && <ConfidenceBadge confidence={t.confidence} />}
                          </div>
                          <div className="mt-0.5 text-xs text-text-secondary">
                            {t.tactics.map(tacticLabel).join(', ') || 'тактика не указана'}
                          </div>
                          {t.evidence && (
                            <p className="mt-1 text-xs text-text-secondary">{t.evidence}</p>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              <div>
                <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                  msgid ({data.msgids.own.length + data.msgids.inherited.length})
                </div>
                {data.msgids.own.length + data.msgids.inherited.length === 0 && (
                  <div className="text-xs text-text-secondary">
                    {data.parse_status === 'ok'
                      ? 'msgid не заданы: правило отбирает события по другим полям'
                      : 'тело не разобрано — требования к событиям неизвестны'}
                  </div>
                )}
                <ul className="flex flex-col gap-1">
                  {data.msgids.own.map((m) => (
                    <li key={`own-${m}`} className="font-mono text-xs text-text">
                      {m}
                    </li>
                  ))}
                  {/* Унаследованные показываются отдельно: правило без
                      собственных msgid всё равно требует телеметрии. */}
                  {data.msgids.inherited.map((m) => (
                    <li key={`inh-${m}`} className="font-mono text-xs text-text">
                      {m}
                      <span className="ml-1.5 text-text-secondary">← унаследован</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                  Зависимости ({data.dependencies.parents.length + data.dependencies.children.length})
                </div>
                {data.dependencies.parents.length + data.dependencies.children.length === 0 && (
                  <div className="text-xs text-text-secondary">нет</div>
                )}
                <ul className="flex flex-col gap-1">
                  {data.dependencies.parents.map((n) => (
                    <li key={`p-${n}`} className="truncate font-mono text-xs text-text-secondary" title={n}>
                      <span className="mr-1.5 text-text-secondary">родитель</span>
                      {n}
                    </li>
                  ))}
                  {data.dependencies.children.map((n) => (
                    <li key={`c-${n}`} className="truncate font-mono text-xs text-text-secondary" title={n}>
                      <span className="mr-1.5 text-text-secondary">потомок</span>
                      {n}
                    </li>
                  ))}
                </ul>
              </div>

              <FindingsSection
                snapshotId={snapshotId}
                ruleUuid={data.uuid}
                findings={data.findings}
              />

              <div>
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Тело правила
                  </span>
                  {(data.body_spans?.length ?? 0) > 0 && (
                    <span className="text-xs text-text-secondary">
                      подсвечены значения из замечаний, цвет — класс
                    </span>
                  )}
                  {/* Легенда только для неучитываемого: остальные цвета
                      совпадают со значками выше и в пояснении не нуждаются. */}
                  {data.body_spans?.some((s) => !s.counted) && (
                    <span className="inline-flex items-center gap-1 text-xs text-kind-accepted">
                      <span
                        className="rounded-[2px] px-1"
                        style={{
                          backgroundColor: 'var(--color-kind-accepted)14',
                          borderBottom: '1px dashed var(--color-kind-accepted)',
                        }}
                      >
                        значение ✓
                      </span>
                      <span>— решение принято, не учитывается</span>
                    </span>
                  )}
                </div>
                <HighlightedBody body={data.body} spans={data.body_spans ?? []} />
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}


/**
 * Находки правила, сгруппированные по классу.
 *
 * Плоский список из сотни строк «класс — поле — статус» не отвечает на
 * вопрос, что с правилом не так: одно и то же замечание повторяется
 * десятками строк, а объяснения нет вовсе. Поэтому группировка по классу,
 * объяснение словами и перечень задетых полей.
 *
 * Значения находок сюда не приходят намеренно: выгрузка — инвентарь
 * внутренней инфраструктуры, и значения отдаются только по явному
 * запросу, поштучно. Ссылка ведёт туда, где их можно раскрыть.
 */
function FindingsSection({
  snapshotId,
  ruleUuid,
  findings,
}: {
  snapshotId: number
  ruleUuid: string
  findings: RuleFindingSummary[]
}) {
  const groups = useMemo(() => {
    const byKind = new Map<FindingKind, { open: number; accepted: number; fields: Map<string, number> }>()
    for (const f of findings) {
      const g = byKind.get(f.kind) ?? { open: 0, accepted: 0, fields: new Map() }
      if (!f.counted) g.accepted += 1
      else g.open += 1
      g.fields.set(f.field, (g.fields.get(f.field) ?? 0) + 1)
      byKind.set(f.kind, g)
    }
    return [...byKind.entries()].sort((a, b) => b[1].open - a[1].open || Number(a[0]) - Number(b[0]))
  }, [findings])

  const open = findings.filter((f) => f.counted).length

  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
          Что не так с правилом
        </span>
        {findings.length > 0 && (
          <Link
            to={`/siem/snapshots/${snapshotId}/hygiene?object_uuid=${encodeURIComponent(ruleUuid)}`}
            className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            Разобрать со значениями
            <ArrowRight size={12} aria-hidden />
          </Link>
        )}
      </div>

      {findings.length === 0 ? (
        <div className="text-xs text-text-secondary">
          Замечаний нет: средовых значений, зашитых в тело, не найдено.
        </div>
      ) : (
        <>
          <p className="mb-2 text-xs text-text-secondary">
            Замечания относятся к <span className="text-text">значениям</span>, которые сравниваются
            с перечисленными полями прямо в теле правила. Поле названо, чтобы найти место в коде;
            сами значения показываются поштучно и только по запросу.
            {open > 0 && ` Открытых замечаний: ${open} из ${findings.length}.`}
          </p>
          <ul className="flex flex-col gap-2">
            {groups.map(([kind, g]) => {
              // Группа, целиком принятая как норма, — это решённый вопрос,
              // а не замечание послабее. Она и выглядеть должна иначе,
              // иначе человек снова и снова читает совет о том, что делать
              // с тем, о чём уже решено.
              const settled = g.open === 0 && g.accepted > 0
              return (
              <li
                key={kind}
                className={cn(
                  'rounded border px-2.5 py-2',
                  settled ? 'border-kind-accepted/30 bg-kind-accepted/[0.04]' : 'border-grid',
                )}
              >
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <KindBadge kind={kind} className={settled ? 'opacity-60' : undefined} />
                  {settled ? (
                    <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                      <CheckCircle2 size={13} aria-hidden />
                      Решение принято
                      <span className="font-mono text-text-secondary">
                        {g.accepted === 1 ? 'одно значение' : `значений: ${g.accepted}`}
                      </span>
                    </span>
                  ) : (
                    <span className="font-mono text-xs text-text-secondary">
                      открытых: {g.open}
                      {g.accepted > 0 && `, не учитываются: ${g.accepted}`}
                    </span>
                  )}
                </div>
                {settled ? (
                  <p className="text-xs text-text-secondary">
                    Здесь решение уже принято: значение зашито намеренно и замечанием не
                    считается. В теле правила оно подсвечено приглушённо.
                  </p>
                ) : (
                  <>
                    <p className="text-xs text-text">{FINDING_KIND_EXPLANATION[kind]}</p>
                    <p className="mt-1 text-xs text-text-secondary">{FINDING_KIND_ADVICE[kind]}</p>
                  </>
                )}
                <div className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1">
                  {[...g.fields.entries()]
                    .sort((a, b) => b[1] - a[1])
                    .map(([field, count]) => (
                      <span
                        key={field}
                        className="rounded bg-app-bg px-1.5 py-0.5 font-mono text-[11px] text-text-secondary"
                        title={`${count} значений в этом поле`}
                      >
                        {field}
                        {count > 1 && <span className="ml-1 opacity-70">×{count}</span>}
                      </span>
                    ))}
                </div>
              </li>
              )
            })}
          </ul>
        </>
      )}
    </div>
  )
}
