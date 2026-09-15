import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Download,
  List,
  Pencil,
  Play,
  Scale,
  Settings2,
  X,
} from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import {
  attackLayerUrl,
  useAttackCoverage,
  useAttackGroupDetail,
  useAttackGroups,
  useJobStatus,
  useRunAttack,
} from '@/modules/siem/api/queries'
import type { AttackGroup, AttackStatus } from '@/modules/siem/api/types'
import { tacticLabel } from '@/modules/siem/api/types'
import { AttackStateBadge, attackDisplayState } from '@/modules/attack/components/AttackStateBadge'
import { ConfidenceBadge } from '@/modules/siem/components/ui/ConfidenceBadge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ReplacementNotice } from '@/modules/attack/components/ReplacementNotice'
import { RuleList } from '@/modules/siem/components/attack/RuleList'
import { TechniquePicker } from '@/modules/siem/components/attack/TechniquePicker'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { ReferenceView } from './attack/ReferenceView'
import { cn } from '@/lib/cn'

const FILTERS: { key: AttackStatus | 'all'; label: string }[] = [
  { key: 'all', label: 'Все' },
  { key: 'suggested', label: 'Предложено моделью' },
  { key: 'confirmed', label: 'Подтверждено' },
  { key: 'unmapped', label: 'Не размечено' },
]

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded border border-grid bg-surface px-3 py-2.5" title={hint}>
      <div className="text-xs text-text-secondary">{label}</div>
      <div className="mt-0.5 font-mono text-lg text-text">{value}</div>
    </div>
  )
}

export function AttackPage({ snapshotId }: { snapshotId: number }) {
  const [view, setView] = useState<'groups' | 'reference'>('groups')
  const [filter, setFilter] = useState<AttackStatus | 'all'>('all')
  //: Тактика — второй фильтр списка групп; отбор на клиенте, потому что
  //: тактики техник уже приходят вместе с группами.
  const [tactic, setTactic] = useState<string | null>(null)
  const [jobId, setJobId] = useState<number | undefined>()
  //: Итог последнего прогона: провал или предупреждение о пропусках.
  const [outcome, setOutcome] = useState<{ failed: boolean; message: string } | null>(null)

  const { admin, write } = useCan()
  const coverage = useAttackCoverage(snapshotId)
  const groups = useAttackGroups({
    snapshot_id: snapshotId,
    ...(filter === 'all' ? {} : { status: filter }),
  })
  const run = useRunAttack()
  const job = useJobStatus(jobId, { enabled: jobId !== undefined })

  const running = job.data?.status === 'running'
  const finished = jobId !== undefined && job.data?.status === 'done'
  const jobFailed = jobId !== undefined && job.data?.status === 'failed'

  // Пока задание идёт, данные на экране устарели; по завершении перечитываем.
  useEffect(() => {
    if (!finished && !jobFailed) return
    // Сообщение переживает сброс jobId: с ним запрос состояния выключается,
    // и объяснение исчезло бы вместе с ним — прогон молча кончался бы ничем.
    setOutcome(
      job.data?.error ? { failed: jobFailed, message: job.data.error } : null,
    )
    setJobId(undefined)
    if (jobFailed) return
    void coverage.refetch()
    void groups.refetch()
    // Перечитывание запускается один раз на завершение задания; сами
    // объекты запросов в зависимости не идут — они меняются на каждый рендер.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished, jobFailed, job.data?.error])

  if (coverage.isLoading) return <FullPageSpinner />
  if (coverage.isError || !coverage.data) {
    const message =
      coverage.error instanceof ApiRequestError
        ? coverage.error.message
        : 'Не удалось загрузить покрытие ATT&CK'
    return (
      <div className="p-6">
        <ErrorState message={message} onRetry={() => coverage.refetch()} />
      </div>
    )
  }

  const c = coverage.data
  const items = (groups.data?.items ?? []).filter(
    (group) => tactic === null || group.techniques.some((t) => t.tactics.includes(tactic)),
  )
  const tactics = Object.entries(c.by_tactic)

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-text">Разметка ATT&CK</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Разметка делается по правилам: правила одной группы обнаруживают разные техники.
            Группу можно разметить целиком одним движением, но для каждого правила такая
            разметка останется неуточнённой. Предложение модели и решение человека — разные
            вещи и показываются по-разному.
          </p>
          {/* Матрица общая для всех модулей: SIEM кладёт в неё слой покрытия
              правилами, VM — слой экспозиции. Смотреть её отсюда некуда — она
              живёт в своём модуле, и путь к ней должен быть виден. */}
          <Link
            to="/attack"
            className="mt-1.5 inline-block text-xs text-primary underline underline-offset-2 hover:text-text"
          >
            Матрица ATT&amp;CK со слоями всех модулей →
          </Link>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={attackLayerUrl(snapshotId)}
            download={`kbaudit-attack-${snapshotId}.json`}
            className="inline-flex items-center justify-center gap-1.5 rounded border border-border px-3 py-1.5 text-sm font-medium text-text hover:bg-row-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <Download size={14} aria-hidden />
            Слой для Navigator
          </a>
          {write && (
          <Button
            variant="primary"
            loading={run.isPending || running}
            disabled={!c.llm_configured}
            onClick={() =>
              run.mutate(
                { snapshot_id: snapshotId },
                { onSuccess: (r) => setJobId(r.job_id) },
              )
            }
            title={
              c.llm_configured
                ? 'Разметить группы, кроме уже подтверждённых человеком'
                : 'Адрес модели не задан — задайте его в настройках'
            }
          >
            <Play size={14} aria-hidden />
            {running ? 'Размечается…' : 'Разметить моделью'}
          </Button>
          )}
        </div>
      </div>

      {outcome && (
        <div
          className={cn(
            'mb-5 flex flex-wrap items-center gap-2 rounded border px-3 py-2 text-xs text-text',
            outcome.failed ? 'border-kind-1/40 bg-kind-1/5' : 'border-kind-3/40 bg-kind-3/5',
          )}
          role="status"
        >
          <AlertTriangle
            size={14}
            className={outcome.failed ? 'text-kind-1' : 'text-kind-3'}
            aria-hidden
          />
          {outcome.message}
          <button
            type="button"
            onClick={() => setOutcome(null)}
            className="ml-auto rounded px-1.5 py-0.5 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            aria-label="Скрыть сообщение"
          >
            <X size={12} aria-hidden />
          </button>
        </div>
      )}

      <ReplacementNotice className="mb-5" />

      {(c.outdated_groups > 0 || c.missing_techniques.length > 0) && (
        <div className="mb-5 flex flex-wrap items-center gap-2 rounded border border-kind-3/40 bg-kind-3/5 px-3 py-2 text-xs text-text">
          <AlertTriangle size={14} className="text-kind-3" aria-hidden />
          Матрица обновилась после разметки.
          {c.outdated_groups > 0 && ` Групп подтверждено на прежней версии: ${c.outdated_groups}.`}
          {c.missing_techniques.length > 0 &&
            ` Техник больше нет в матрице: ${c.missing_techniques.join(', ')}.`}
          {' '}Разметка сохранена — её стоит пересмотреть, а не считать неверной.
        </div>
      )}

      {!c.llm_configured && (
        <div className="mb-5 flex flex-wrap items-center gap-2 rounded border border-kind-3/40 bg-kind-3/5 px-3 py-2 text-xs text-text">
          <Settings2 size={14} className="text-kind-3" aria-hidden />
          Адрес модели не задан — предложения по разметке недоступны. Остальные разделы работают,
          а разметку можно вносить руками.
          {admin ? (
            <Link to="/settings/llm" className="underline underline-offset-2 hover:text-primary">
              Открыть настройки модели
            </Link>
          ) : (
            <span className="text-text-secondary">Адрес задаёт администратор.</span>
          )}
        </div>
      )}

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat
          label="Правил"
          value={c.rule_count}
          hint={`Единица разметки — правило. Групп: ${c.group_count}`}
        />
        <Stat
          label="Подтверждено человеком"
          value={c.confirmed}
          hint="Разметка, которую проверил аналитик"
        />
        <Stat
          label="Предложено моделью"
          value={c.suggested}
          hint="Не проверено человеком — считать фактом рано"
        />
        <Stat
          label="Не уточнено для правила"
          value={c.inherited}
          hint="Разметка досталась от группы и об этом правиле ничего не утверждает"
        />
        <Stat
          label="Техник закрыто"
          value={c.techniques_covered}
          hint={`Матрица ATT&CK ${c.attack_version}`}
        />
      </div>

      {tactics.length > 0 && (
        <section className="mb-5 rounded border border-grid bg-surface p-4">
          <h2 className="mb-3 text-sm font-semibold text-text">По тактикам</h2>
          <div className="flex flex-wrap gap-2">
            {tactics.map(([id, count]) => (
              <button
                key={id}
                type="button"
                onClick={() => setTactic((cur) => (cur === id ? null : id))}
                aria-pressed={tactic === id}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                  tactic === id
                    ? 'border-primary/60 bg-primary/10 text-text'
                    : 'border-grid text-text hover:bg-row-hover',
                )}
              >
                {tacticLabel(id)}
                <span className="font-mono text-text-secondary">{count}</span>
              </button>
            ))}
          </div>
        </section>
      )}

      <div className="mb-3 flex items-center gap-1.5 border-b border-grid">
        {([
          { key: 'groups', label: 'Разметка по группам', icon: List },
          { key: 'reference', label: 'Сверка с эталоном', icon: Scale },
        ] as const).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            onClick={() => setView(key)}
            className={cn(
              'flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
              view === key
                ? 'border-primary text-text'
                : 'border-transparent text-text-secondary hover:text-text',
            )}
            aria-current={view === key ? 'page' : undefined}
          >
            <Icon size={14} aria-hidden />
            {label}
          </button>
        ))}
      </div>

      {view === 'reference' && <ReferenceView snapshotId={snapshotId} />}

      {view === 'groups' && (
      <>
      {/* Список выглядит как второй инвентарь правил, и путать их легко.
          Единица разметки — правило. Группы остались способом разметить
          однородную пачку одним движением, но решение записывается каждому
          правилу: на сверке с ручной разметкой заказчика из 32 групп лишь
          у 14 все правила сошлись на одной технике. */}
      <p className="mb-3 text-xs text-text-secondary">
        Рабочий список разметки: {c.rule_count} правил в {c.group_count} группах.
        {c.unmapped > 0 && ` Не размечено: ${c.unmapped}.`}
        {c.inherited > 0 &&
          ` Ещё ${c.inherited} получили разметку от своей группы — для самого правила она не проверена.`}{' '}
        Группу можно разметить целиком, но уточнять придётся по правилу. Смотреть разметку
        со стороны отдельного правила —{' '}
        <Link
          to={`/siem/snapshots/${snapshotId}/rules`}
          className="underline underline-offset-2 hover:text-primary"
        >
          в инвентаре
        </Link>
        .
      </p>
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {FILTERS.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => setFilter(key)}
            className={cn(
              'rounded border px-2.5 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
              filter === key
                ? 'border-primary/60 bg-primary/10 text-text'
                : 'border-grid text-text-secondary hover:bg-row-hover hover:text-text',
            )}
            aria-pressed={filter === key}
          >
            {label}
          </button>
        ))}
        {tactic !== null && (
          <button
            type="button"
            onClick={() => setTactic(null)}
            className="inline-flex items-center gap-1 rounded border border-primary/60 bg-primary/10 px-2.5 py-1 text-xs text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            aria-label={`Снять фильтр по тактике ${tacticLabel(tactic)}`}
          >
            {tacticLabel(tactic)}
            <X size={12} aria-hidden />
          </button>
        )}
        <span className="ml-auto text-xs text-text-secondary">
          {c.model ? `модель: ${c.model}` : 'разметка моделью не запускалась'}
        </span>
      </div>

      {items.length === 0 ? (
        <EmptyState
          icon={Crosshair}
          title="Групп с такой разметкой нет"
          description={
            c.group_count === 0
              ? 'Схема именования не опознана, поэтому группы не выделены. Проверьте профиль инсталляции.'
              : tactic !== null
                ? 'В этой тактике групп с таким статусом нет. Снимите фильтр по тактике.'
                : 'Смените фильтр или запустите разметку моделью.'
          }
        />
      ) : (
        <div className="flex flex-col gap-2">
          {items.map((group) => (
            <GroupCard key={group.group} snapshotId={snapshotId} group={group} />
          ))}
        </div>
      )}
      </>
      )}
    </div>
  )
}

/**
 * Группа в списке: свёрнута до строки, раскрывается по клику.
 *
 * Сорок четыре развёрнутые группы — это экран, по которому невозможно
 * искать. Подробности читают по одной, и тогда они нужны все сразу:
 * правила с маркировкой, обоснования модели, кандидаты.
 */
function GroupCard({ snapshotId, group }: { snapshotId: number; group: AttackGroup }) {
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState(false)
  const detail = useAttackGroupDetail(open ? group.group : undefined, snapshotId)
  // Без правки карточка остаётся полной: разметка, правила, кандидаты —
  // всё это чтение, и аудитору оно нужно целиком.
  const { write } = useCan()

  return (
    <article className="rounded border border-grid bg-surface">
      <header className="flex flex-wrap items-center gap-3 px-3.5 py-2.5">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex min-w-0 flex-1 items-center gap-2 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          aria-expanded={open}
        >
          {open ? (
            <ChevronDown size={14} className="shrink-0 text-text-secondary" aria-hidden />
          ) : (
            <ChevronRight size={14} className="shrink-0 text-text-secondary" aria-hidden />
          )}
          <span className="font-mono text-sm text-text">{group.group}</span>
          <span className="text-xs text-text-secondary">{group.rule_count} правил</span>
          <AttackStateBadge state={attackDisplayState(group.status, false)} />
          {group.version_outdated && (
            <span className="text-xs text-kind-3" title="Подтверждено на прежней версии матрицы">
              прежняя версия матрицы
            </span>
          )}
          {!open && group.techniques.length > 0 && (
            <span className="min-w-0 truncate font-mono text-xs text-primary">
              {group.techniques.map((t) => t.technique_id).join(', ')}
            </span>
          )}
        </button>
        {group.reviewed_by && (
          <span className="text-xs text-text-secondary">
            {group.reviewed_by}
            {group.reviewed_at ? `, ${new Date(group.reviewed_at).toLocaleDateString('ru')}` : ''}
          </span>
        )}
        {write && !editing && (
          <Button
            variant="secondary"
            onClick={() => {
              setOpen(true)
              setEditing(true)
            }}
          >
            <Pencil size={14} aria-hidden />
            Поправить
          </Button>
        )}
      </header>

      {open && (
        <div className="border-t border-grid px-3.5 py-3">
          {editing ? (
            <TechniquePicker
              snapshotId={snapshotId}
              group={group.group}
              current={group.techniques}
              ruleCount={group.rule_count}
              onDone={() => setEditing(false)}
            />
          ) : (
            <div className="flex flex-col gap-3">
              {group.techniques.length === 0 ? (
                <p className="text-xs text-text-secondary">
                  Техники не назначены. Подтверждение с пустым списком — тоже решение: «эта
                  группа ни одной технике не соответствует» отличается от «ещё не смотрели».
                </p>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {group.techniques.map((t) => (
                    <li
                      key={t.technique_id}
                      className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1"
                    >
                      <span className="font-mono text-xs text-primary">{t.technique_id}</span>
                      <span className="text-sm text-text">{t.name_ru ?? t.name}</span>
                      {t.missing && (
                        <span className="text-xs text-kind-1" title="Нет в действующей матрице">
                          нет в матрице
                        </span>
                      )}
                      {t.moved_from && (
                        <span
                          className="text-xs text-kind-3"
                          title={`MITRE отозвала ${t.moved_from} и перенесла её сюда. В разметке сохранено ваше подтверждение — при следующем подтверждении она запишется по новому идентификатору.`}
                        >
                          перенесена из {t.moved_from}
                        </span>
                      )}
                      {t.tactics.map((tactic) => (
                        <span key={tactic} className="text-xs text-text-secondary">
                          {tacticLabel(tactic)}
                        </span>
                      ))}
                      {t.confidence && <ConfidenceBadge confidence={t.confidence} />}
                      {t.source === 'manual' && (
                        <span className="text-xs text-kind-accepted">выбрано человеком</span>
                      )}
                      {t.evidence && (
                        <span className="w-full text-xs text-text-secondary">{t.evidence}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              <div>
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold tracking-wide text-text-secondary uppercase">
                    Правила группы
                  </span>
                  {detail.data && detail.data.unparsed > 0 && (
                    <span className="text-xs text-kind-2">
                      не разобрано: {detail.data.unparsed}
                    </span>
                  )}
                  {detail.data && detail.data.with_findings > 0 && (
                    <span className="text-xs text-kind-3">
                      с замечаниями: {detail.data.with_findings}
                    </span>
                  )}
                </div>
                {detail.isLoading && (
                  <span className="text-xs text-text-secondary">загрузка правил…</span>
                )}
                {detail.data && (
                  <RuleList snapshotId={snapshotId} rules={detail.data.rules} />
                )}
              </div>

              {group.candidates.length > 0 && (
                <details>
                  <summary className="cursor-pointer text-xs text-text-secondary hover:text-text">
                    Кандидаты, которые видела модель ({group.candidates.length})
                  </summary>
                  <p className="mt-1.5 font-mono text-xs leading-relaxed text-text-secondary">
                    {group.candidates.join(', ')}
                  </p>
                </details>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  )
}
