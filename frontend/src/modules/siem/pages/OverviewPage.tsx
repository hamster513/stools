import { useState, type ReactNode } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Copy,
  Database,
  FileCheck2,
  FileWarning,
  FileX2,
  ListFilter,
  TrendingDown,
  TrendingUp,
} from 'lucide-react'
import { useClones, useDivergences, useSnapshotSummary } from '@/modules/siem/api/queries'
import type { TableRankingEntry } from '@/modules/siem/api/types'
import { Link } from '@/lib/router'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ErrorState } from '@/components/ui/ErrorState'
import { ApiRequestError } from '@/api/client'
import { cn } from '@/lib/cn'

function tableState(t: TableRankingEntry): 'missing' | 'empty' | 'filled' {
  if (!t.exists) return 'missing'
  if (t.is_empty) return 'empty'
  return 'filled'
}

const STATE_META = {
  missing: { icon: FileX2, label: 'Нет в выгрузке', color: 'var(--color-kind-1)' },
  empty: { icon: FileWarning, label: 'Пуст', color: 'var(--color-kind-3)' },
  filled: { icon: FileCheck2, label: 'Наполнен', color: 'var(--color-kind-accepted)' },
} as const

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded border border-grid bg-surface p-4', className)}>{children}</div>
}

function CardHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-3">
      <div className="text-xs font-semibold tracking-wide text-text-secondary uppercase">{title}</div>
      <div className="mt-0.5 text-[11px] text-text-secondary">{subtitle}</div>
    </div>
  )
}

export function OverviewPage({ snapshotId }: { snapshotId: number }) {
  const summary = useSnapshotSummary(snapshotId)
  const divergences = useDivergences({ snapshot_id: snapshotId, limit: 1 })
  const clones = useClones(snapshotId)
  const [clonesOpen, setClonesOpen] = useState(false)

  if (summary.isLoading) return <FullPageSpinner />
  if (summary.isError || !summary.data) {
    const msg = summary.error instanceof ApiRequestError ? summary.error.message : 'Не удалось загрузить сводку снапшота'
    return (
      <div className="p-6">
        <ErrorState message={msg} onRetry={() => summary.refetch()} />
      </div>
    )
  }

  const s = summary.data
  const scopedShare = s.rule_count > 0 ? Math.round((s.scoped_count / s.rule_count) * 100) : 0
  const sortedTables = [...s.table_ranking].sort((a, b) => b.risk - a.risk)
  const previousId = snapshotId - 1

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between">
        <div>
          <h1 className="text-base font-semibold text-text">Обзор</h1>
          <p className="font-mono text-xs text-text-secondary">
            {s.filename} · {new Date(s.created_at).toLocaleString('ru-RU')}
          </p>
        </div>
        {!s.profile_confirmed && (
          <Link
            to={`/siem/snapshots/${snapshotId}/profile`}
            className="flex items-center gap-2 rounded border border-kind-3/40 bg-kind-3/10 px-3 py-2 text-xs text-text hover:bg-kind-3/20"
          >
            <AlertTriangle size={14} className="text-kind-3" aria-hidden />
            Профиль инсталляции не подтверждён — область действия правил не размечена
            <ArrowRight size={13} aria-hidden />
          </Link>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <Card>
          <Link to={`/siem/snapshots/${snapshotId}/clones`} className="block hover:text-primary">
            <CardHeader title="Клоны правил" subtitle="пары с высоким совпадением тела — сравнить бок о бок" />
          </Link>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-3xl tabular-nums text-text">{s.clone_count}</span>
            <span className="text-xs text-text-secondary">пар</span>
          </div>
          <button
            type="button"
            onClick={() => setClonesOpen((v) => !v)}
            className="mt-2 flex items-center gap-1 text-xs text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <Copy size={12} aria-hidden /> {clonesOpen ? 'свернуть список' : 'показать пары'}
          </button>
          {clonesOpen && (
            <ul className="mt-2 flex max-h-48 flex-col gap-1.5 overflow-y-auto border-t border-grid pt-2">
              {clones.data?.map((c, i) => (
                <li key={i} className="text-[11px]">
                  <Link
                    to={`/siem/snapshots/${snapshotId}/clones?a=${encodeURIComponent(c.rule_a)}&b=${encodeURIComponent(c.rule_b)}`}
                    className="flex items-center justify-between gap-2 rounded px-1 hover:bg-row-hover"
                    title="Сравнить бок о бок"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-text-secondary">{c.rule_a}</span>
                      <span className="block truncate font-mono text-text-secondary">{c.rule_b}</span>
                    </span>
                    <span className="shrink-0 font-mono tabular-nums text-text-secondary">{Math.round(c.similarity * 100)}%</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Link to={`/siem/snapshots/${snapshotId}/hygiene?in_table=true`} className="block">
          <Card className="h-full hover:border-border">
            <CardHeader title="Расхождения правило ↔ список" subtitle="хардкод вместо чтения табличного списка" />
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-3xl tabular-nums text-kind-1">{s.divergence_count}</span>
              <span className="text-xs text-text-secondary">
                из {s.finding_count} находок ({divergences.data ? Math.round((s.divergence_count / s.finding_count) * 100) : '…'}%)
              </span>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-primary">
              смотреть в гигиене контента <ArrowRight size={12} aria-hidden />
            </div>
          </Card>
        </Link>

        <Link to={`/siem/snapshots/${snapshotId}/rules?scoped=1`} className="block">
          <Card className="h-full hover:border-border">
            <CardHeader title="Правила, ограниченные списками" subtitle="область действия сужена табличным списком" />
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-3xl tabular-nums text-text">{scopedShare}%</span>
              <span className="text-xs text-text-secondary">
                {s.scoped_count} из {s.rule_count} правил
              </span>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-primary">
              <ListFilter size={12} aria-hidden /> открыть инвентарь правил <ArrowRight size={12} aria-hidden />
            </div>
          </Card>
        </Link>

        <Card className="lg:col-span-2 xl:col-span-3">
          <CardHeader
            title="Состояние табличных списков"
            subtitle="список может отсутствовать в выгрузке, быть пустым или наполненным — это три разные поломки с разным ремонтом"
          />
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {sortedTables.slice(0, 9).map((t) => {
              const state = tableState(t)
              const meta = STATE_META[state]
              const Icon = meta.icon
              return (
                <div key={t.name} className="flex items-center gap-2.5 rounded border border-grid px-2.5 py-2">
                  <Icon size={16} style={{ color: meta.color }} aria-hidden className="shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs text-text" title={t.name}>
                      {t.name}
                    </div>
                    <div className="text-[11px] text-text-secondary">
                      {meta.label}
                      {state === 'filled' && ` · ${t.value_count} значений`}
                      {t.is_scoping && ' · ограничивает область'}
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <div className="font-mono text-sm tabular-nums text-text">{t.dependant_count}</div>
                    <div className="text-[10px] text-text-secondary">правил</div>
                  </div>
                </div>
              )
            })}
          </div>
        </Card>

        <Card>
          <CardHeader title="Дельта к предыдущему снапшоту" subtitle="изменение объёмов между загрузками" />
          {s.delta ? (
            <div className="flex flex-col gap-1.5">
              <DeltaRow label="Находки" value={s.delta.finding_count} />
              <DeltaRow label="Правила" value={s.delta.rule_count} />
              {previousId > 0 && (
                <Link to={`/siem/snapshots/${previousId}/overview`} className="mt-1 flex items-center gap-1 text-xs text-primary">
                  сравнить с предыдущим снапшотом <ArrowRight size={12} aria-hidden />
                </Link>
              )}
            </div>
          ) : (
            <div className="text-xs text-text-secondary">Это первый снапшот — сравнивать не с чем.</div>
          )}
        </Card>

        <Card>
          <CardHeader title="Объём выгрузки" subtitle="общие числа снапшота" />
          <dl className="grid grid-cols-2 gap-y-1.5 text-xs">
            <dt className="text-text-secondary">Правила</dt>
            <dd className="text-right font-mono tabular-nums text-text">{s.rule_count}</dd>
            <dt className="text-text-secondary">Группы</dt>
            <dd className="text-right font-mono tabular-nums text-text">{s.group_count}</dd>
            <dt className="text-text-secondary">Без msgid</dt>
            <dd className="text-right font-mono tabular-nums text-text">{s.rules_without_msgid}</dd>
            <dt className="text-text-secondary">Не разобрано</dt>
            <dd className="text-right font-mono tabular-nums text-text">{s.unsupported_count}</dd>
            <dt className="text-text-secondary">Схема именования</dt>
            <dd className="text-right font-mono tabular-nums text-text">{s.name_scheme_coverage}</dd>
          </dl>
        </Card>

        <Card>
          <CardHeader title="Авторы контента" subtitle="без привязки к конкретному вендору" />
          <dl className="flex flex-col gap-1.5 text-xs">
            {Object.entries(s.authors)
              .sort((a, b) => b[1] - a[1])
              .map(([author, cnt]) => (
                <div key={author} className="flex items-center justify-between">
                  <dt className="text-text-secondary">{author}</dt>
                  <dd className="font-mono tabular-nums text-text">{cnt}</dd>
                </div>
              ))}
          </dl>
        </Card>
      </div>

      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-text-secondary">
        <Database size={12} aria-hidden /> данные снапшота #{snapshotId}
      </div>
    </div>
  )
}

function DeltaRow({ label, value }: { label: string; value: number }) {
  const Icon = value > 0 ? TrendingUp : value < 0 ? TrendingDown : ArrowRight
  const color = value === 0 ? 'text-text-secondary' : value > 0 ? 'text-kind-2' : 'text-kind-accepted'
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-text-secondary">{label}</span>
      <span className={cn('flex items-center gap-1 font-mono tabular-nums', color)}>
        <Icon size={12} aria-hidden />
        {value > 0 ? '+' : ''}
        {value}
      </span>
    </div>
  )
}
