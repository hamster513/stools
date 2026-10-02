import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { ArrowRight, ServerCog } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'
import { SEVERITIES, SEVERITY_LABELS, SEVERITY_TEXT, type CheckSummary, type OverviewBase, type Severity } from './types'

function worst(c: CheckSummary): Severity | null {
  return SEVERITIES.find((s) => (c.by_severity[s] ?? 0) > 0) ?? null
}

function when(iso: string): string {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

type Snap<O extends OverviewBase> = NonNullable<O['snapshot']>

/**
 * Обзор последнего снапшота: плитки severity и счётчики статусов находок
 * (ссылки на отфильтрованный список), карточки проверок. Числа severity и
 * проверок — по статусам, которые велено учитывать (настройка платформы). Модуль
 * задаёт заголовок, подпись источника и счётчика и блок над плитками.
 */
export function CollectorOverviewPage<O extends OverviewBase>({ overview, settingsPath, emptyDescription, findingsPath: base, title, source, count, firstNote, extra }: {
  overview: UseQueryResult<O, ApiRequestError>
  settingsPath: string
  emptyDescription: string
  findingsPath: string
  title: (o: O) => string
  source: (snap: Snap<O>) => string
  count: (snap: Snap<O>) => string
  firstNote: string
  extra?: (o: O) => ReactNode
}) {
  if (overview.isLoading) return <FullPageSpinner />
  if (overview.isError || !overview.data) {
    const msg = overview.error instanceof ApiRequestError ? overview.error.message : 'Не удалось загрузить обзор'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => overview.refetch()} /></div>
  }
  const o = overview.data
  if (!o.snapshot) {
    return (
      <div className="p-6">
        <EmptyState icon={ServerCog} title="Снапшотов ещё нет" description={emptyDescription} action={<Link to={settingsPath} className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-text hover:bg-primary/90">Настройки и данные <ArrowRight size={13} aria-hidden /></Link>} />
      </div>
    )
  }
  const snap: Snap<O> = o.snapshot
  const cmp = o.compared_to
  const withFindings = o.checks.filter((c) => c.all > 0 || c.resolved > 0)
  // Проверка с находками тоже бывает проверена частично (у AD CS часть ESC — только по данным ЦС).
  const unchecked = o.checks.filter((c) => c.unchecked)
  const clean = o.checks.filter((c) => c.all === 0 && c.resolved === 0 && !c.unchecked)
  // Плитки severity — по учитываемым статусам (настройка платформы), как и счётчики проверок.
  const bySeverity = o.counted?.by_severity ?? snap.by_severity
  const summary = o.summary
  const statusTiles = summary ? [
    { label: 'новые', value: summary.by_status.new, to: `${base}?status=new` },
    { label: 'в работе', value: summary.by_status.in_work, to: `${base}?status=in_work` },
    { label: 'просроченные', value: summary.overdue, to: `${base}?overdue=true` },
    { label: 'переоткрытые', value: summary.by_status.reopened, to: `${base}?status=reopened` },
    { label: 'риск истекает', value: summary.risk_expiring, to: `${base}?risk_expiring=true` },
  ] : []

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">{title(o)}</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Снапшот #{snap.id} от {when(snap.collected_at)}, {source(snap)} ({snap.collector}), {count(snap)}.
            {cmp?.previous_id ? ` По сравнению с ${cmp.collected_at ? when(cmp.collected_at) : 'прошлым'}: новых ${cmp.new}, пропало ${cmp.fixed}.` : firstNote}
          </p>
        </div>
      </div>

      {extra?.(o)}

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {SEVERITIES.map((s) => (
          <Link key={s} to={`${base}?severity=${s}`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
            <div className={cn('text-[11px]', SEVERITY_TEXT[s])}>{SEVERITY_LABELS[s]}</div>
            <div className="mt-1 font-mono text-xl tabular-nums text-text">{(bySeverity[s] ?? 0).toLocaleString('ru-RU')}</div>
          </Link>
        ))}
        <Link to={`${base}?delta=new&status=all`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <div className="text-[11px] text-text-secondary">появились в снапшоте</div>
          <div className="mt-1 font-mono text-xl tabular-nums text-text">{cmp?.new ?? 0}</div>
        </Link>
      </div>

      {statusTiles.length > 0 && (
        <>
          <div className="mb-2 text-xs font-semibold tracking-wide text-text-secondary uppercase">Статусы</div>
          <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {statusTiles.map((t) => (
              <Link key={t.label} to={t.to} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
                <div className="text-[11px] text-text-secondary">{t.label}</div>
                <div className="mt-1 font-mono text-xl tabular-nums text-text">{t.value.toLocaleString('ru-RU')}</div>
              </Link>
            ))}
          </div>
        </>
      )}

      <div className="mb-2 text-xs font-semibold tracking-wide text-text-secondary uppercase">Проверки</div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {withFindings.map((c) => {
          const w = worst(c)
          return (
            <Link key={c.code} to={`${base}?check=${c.code}`} className="flex flex-col gap-1.5 rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
              <div className="flex items-start justify-between gap-2">
                <span className="text-sm text-text">{c.title}</span>
                <span className={cn('font-mono text-lg tabular-nums', w ? SEVERITY_TEXT[w] : 'text-text-secondary')}>{c.total}</span>
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-secondary">
                {SEVERITIES.filter((s) => (c.by_severity[s] ?? 0) > 0).map((s) => (
                  <span key={s}><span className={SEVERITY_TEXT[s]}>{SEVERITY_LABELS[s]}</span> {c.by_severity[s]}</span>
                ))}
                {c.all !== c.total && <span>всего {c.all}</span>}
                {c.new > 0 && <span className="text-risk-high">+{c.new} новых</span>}
                {c.resolved > 0 && <span className="text-kind-accepted">−{c.resolved} пропало</span>}
              </div>
              <p className="text-[11px] leading-relaxed text-text-secondary">{c.description}</p>
            </Link>
          )
        })}
      </div>
      {unchecked.length > 0 && (
        <div className="mt-4 text-xs text-text-secondary">
          <p className="text-kind-1">Не проверено или проверено частично — не было данных:</p>
          <ul className="mt-1 space-y-0.5">
            {unchecked.map((c) => <li key={c.code}><span className="text-text">{c.title}</span> — {c.unchecked}</li>)}
          </ul>
        </div>
      )}
      {clean.length > 0 && (
        <p className="mt-4 text-xs text-text-secondary">
          Без находок: {clean.map((c) => c.title).join(' · ')}.
        </p>
      )}
    </div>
  )
}
