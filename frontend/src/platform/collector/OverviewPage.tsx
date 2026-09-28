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
 * Обзор последнего снапшота: плитки severity, карточки проверок. Модуль
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
  const withFindings = o.checks.filter((c) => c.total > 0 || c.fixed > 0)
  const clean = o.checks.filter((c) => c.total === 0 && c.fixed === 0)

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">{title(o)}</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Снапшот #{snap.id} от {when(snap.collected_at)}, {source(snap)} ({snap.collector}), {count(snap)}.
            {cmp?.previous_id ? ` По сравнению с ${cmp.collected_at ? when(cmp.collected_at) : 'прошлым'}: новых ${cmp.new}, закрыто ${cmp.fixed}.` : firstNote}
          </p>
        </div>
      </div>

      {extra?.(o)}

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {SEVERITIES.map((s) => (
          <Link key={s} to={`${base}?severity=${s}`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
            <div className={cn('text-[11px]', SEVERITY_TEXT[s])}>{SEVERITY_LABELS[s]}</div>
            <div className="mt-1 font-mono text-xl tabular-nums text-text">{(snap.by_severity[s] ?? 0).toLocaleString('ru-RU')}</div>
          </Link>
        ))}
        <Link to={`${base}?status=new`} className="rounded border border-grid bg-surface p-3 hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring">
          <div className="text-[11px] text-text-secondary">новых</div>
          <div className="mt-1 font-mono text-xl tabular-nums text-text">{cmp?.new ?? 0}</div>
        </Link>
      </div>

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
                {c.new > 0 && <span className="text-risk-high">+{c.new} новых</span>}
                {c.fixed > 0 && <span className="text-kind-accepted">−{c.fixed} закрыто</span>}
                {c.accepted > 0 && <span>принято {c.accepted}</span>}
              </div>
              <p className="text-[11px] leading-relaxed text-text-secondary">{c.description}</p>
            </Link>
          )
        })}
      </div>
      {clean.length > 0 && (
        <p className="mt-4 text-xs text-text-secondary">
          Без находок: {clean.map((c) => c.title).join(' · ')}.
        </p>
      )}
    </div>
  )
}
