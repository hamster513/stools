import { ArrowLeft, ExternalLink } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiRequestError } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { useKbConnection } from '@/modules/siem/api/queries'
import { FindingWorkBlock } from '@/platform/findings/FindingWorkBlock'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { TH_FINDINGS_KEY, useHunts, useThFinding } from '../api/queries'
import { TH_MODULE, TH_SCOPE } from '../api/types'
import { EventsTable } from '../components/EventsTable'
import { ruDay, ruStamp } from '../format'

const LINK = 'inline-flex items-center gap-1 rounded text-xs text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Адрес консоли MaxPatrol из настройки подключения: хост может быть записан и со схемой. Точная форма ссылки на события — после проверки на живой системе. */
function maxPatrolUrl(host: string | undefined): string | null {
  const bare = (host ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '')
  return bare ? `https://${bare}/` : null
}

/**
 * Карточка находки Threat Hunting: шапка (хант и запрос), работа со статусом (платформа),
 * сводка и события. Для находки большого ханта (`kind: 'deep'`) ханта в библиотеке нет — ссылки на него не показываются.
 */
export function FindingPage({ id }: { id: number }) {
  const qc = useQueryClient()
  const finding = useThFinding(Number.isFinite(id) ? id : undefined)
  const hunts = useHunts()
  const connection = useKbConnection()
  const f = finding.data

  if (finding.isLoading) return <FullPageSpinner />
  if (!f) {
    const message = finding.error instanceof ApiRequestError ? finding.error.message : 'Находка не найдена'
    return <div className="p-6"><ErrorState message={message} onRetry={finding.isError ? () => finding.refetch() : undefined} /></div>
  }

  const deep = f.kind === 'deep'
  const hunt = deep ? undefined : hunts.data?.find((h) => h.code === f.hunt_code)
  const mp = maxPatrolUrl(connection.data?.host)
  const title = deep ? `Большой хант #${f.deep_id}` : `${f.hunt_code} · ${f.query_id}${f.target_date ? ` · ночь ${ruDay(f.target_date)}` : ''}`

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <header className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 border-b border-grid bg-surface px-4 py-2.5">
        <Link to="/siem/hunting" className={LINK}><ArrowLeft size={13} aria-hidden /> Находки</Link>
        <h1 className="text-sm font-semibold text-text">{deep ? title : <><span className="font-mono">{f.hunt_code}</span> <span className="font-normal text-text-secondary">{f.hunt_name}</span></>}</h1>
        {!deep && <span className="font-mono text-xs text-text-secondary">запрос {f.query_id}</span>}
        <StatusBadge status={f.state.status} />
        <div className="ml-auto flex flex-wrap items-center gap-4">
          {hunt && <Link to={`/siem/hunting/library/${hunt.id}`} className={LINK}>править запрос</Link>}
          {!deep && <Link to={`/siem/hunting?hunt=${encodeURIComponent(f.hunt_code)}&status=all`} className={LINK}>все находки ханта</Link>}
          {mp && <a href={mp} target="_blank" rel="noopener noreferrer" className={LINK}>открыть в MaxPatrol <ExternalLink size={12} aria-hidden /></a>}
        </div>
      </header>

      <div className="flex flex-col gap-4 p-4">
        <div className="grid gap-4 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
          <section className="rounded border border-grid bg-surface p-4">
            <FindingWorkBlock
              module={TH_MODULE}
              scopeId={TH_SCOPE}
              findingKey={f.key}
              title={title}
              severity="medium"
              onChanged={() => qc.invalidateQueries({ queryKey: TH_FINDINGS_KEY })}
            />
          </section>
          <section className="rounded border border-grid bg-surface p-4">
            <div className="mb-3 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Сводка</div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs">
              <dt className="text-text-secondary">Событий</dt>
              <dd className="font-mono tabular-nums text-text">{f.event_count}</dd>
              <dt className="text-text-secondary">{deep ? 'Период' : 'Ночь'}</dt>
              <dd className="text-text">{deep ? `${ruStamp(f.period_from)} — ${ruStamp(f.period_to)}` : ruDay(f.target_date)}</dd>
              <dt className="text-text-secondary">Найдено</dt>
              <dd className="text-text">{ruStamp(f.created_at)}</dd>
              <dt className="text-text-secondary">Достигнут лимит</dt>
              <dd className={f.limit_hit ? 'text-kind-1' : 'text-text'}>
                {f.limit_hit ? 'да — событий могло быть больше' : 'нет'}
                {f.limit_hit_slices !== null && f.limit_hit_slices > 0 && `, окон с пределом: ${f.limit_hit_slices}`}
              </dd>
              {deep && (
                <>
                  <dt className="text-text-secondary">Неполная выборка</dt>
                  <dd className={f.partial ? 'text-kind-1' : 'text-text'}>{f.partial ? 'да — хант отменён или ещё идёт, события собраны не за весь период' : 'нет'}</dd>
                </>
              )}
              <dt className="text-text-secondary">События удалены</dt>
              <dd className={f.events_purged ? 'text-kind-1' : 'text-text'}>{f.events_purged ? 'да — по сроку хранения; находка осталась' : 'нет'}</dd>
            </dl>
          </section>
        </div>

        {f.events_purged || f.columns.length === 0 ? (
          <p className="rounded border border-dashed border-grid px-4 py-8 text-center text-xs text-text-secondary">
            {f.events_purged ? 'События этой находки удалены по сроку хранения. Саму находку и решения по ней это не затрагивает.' : 'У находки нет колонок событий.'}
          </p>
        ) : (
          <EventsTable key={f.id} findingId={f.id} columns={f.columns} storageKey={`siem-th-events-columns:${deep ? 'deep' : `${f.hunt_code}:${f.query_id}`}`} />
        )}
      </div>
    </div>
  )
}
