import { X } from 'lucide-react'
import { ReadingAssistant } from './ReadingAssistant'
import { SeverityBadge } from './SeverityBadge'
import { PocEvidence } from './PocEvidence'
import { ApplicabilityPanel } from './ApplicabilityPanel'
import { useEffect, useRef, useState } from 'react'
import { publicationUrl, safeUrl } from './publicationUrl'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { FIELD } from '@/platform/collector/ui'
import { TREND_BASE, trendPeriodLabel, useTrend, useTrendMutation, when, type Evidence, type TrendDetail, type TrendScope } from '../../api/trends'

const evidenceKinds: Record<string, string> = { kev: 'Запись каталога CISA KEV', vendor: 'Бюллетень производителя', advisory: 'Бюллетень безопасности' }

function publicationAge(value: string | null) {
  if (!value) return 'Дата неизвестна; только в архиве'
  const elapsed = Date.now() - new Date(value).getTime()
  if (elapsed < 0) return 'Дата в будущем'
  const days = Math.floor(elapsed / 86_400_000)
  return days === 0 ? 'Менее суток назад' : `${days} дн. назад`
}

export function TrendDrawer({ id, scope, close }: { id: string; scope: TrendScope; close: () => void }) {
  const dialog = useRef<HTMLElement>(null)
  const data = useTrend(id, scope)
  const { write } = useCan()
  const review = useTrendMutation((status: string) => api.patch(TREND_BASE + '/' + encodeURIComponent(id) + '/review', { version: data.data?.version, status }))
  useEffect(() => {
    function outside(event: PointerEvent) {
      if (event.target instanceof Node && !dialog.current?.contains(event.target)) close()
    }
    function escape(event: KeyboardEvent) { if (event.key === 'Escape') close() }
    document.addEventListener('pointerdown', outside)
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('pointerdown', outside); document.removeEventListener('keydown', escape) }
  }, [close])
  const detail = data.data
  const publications = detail ? [...detail.evidence].sort((a, b) => Number(b.url === detail.source_url) - Number(a.url === detail.source_url)) : []
  return <aside ref={dialog} role="dialog" aria-modal="false" className="fixed inset-y-0 right-0 z-40 h-dvh w-full max-w-[640px] overflow-y-auto border-l border-grid bg-surface p-0 text-text shadow-2xl" aria-labelledby="trend-title">
    <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-grid bg-surface px-4 py-3"><div><h2 id="trend-title" className="font-mono text-sm">{id.startsWith('signal-') ? 'Новость без CVE' : id}</h2><p className="line-clamp-3 text-xs text-text-secondary" title={detail?.title}>{detail?.title}</p><p className="mt-1 text-xs text-text-secondary">{trendPeriodLabel(scope)} · {scope.tz}</p>{/^CVE-\d{4}-\d{4,}$/i.test(id) && <a href={'https://www.cve.org/CVERecord?id=' + encodeURIComponent(id)} target="_blank" rel="noopener noreferrer" className="text-xs underline">Карточка CVE.org</a>}</div><button type="button" onClick={close} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)"><X size={16} aria-hidden /></button></header>
    <div className="space-y-6 p-5">
      {data.isLoading && <Spinner />}{data.error && <p role="alert">{data.error.message}</p>}
      {detail && <>
        {!id.startsWith('signal-') && <section className="space-y-3" aria-label="Опасность CVE"><h3 className="font-semibold">Опасность CVE</h3>
          <div className="grid grid-cols-2 gap-3 rounded border border-grid bg-app-bg p-3 text-xs">
            <div><p className="mb-1 text-text-secondary">Критичность · CVSS</p><SeverityBadge value={detail} /></div>
            <div><p className="mb-1 text-text-secondary">Вероятность эксплуатации · EPSS</p><p className="font-semibold">{detail.enrichment?.epss == null ? 'Нет данных' : `${(detail.enrichment.epss * 100).toLocaleString('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}%`}</p><p className="mt-1 text-text-secondary">Оценка на ближайшие 30 дней, не риск конкретного хоста.</p></div>
            <div className="col-span-2"><p className="mb-1 text-text-secondary">Известная эксплуатация</p><p>{detail.reason === 'confirmed_exploitation' ? 'Подтверждена материалами за выбранный период' : detail.enrichment?.known_exploited === true ? 'Есть в каталоге известных эксплуатируемых уязвимостей' : detail.enrichment?.known_exploited === false ? 'Не отмечена в проверенном каталоге; это не доказывает отсутствие атак' : 'Нет данных'}</p></div>
          </div>
          {detail.cvss_vector && <details className="text-xs text-text-secondary"><summary className="cursor-pointer">Вектор CVSS</summary><p className="mt-1 break-all">{detail.cvss_vector}</p></details>}
          <ReadingAssistant key={`${id}/${detail.version}`} cardId={id} originalText={detail.enrichment?.description ?? ''} />
        </section>}
        <section className="space-y-3"><h3 className="font-semibold">Публикации и доказательства за период ({detail.evidence_total})</h3>
          {detail.evidence_total === 0 && <p className="text-xs text-text-secondary">У этой карточки нет публикаций за выбранный период. Для истории выберите «Архив · всё время».</p>}
          {detail.evidence_total > detail.evidence.length && <p className="text-xs text-text-secondary">Показаны первые {detail.evidence.length} публикаций за период.</p>}
          {publications.map(entry => <EvidenceCard key={`${entry.publication_key}/${entry.revision}`} entry={entry} detail={detail} />)}
        </section>
        <section className="space-y-2"><h3 className="font-semibold">{detail.status === 'rejected' ? 'Оценка тренда' : detail.active ? 'Почему это в трендах' : 'Почему это на проверке'}</h3><p className="text-xs">{detail.reason === 'confirmed_exploitation' ? 'За выбранный период есть подтверждение эксплуатации.' : detail.reason === 'independent_reports' ? 'За выбранный период найдено не менее двух независимых материалов об уязвимости.' : 'Материал найден, но подтверждения эксплуатации или достаточного независимого освещения пока нет.'}</p>
          <p className="text-xs text-text-secondary">{detail.status === 'rejected' ? 'Карточка отклонена аналитиком и исключена из активных трендов.' : detail.active ? 'Критерий тренда выполнен за этот период.' : 'Критерий тренда за этот период не подтверждён.'} {scope.period === 'all' && 'Это архив: наличие основания в прошлом не означает, что CVE обсуждают сейчас.'}</p>
          <p className="text-xs">Публикаций: {detail.publication_count} · Новостей: {detail.news_count} · Издателей: {detail.publisher_count} · Независимых материалов: {detail.independent_sources}</p>
          <p className="text-xs text-text-secondary">Последняя исходная публикация за период — {when(detail.last_event_at)}. Упоминание в новости, PoC и машинная выжимка сами по себе не подтверждают эксплуатацию.</p>
          {write && <details><summary className="cursor-pointer text-xs text-text-secondary">Решение аналитика</summary><div className="mt-2 flex flex-wrap gap-2"><Button disabled={review.isPending} onClick={() => review.mutate('verified')}>Отметить проверенным</Button><Button disabled={review.isPending} onClick={() => review.mutate('rejected')}>Отклонить</Button><Button disabled={review.isPending} onClick={() => review.mutate('new')}>Вернуть на проверку</Button></div></details>}{review.error && <p role="alert">{review.error.message}</p>}
        </section>
        <ApplicabilityPanel enrichment={detail.enrichment} items={detail.applicability ?? []} />
        <section className="space-y-2"><h3 className="font-semibold">PoC</h3><p className="text-xs text-text-secondary">Кандидаты оцениваются статически. Код не исполнялся; наличие PoC не подтверждает эксплуатацию в атаках.</p>{detail.pocs?.length ? detail.pocs.map(item => <PocEvidence key={item.id} item={item} />) : <p className="text-xs">Кандидаты ещё не получены. Статус поиска доступен в диагностике сборщика.</p>}</section>
        <section className="space-y-3"><h3 className="font-semibold">Наличие у нас</h3><p className="text-xs text-text-secondary">Последний импорт хостов — {when(detail.matches.host_data_at)}. Совпадений на хостах {detail.matches.host_total}, находок в образах {detail.matches.image_finding_total}.</p>
          {detail.matches.coverage === 'insufficient' && <p>Недостаточно локальных данных для проверки.</p>}
          {detail.matches.hosts.map(host => <div key={host.id} className="rounded border border-grid p-3 text-xs"><Link to={'/vm/vulns?cve=' + encodeURIComponent(id) + '&host_id=' + host.id + '&status=all'} className="font-medium underline">{host.hostname}</Link> · {host.ip}<p className="text-text-secondary">{host.os} · Риск {host.risk} · <StatusBadge status={host.status} /></p></div>)}
          {detail.matches.images.map(image => <div key={`${image.id}/${image.package}/${image.installed_version}`} className="rounded border border-grid p-3 text-xs"><Link to={'/vm/images/' + image.id} className="font-medium underline">{image.name}</Link><p>{image.package} {image.installed_version} · Исправлено {image.fixed_version ?? 'нет данных'}</p><p className="text-text-secondary">Скан — {when(image.scanned_at)} · {image.scan_status}{image.sync_error ? ' · Ошибка обновления' : ''}</p></div>)}
          {(detail.matches.host_total > detail.matches.hosts.length || detail.matches.image_finding_total > detail.matches.images.length) && <p className="text-xs">Показаны первые 100 совпадений каждого типа. Полный список доступен в разделе уязвимостей и образов.</p>}
        </section>
        {detail.candidates.length > 0 && <section className="space-y-2"><h3 className="font-semibold">Кандидаты на проверку</h3><p className="text-xs text-text-secondary">Подсказки по названиям продуктов из машинного анализа. Наличие уязвимости не подтверждено.</p>{detail.candidates.map((item, index) => <div key={index} className="rounded border border-grid p-3 text-xs"><p>{item.name} · {item.product}</p><p className="text-text-secondary">{item.reason}</p></div>)}</section>}
        {detail.reviews.length > 0 && <section className="space-y-2"><h3 className="font-semibold">История решений</h3>{detail.reviews.map((item, index) => <p key={index} className="text-xs">{when(item.at)} · {item.actor} · {item.decision.status ?? 'Проверка доказательства'} {item.decision.linked_identifier} {item.decision.note}</p>)}</section>}
      </>}
    </div>
  </aside>
}

function EvidenceCard({ entry, detail }: { entry: Evidence; detail: TrendDetail }) {
  const { write } = useCan()
  const [note, setNote] = useState('')
  const [linked, setLinked] = useState('')
  const review = useTrendMutation((changes: Record<string, unknown>) => api.patch(TREND_BASE + '/' + encodeURIComponent(detail.id) + '/review', {
    version: detail.version, publication_key: entry.publication_key, revision: entry.revision, note,
    independent: Boolean(entry.independent), confirm_exploitation: Boolean(entry.exploitation_verified), rejected: Boolean(entry.rejected), ...changes,
  }))
  const url = publicationUrl(entry.url, detail.id)
  const kind = evidenceKinds[entry.evidence_kind ?? ''] ?? 'Публикация'
  const confirmed = !entry.retracted && !entry.rejected && (entry.exploitation_verified || (entry.exploitation_confirmed && ['kev', 'vendor'].includes(entry.evidence_kind ?? '')))
  return <article className="space-y-2 rounded border border-grid bg-app-bg p-3">
    <div><p className="mb-1 text-xs text-text-secondary">{kind} · {entry.source_name || entry.publisher_id}{entry.language ? ` · ${entry.language}` : ''}</p><h4 className="line-clamp-3 font-medium" title={entry.title}>{entry.title}</h4><p className="text-xs text-text-secondary">{entry.evidence_kind === 'kev' ? 'Добавлено в KEV' : 'Опубликовано'}: {when(entry.published_at)} · {publicationAge(entry.published_at)}</p>{url && <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs underline">{entry.evidence_kind === 'kev' ? 'Открыть запись KEV' : 'Открыть публикацию'}</a>}</div>
    <p className="text-xs text-text-secondary">{confirmed ? 'Подтверждённая эксплуатация' : 'Эксплуатация этим материалом не подтверждена'}{entry.independent ? ' · Учитывается как самостоятельный материал' : ' · Независимость не подтверждена'}</p>
    {entry.classification && <details className="text-xs text-text-secondary"><summary className="cursor-pointer">Почему материал учтён</summary><p className="mt-1">{entry.classification.reasons.join("; ")}</p></details>}
    {entry.suppressed && <p className="text-xs">Исключено: {entry.suppression_reason}</p>}
    {entry.retracted && <p className="text-danger">Источник отозвал публикацию</p>}
    {entry.rejected && <p className="text-text-secondary">Основание отклонено аналитиком</p>}
    {entry.analysis.summary_ru && <details className="space-y-2"><summary className="cursor-pointer text-xs text-text-secondary">Автоматическая выжимка</summary><p className="text-xs whitespace-pre-wrap">{entry.analysis.summary_ru}</p><p className="text-xs">{entry.analysis.product} {entry.analysis.affected_versions}</p>{entry.analysis.quote && <blockquote className="border-l-2 border-grid pl-3 text-xs">{entry.analysis.quote}</blockquote>}</details>}
    <ReadingAssistant key={`${detail.id}/${entry.publication_key}/${entry.revision}`} cardId={detail.id} publicationKey={entry.publication_key} revision={entry.revision} originalText={entry.text} textLabel={entry.full_text ? 'Текст публикации' : 'Текст публикации · краткое описание'} />
    {entry.links?.length > 0 && <details><summary className="cursor-pointer text-xs">Ссылки из публикации</summary><ul className="space-y-1 text-xs">{entry.links.slice(0, 20).map((link, index) => <li key={index}>{safeUrl(link) ? <a className="break-all underline" href={safeUrl(link)} target="_blank" rel="noopener noreferrer">{link}</a> : <span>{link}</span>}</li>)}</ul></details>}
    {entry.error && <p className="text-xs text-danger">Ошибка машинного анализа · {entry.error}</p>}
    {write && <details className="border-t border-grid pt-2"><summary className="cursor-pointer text-xs text-text-secondary">Проверка аналитиком</summary><div className="mt-2 space-y-2"><input className={FIELD} placeholder="Комментарий к проверке" aria-label="Комментарий к проверке" value={note} onChange={e => setNote(e.target.value)} />
      {entry.classification?.category === "background" && <Button disabled={review.isPending || !note.trim()} onClick={() => review.mutate({ include_background: !entry.included_manually })}>{entry.included_manually ? "Вернуть в фон" : "Включить в анализ"}</Button>}
      <div className="flex flex-wrap gap-2"><Button disabled={review.isPending} onClick={() => review.mutate({ independent: !entry.independent })}>{entry.independent ? 'Снять независимость' : 'Самостоятельный материал'}</Button><Button disabled={review.isPending} onClick={() => review.mutate({ confirm_exploitation: !entry.exploitation_verified })}>{entry.exploitation_verified ? 'Снять подтверждение' : 'Подтвердить эксплуатацию'}</Button><Button disabled={review.isPending} onClick={() => review.mutate({ rejected: !entry.rejected })}>{entry.rejected ? 'Вернуть основание' : 'Отклонить основание'}</Button></div>
      <div className="flex gap-2"><input className={FIELD} placeholder="Связать с CVE или GHSA" aria-label="Идентификатор для связи" value={linked} onChange={e => setLinked(e.target.value)} /><Button disabled={!linked || review.isPending} onClick={() => review.mutate({ linked_identifier: linked })}>Связать</Button></div>
      {review.error && <p role="alert" className="text-xs text-danger">{review.error.message}</p>}
    </div></details>}
  </article>
}
