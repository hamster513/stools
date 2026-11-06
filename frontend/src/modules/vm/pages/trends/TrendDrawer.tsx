import { useEffect, useRef, useState } from 'react'
import { publicationUrl, safeUrl } from './publicationUrl'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { StatusBadge } from '@/platform/findings/StatusBadge'
import { FIELD } from '@/platform/collector/ui'
import { TREND_BASE, reasons, trendPeriodLabel, useTrend, useTrendMutation, when, type Evidence, type TrendDetail, type TrendScope } from '../../api/trends'

const evidenceKinds: Record<string, string> = { kev: 'Запись каталога CISA KEV', vendor: 'Бюллетень производителя', advisory: 'Бюллетень безопасности' }

function publicationAge(value: string | null) {
  if (!value) return 'Дата неизвестна; только в архиве'
  const elapsed = Date.now() - new Date(value).getTime()
  if (elapsed < 0) return 'Дата в будущем'
  const days = Math.floor(elapsed / 86_400_000)
  return days === 0 ? 'Менее суток назад' : `${days} дн. назад`
}

export function TrendDrawer({ id, scope, close }: { id: string; scope: TrendScope; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const data = useTrend(id, scope)
  const { write } = useCan()
  const review = useTrendMutation((status: string) => api.patch(TREND_BASE + '/' + encodeURIComponent(id) + '/review', { version: data.data?.version, status }))
  useEffect(() => { dialog.current?.showModal() }, [])
  const detail = data.data
  return <dialog ref={dialog} onClose={close} className="fixed inset-y-0 left-auto right-0 m-0 h-screen max-h-screen w-full max-w-3xl overflow-y-auto border-l border-grid bg-surface p-0 text-text backdrop:bg-black/40" aria-labelledby="trend-title">
    <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-grid bg-surface p-5"><div><h2 id="trend-title" className="text-lg font-semibold">{id.startsWith('signal-') ? 'Сигнал без CVE' : id}</h2><p className="text-sm text-text-secondary">{detail?.title}</p><p className="mt-1 text-xs text-text-secondary">{trendPeriodLabel(scope)} · {scope.tz}</p>{/^CVE-\d{4}-\d{4,}$/i.test(id) && <a href={'https://www.cve.org/CVERecord?id=' + encodeURIComponent(id)} target="_blank" rel="noopener noreferrer" className="text-sm underline">Карточка CVE.org</a>}</div><Button onClick={close}>Закрыть</Button></header>
    <div className="space-y-6 p-5">
      {data.isLoading && <Spinner />}{data.error && <p role="alert">{data.error.message}</p>}
      {detail && <>
        <section className="space-y-2"><h3 className="font-semibold">Основание за выбранный период</h3><p>{reasons[detail.reason] ?? detail.reason}</p>
          <p className="text-sm text-text-secondary">{detail.active ? 'Критерий тренда выполнен за этот период.' : 'Критерий тренда за этот период не подтверждён.'} {scope.period === 'all' && 'Это архив: наличие основания в прошлом не означает, что CVE обсуждают сейчас.'}</p>
          <p className="text-sm">Публикаций: {detail.publication_count} · Новостей: {detail.news_count} · Издателей: {detail.publisher_count} · Независимых материалов: {detail.independent_sources}</p>
          <p className="text-sm text-text-secondary">Последняя исходная публикация за период — {when(detail.last_event_at)}. Упоминание в новости, PoC и машинная выжимка сами по себе не подтверждают эксплуатацию.</p>
          {write && <div className="flex flex-wrap gap-2"><Button disabled={review.isPending} onClick={() => review.mutate('verified')}>Отметить проверенным</Button><Button disabled={review.isPending} onClick={() => review.mutate('rejected')}>Отклонить</Button><Button disabled={review.isPending} onClick={() => review.mutate('new')}>Вернуть на проверку</Button></div>}{review.error && <p role="alert">{review.error.message}</p>}
        </section>
        <section className="space-y-3"><h3 className="font-semibold">Наличие у нас</h3><p className="text-sm text-text-secondary">Последний импорт хостов — {when(detail.matches.host_data_at)}. Совпадений на хостах {detail.matches.host_total}, находок в образах {detail.matches.image_finding_total}.</p>
          {detail.matches.coverage === 'insufficient' && <p>Недостаточно локальных данных для проверки.</p>}
          {detail.matches.hosts.map(host => <div key={host.id} className="rounded border border-grid p-3 text-sm"><Link to={'/vm/vulns?cve=' + encodeURIComponent(id) + '&host_id=' + host.id + '&status=all'} className="font-medium underline">{host.hostname}</Link> · {host.ip}<p className="text-text-secondary">{host.os} · Риск {host.risk} · <StatusBadge status={host.status} /></p></div>)}
          {detail.matches.images.map(image => <div key={`${image.id}/${image.package}/${image.installed_version}`} className="rounded border border-grid p-3 text-sm"><Link to={'/vm/images/' + image.id} className="font-medium underline">{image.name}</Link><p>{image.package} {image.installed_version} · Исправлено {image.fixed_version ?? 'нет данных'}</p><p className="text-text-secondary">Скан — {when(image.scanned_at)} · {image.scan_status}{image.sync_error ? ' · Ошибка обновления' : ''}</p></div>)}
          {(detail.matches.host_total > detail.matches.hosts.length || detail.matches.image_finding_total > detail.matches.images.length) && <p className="text-sm">Показаны первые 100 совпадений каждого типа. Полный список доступен в разделе уязвимостей и образов.</p>}
        </section>
        {detail.candidates.length > 0 && <section className="space-y-2"><h3 className="font-semibold">Кандидаты на проверку</h3><p className="text-sm text-text-secondary">Подсказки по названиям продуктов из машинного анализа. Наличие уязвимости не подтверждено.</p>{detail.candidates.map((item, index) => <div key={index} className="rounded border border-grid p-3 text-sm"><p>{item.name} · {item.product}</p><p className="text-text-secondary">{item.reason}</p></div>)}</section>}
        <section className="space-y-3"><h3 className="font-semibold">Публикации и доказательства за период ({detail.evidence_total})</h3>
          {detail.evidence_total === 0 && <p className="text-sm text-text-secondary">У этой карточки нет публикаций за выбранный период. Для истории закройте карточку и выберите «Архив · всё время».</p>}
          {detail.evidence_total > detail.evidence.length && <p className="text-xs text-text-secondary">Показаны первые {detail.evidence.length} публикаций за период.</p>}
          {detail.evidence.map(entry => <EvidenceCard key={`${entry.publication_key}/${entry.revision}`} entry={entry} detail={detail} />)}
        </section>
        {detail.reviews.length > 0 && <section className="space-y-2"><h3 className="font-semibold">История решений</h3>{detail.reviews.map((item, index) => <p key={index} className="text-sm">{when(item.at)} · {item.actor} · {item.decision.status ?? 'Проверка доказательства'} {item.decision.linked_identifier} {item.decision.note}</p>)}</section>}
      </>}
    </div>
  </dialog>
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
  return <article className="space-y-3 rounded border border-grid p-4">
    <div><p className="mb-1 text-xs text-text-secondary">{kind} · {entry.source_name || entry.publisher_id}{entry.language ? ` · ${entry.language}` : ''}</p><h4 className="font-medium">{entry.title}</h4><p className="text-xs text-text-secondary">{entry.evidence_kind === 'kev' ? 'Добавлено в KEV' : 'Опубликовано'}: {when(entry.published_at)} · {publicationAge(entry.published_at)} · версия {entry.revision}</p>{url && <a href={url} target="_blank" rel="noopener noreferrer" className="text-sm underline">{entry.evidence_kind === 'kev' ? 'Открыть запись KEV' : 'Открыть публикацию'}</a>}</div>
    <p className="text-xs text-text-secondary">{confirmed ? 'Подтверждённая эксплуатация' : 'Эксплуатация этим материалом не подтверждена'}{entry.independent ? ' · Учитывается как самостоятельный материал' : ' · Независимость не подтверждена'}</p>
    {entry.retracted && <p className="text-danger">Источник отозвал публикацию</p>}
    {entry.rejected && <p className="text-text-secondary">Основание отклонено аналитиком</p>}
    {entry.analysis.summary_ru && <div className="space-y-2"><p className="text-xs text-text-secondary">Машинная выжимка, требует проверки</p><p className="text-sm whitespace-pre-wrap">{entry.analysis.summary_ru}</p><p className="text-sm">{entry.analysis.product} {entry.analysis.affected_versions}</p>{entry.analysis.quote && <blockquote className="border-l-2 border-grid pl-3 text-sm">{entry.analysis.quote}</blockquote>}</div>}
    <details><summary className="cursor-pointer text-sm">Текст публикации{entry.full_text ? '' : ' · краткое описание'}</summary><p className="mt-2 whitespace-pre-wrap break-words text-sm text-text-secondary">{entry.text}</p></details>
    {entry.links?.length > 0 && <details><summary className="cursor-pointer text-sm">Ссылки из публикации</summary><ul className="space-y-1 text-xs">{entry.links.slice(0, 20).map((link, index) => <li key={index}>{safeUrl(link) ? <a className="break-all underline" href={safeUrl(link)} target="_blank" rel="noopener noreferrer">{link}</a> : <span>{link}</span>}</li>)}</ul></details>}
    {entry.error && <p className="text-xs text-danger">Ошибка машинного анализа · {entry.error}</p>}
    {write && <div className="space-y-2 border-t border-grid pt-3"><input className={FIELD} placeholder="Комментарий к проверке" aria-label="Комментарий к проверке" value={note} onChange={e => setNote(e.target.value)} />
      <div className="flex flex-wrap gap-2"><Button disabled={review.isPending} onClick={() => review.mutate({ independent: !entry.independent })}>{entry.independent ? 'Снять независимость' : 'Самостоятельный материал'}</Button><Button disabled={review.isPending} onClick={() => review.mutate({ confirm_exploitation: !entry.exploitation_verified })}>{entry.exploitation_verified ? 'Снять подтверждение' : 'Подтвердить эксплуатацию'}</Button><Button disabled={review.isPending} onClick={() => review.mutate({ rejected: !entry.rejected })}>{entry.rejected ? 'Вернуть основание' : 'Отклонить основание'}</Button></div>
      <div className="flex gap-2"><input className={FIELD} placeholder="Связать с CVE или GHSA" aria-label="Идентификатор для связи" value={linked} onChange={e => setLinked(e.target.value)} /><Button disabled={!linked || review.isPending} onClick={() => review.mutate({ linked_identifier: linked })}>Связать</Button></div>
      {review.error && <p role="alert" className="text-xs text-danger">{review.error.message}</p>}
    </div>}
  </article>
}
