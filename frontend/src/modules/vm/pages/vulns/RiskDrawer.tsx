import { useEffect, useRef } from 'react'
import { ExternalLink, X } from 'lucide-react'
import { useRiskCard } from '@/modules/vm/api/queries'
import type { Factor, VulnItem } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { AssetLink } from '@/modules/assets/AssetLink'
import { FindingWorkBlock } from '@/platform/findings/FindingWorkBlock'
import { Spinner } from '@/components/ui/Spinner'
import { Link } from '@/lib/router'
import { cn } from '@/lib/cn'

interface Props {
  item: VulnItem | null
  onClose: () => void
  /** Статус пары сохранён — список и обзор устарели. */
  onChanged?: () => void
}

function num(v: number): string {
  return v.toLocaleString('ru-RU', { maximumFractionDigits: 3 })
}

/** Члены формулы — ровно два знака, как в строке `0,82 × 0,98 × 1,00 × 100 = 81`. */
function num2(v: number): string {
  return v.toLocaleString('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

/** `YYYY-MM-DD` → `ДД.ММ.ГГГГ` без Date: разбор через Date сдвигал бы дату на день западнее UTC. */
function day(iso: string): string {
  return iso.split('-').reverse().join('.')
}

function FactorRow({ label, f, loaded, total }: { label: string; f: Factor; loaded?: string | null; total?: boolean }) {
  return (
    <tr className="border-t border-grid/60 align-top">
      <td className={cn('py-1.5 pr-2', total ? 'font-medium text-text' : 'text-text-secondary')}>{label}</td>
      <td className={cn('py-1.5 pr-2 text-right font-mono tabular-nums', f.substituted ? 'text-risk-medium' : 'text-text')}>{num(f.value)}</td>
      <td className="py-1.5 text-text-secondary">
        {f.source}
        {f.substituted && <span className="ml-1 text-[10px] text-risk-medium">подставлено</span>}
        {loaded && <span className="ml-1 text-[10px]">· справочник от {new Date(loaded).toLocaleDateString('ru-RU')}</span>}
      </td>
    </tr>
  )
}

/**
 * Карточка пары: работа с находкой (статус пары хост × CVE), формула риска с числами
 * и происхождение каждого члена: вероятность эксплуатации × тяжесть × ценность хоста.
 */
export function RiskDrawer({ item, onClose, onChanged }: Props) {
  const open = item !== null
  const card = useRiskCard(item?.host_id, item?.cve_id)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open, item?.host_id, item?.cve_id])

  const d = card.data
  const r = d?.risk

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside
        role="dialog"
        aria-label="Расчёт риска"
        aria-hidden={!open}
        className={cn('fixed top-0 right-0 z-40 flex h-full w-[520px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}
      >
        {item && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="min-w-0">
                <div className="font-mono text-sm text-text">{item.cve_id}</div>
                <div className="truncate font-mono text-xs text-text-secondary" title={item.hostname}>{item.hostname} {item.ip && `(${item.ip})`}</div>
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)">
                <X size={16} aria-hidden />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              <div className="mb-4 border-b border-grid pb-4">
                <FindingWorkBlock module="vm" scopeId={0} findingKey={item.key} title={`${item.cve_id} на ${item.hostname}`} severity={item.level} onChanged={onChanged} />
              </div>
              {card.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {card.isError && <p className="text-kind-1">Не удалось загрузить карточку расчёта.</p>}
              {d && r && (
                <>
                  <div className="mb-3 flex items-center justify-between rounded border border-grid bg-app-bg px-3 py-2">
                    <RiskBadge score={r.score} level={r.level} />
                    <span className="text-[11px] text-text-secondary">порог {r.threshold}{r.score >= r.threshold ? ' — требует действия' : ''}</span>
                  </div>

                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Формула</div>
                  <code className="mb-1 block rounded border border-grid bg-app-bg px-2 py-1.5 font-mono text-[11px] text-text">
                    {num2(r.likelihood.value)} × {num2(r.severity.value)} × {num2(r.value.value)} × 100 = {r.score}
                  </code>
                  <p className="mb-3 text-[11px] text-text-secondary">
                    вероятность эксплуатации × тяжесть × ценность хоста
                    {/* Балл — сохранённый при последнем пересчёте, части — по текущим весам: после смены весов они расходятся до пересчёта.
                        Порядок умножения и округление — как в SQL пересчёта, иначе половинки давали бы ложное расхождение. */}
                    {Math.floor(r.likelihood.value * r.severity_parts.cvss.value * r.severity_parts.reach.value * r.value.value * 100 + 0.5) !== r.score && ' · части посчитаны по текущим весам, балл — по последнему пересчёту'}
                  </p>
                  <table className="mb-4 w-full">
                    <tbody>
                      <FactorRow label="Вероятность эксплуатации" f={r.likelihood} total />
                      <FactorRow label="· KEV" f={r.likelihood_parts.kev} loaded={d.refs_loaded_at.kev} />
                      <FactorRow label="· EPSS" f={r.likelihood_parts.epss} loaded={d.refs_loaded_at.epss} />
                      <FactorRow label="· эксплойт ExploitDB" f={r.likelihood_parts.exploit} loaded={d.refs_loaded_at.exploitdb} />
                      <FactorRow label="· модуль Metasploit" f={r.likelihood_parts.msf} loaded={d.refs_loaded_at.msf} />
                      <FactorRow label="Тяжесть" f={r.severity} total />
                      <FactorRow label="· CVSS ÷ 10" f={r.severity_parts.cvss} loaded={d.refs_loaded_at.nvd} />
                      <FactorRow label="· достижимость" f={r.severity_parts.reach} />
                      <FactorRow label="Ценность хоста" f={r.value} total />
                      <FactorRow label="· критичность" f={r.value_parts.criticality} />
                      <FactorRow label="· конфиденциальные данные" f={r.value_parts.confidential} />
                      <FactorRow label="· доступ из интернета" f={r.value_parts.internet} />
                    </tbody>
                  </table>
                  {(r.value_parts.internet.substituted || r.value_parts.criticality.substituted || r.likelihood_parts.kev.substituted) && (
                    <p className="mb-4 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-[11px] text-text-secondary">
                      {r.value_parts.internet.substituted && <>Зона «{d.host.zone || '—'}» не размечена — доступ из интернета и конфиденциальные данные взяты как «нет». <Link to="/vm/settings#zones" className="text-text underline">Разметить зоны</Link>. </>}
                      {r.value_parts.criticality.substituted && <>Критичность хоста в VM не задана — учтена как None. </>}
                      {/* Без каталога «нет в KEV» не факт: эксплуатируемая CVE считается только по EPSS и эксплойтам. */}
                      {r.likelihood_parts.kev.substituted && <>Справочник CISA KEV не загружен — факт эксплуатации не учтён. <Link to="/vm/settings" className="text-text underline">Загрузить справочники</Link>.</>}
                    </p>
                  )}

                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">CVE</div>
                  <p className="mb-2 leading-relaxed text-text">{d.cve.description ?? <span className="text-text-secondary">описания нет — CVE отсутствует в загруженном NVD</span>}</p>
                  <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-text-secondary">
                    <dt>CVSS</dt><dd className="font-mono text-text">{d.cve.cvss ?? '—'} <span className="text-[10px] text-text-secondary">{CVSS_SOURCE_LABELS[d.cve.cvss_source]}</span></dd>
                    <dt>EPSS</dt><dd className="font-mono text-text">{d.cve.epss === null ? '—' : `${d.cve.epss.toFixed(4)} (перцентиль ${((d.cve.epss_percentile ?? 0) * 100).toFixed(0)})`}</dd>
                    {d.cve.kev && (
                      <>
                        <dt>CISA KEV</dt>
                        <dd className="text-risk-critical">
                          {d.cve.kev_added ? `с ${day(d.cve.kev_added)}` : 'в каталоге'}
                          {d.cve.kev_ransomware && ', ransomware'}
                          {d.cve.kev_due && `, срок CISA ${day(d.cve.kev_due)}`}
                        </dd>
                      </>
                    )}
                    <dt>Опубликована</dt><dd className="text-text">{d.cve.published ? new Date(d.cve.published).toLocaleDateString('ru-RU') : '—'}</dd>
                    <dt>NVD</dt><dd><a href={d.cve.nvd_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-text underline">{d.cve.cve_id} <ExternalLink size={11} aria-hidden /></a></dd>
                  </dl>
                  {d.cve.exploits.length > 0 && (
                    <>
                      <div className="mb-1 text-[11px] text-text-secondary">ExploitDB</div>
                      <ul className="mb-3 flex flex-col gap-0.5">
                        {d.cve.exploits.map((e) => (
                          <li key={e.exploit_id} className="font-mono text-text-secondary">
                            <a href={`https://www.exploit-db.com/exploits/${e.exploit_id}`} target="_blank" rel="noreferrer" className="text-text underline">EDB-{e.exploit_id}</a> {e.type}{e.verified ? ' · проверен' : ''}{e.published ? ` · ${e.published}` : ''}
                          </li>
                        ))}
                      </ul>
                    </>
                  )}
                  {d.cve.msf_modules.length > 0 && (
                    <>
                      <div className="mb-1 text-[11px] text-text-secondary">Metasploit</div>
                      <ul className="mb-3 flex flex-col gap-0.5">
                        {d.cve.msf_modules.map((m) => (
                          <li key={m.fullname} className="truncate font-mono text-text-secondary" title={m.fullname}>{m.fullname} <span className="text-[10px]">rank {m.rank}</span></li>
                        ))}
                      </ul>
                    </>
                  )}

                  <div className="mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase">Хост</div>
                  <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-text-secondary">
                    <dt>ОС</dt><dd className="text-text">{d.host.os_name || '—'}</dd>
                    <dt>Критичность</dt><dd className="text-text">{d.host.criticality || 'не задана'}</dd>
                    <dt>Зона</dt><dd className="text-text">{d.host.zone || '—'} {d.host.zone_marked ? `· интернет: ${d.host.internet_access ? 'да' : 'нет'}, конф. данные: ${d.host.confidential_data ? 'да' : 'нет'}` : '· не размечена'}</dd>
                    {d.host.groups && <><dt>Группы</dt><dd className="text-text">{d.host.groups}</dd></>}
                  </dl>
                  <div className="flex flex-wrap gap-3 text-[11px]">
                    <Link to={`/vm/vulns?host_id=${d.host.id}`} onNavigate={onClose} className="text-text underline">все уязвимости хоста</Link>
                    <Link to={`/vm/vulns?cve=${d.cve.cve_id}`} onNavigate={onClose} className="text-text underline">все хосты с этой CVE</Link>
                    <AssetLink source="vm" hostKey={`${d.host.hostname}|${d.host.ip}`} onNavigate={onClose} />
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
