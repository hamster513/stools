import { useEffect, useRef } from 'react'
import { ExternalLink, X } from 'lucide-react'
import { useImageCard } from '@/modules/vm/api/queries'
import type { ImageVulnItem } from '@/modules/vm/api/types'
import { CVSS_SOURCE_LABELS } from '@/modules/vm/api/types'
import { RiskBadge } from '@/modules/vm/components/RiskBadge'
import { Spinner } from '@/components/ui/Spinner'
import { cn } from '@/lib/cn'
import { FactorRow } from '../vulns/RiskDrawer'
import { TrivyBadge } from './ImageVulnsTable'

interface Props {
  imageId: number
  item: ImageVulnItem | null
  onClose: () => void
}

/** Члены формулы — ровно два знака, как в строке `0,82 × 0,98 × 1,00 × 100 = 81`. */
function num2(v: number): string {
  return v.toLocaleString('ru-RU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

/** Ссылка из отчёта Trivy приходит снаружи: переходим только по http(s). */
function safeLink(url: string | null): string | null {
  return url && /^https?:\/\//i.test(url) ? url : null
}

const SECTION = 'mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'
const EXTERNAL = 'inline-flex items-center gap-1 text-text underline'

/**
 * Находка образа: данные Trivy и, для CVE из справочника, расчёт риска — вероятность
 * эксплуатации × тяжесть × ценность. У образа нет хоста: ценность одна для всех образов.
 */
export function ImageRiskDrawer({ imageId, item, onClose }: Props) {
  const open = item !== null
  const card = useImageCard(imageId, item)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open, item?.cve_id, item?.package, item?.installed_version])

  const d = card.data
  const r = d?.factors
  const link = item ? safeLink(item.link) : null

  return (
    <>
      <div className={cn('fixed inset-0 z-30 bg-black/50 transition-opacity duration-200', open ? 'opacity-100' : 'pointer-events-none opacity-0')} onClick={onClose} aria-hidden />
      <aside
        role="dialog"
        aria-label="Расчёт риска находки образа"
        aria-hidden={!open}
        className={cn('fixed top-0 right-0 z-40 flex h-full w-[520px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}
      >
        {item && (
          <>
            <div className="flex items-center justify-between border-b border-grid px-4 py-3">
              <div className="min-w-0">
                <div className={cn('truncate font-mono text-sm text-text', !item.is_cve && 'italic')} title={item.cve_id}>{item.cve_id}</div>
                <div className="truncate font-mono text-xs text-text-secondary" title={`${item.package} ${item.installed_version}`}>
                  {item.package} {item.installed_version}
                </div>
              </div>
              <button ref={closeRef} type="button" onClick={onClose} className="rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring" aria-label="Свернуть (Esc)">
                <X size={16} aria-hidden />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
              {item.is_cve && card.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
              {item.is_cve && card.isError && <p className="mb-3 text-kind-1">Не удалось загрузить расчёт риска.</p>}

              {item.is_cve && d && r && (
                <>
                  <div className="mb-3 flex items-center justify-between rounded border border-grid bg-app-bg px-3 py-2">
                    <RiskBadge score={r.score} level={r.level} />
                    <span className="text-[11px] text-text-secondary">порог {r.threshold}{r.score >= r.threshold ? ' — требует действия' : ''}</span>
                  </div>

                  <div className={SECTION}>Формула</div>
                  <code className="mb-1 block rounded border border-grid bg-app-bg px-2 py-1.5 font-mono text-[11px] text-text">
                    {num2(r.likelihood.value)} × {num2(r.severity.value)} × {num2(r.value.value)} × 100 = {r.score}
                  </code>
                  <p className="mb-3 text-[11px] text-text-secondary">
                    вероятность эксплуатации × тяжесть × ценность
                    {/* Балл — сохранённый при последнем пересчёте, части — по текущим весам: после смены весов они расходятся до пересчёта. */}
                    {Math.floor(r.likelihood.value * r.severity_parts.cvss.value * r.severity_parts.reach.value * r.value.value * 100 + 0.5) !== r.score && ' · части посчитаны по текущим весам, балл — по последнему пересчёту'}
                  </p>
                  <table className="mb-2 w-full">
                    <tbody>
                      <FactorRow label="Вероятность эксплуатации" f={r.likelihood} total />
                      <FactorRow label="· KEV" f={r.likelihood_parts.kev} />
                      <FactorRow label="· EPSS" f={r.likelihood_parts.epss} />
                      <FactorRow label="· эксплойт ExploitDB" f={r.likelihood_parts.exploit} />
                      <FactorRow label="· модуль Metasploit" f={r.likelihood_parts.msf} />
                      <FactorRow label="Тяжесть" f={r.severity} total />
                      <FactorRow label="· CVSS ÷ 10" f={r.severity_parts.cvss} />
                      <FactorRow label="· достижимость" f={r.severity_parts.reach} />
                      <FactorRow label="Ценность" f={r.value} total />
                    </tbody>
                  </table>
                  <p className="mb-4 rounded border border-grid bg-app-bg px-3 py-2 text-[11px] text-text-secondary">
                    Образ: ценность одинаковая для всех образов, доступ из интернета не учитывается.
                  </p>
                </>
              )}
              {item.is_cve && d && !r && (
                <p className="mb-4 rounded border border-risk-medium/40 bg-risk-medium/5 px-3 py-2 text-[11px] text-text-secondary">
                  Расчёта нет: {item.cve_id} отсутствует в загруженном NVD. Загрузите справочники в настройках модуля VM — риск появится после пересчёта.
                </p>
              )}
              {!item.is_cve && (
                <p className="mb-4 rounded border border-grid bg-app-bg px-3 py-2 text-[11px] text-text-secondary">
                  Идентификатор не из CVE ({item.cve_id}): риск не рассчитывается, ниже — данные из отчёта Trivy.
                </p>
              )}

              <div className={SECTION}>Trivy</div>
              <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-text-secondary">
                <dt>Оценка</dt><dd><TrivyBadge severity={item.trivy_severity} /></dd>
                <dt>CVSS</dt><dd className="font-mono text-text">{item.trivy_cvss ?? '—'}</dd>
                <dt>Пакет</dt><dd className="break-all font-mono text-text">{item.package}</dd>
                <dt>Установлена</dt><dd className="break-all font-mono text-text">{item.installed_version || '—'}</dd>
                <dt>Исправлена</dt><dd className="break-all font-mono text-text">{item.fixed_version || <span className="font-sans text-text-secondary">нет</span>}</dd>
                {link && (
                  <>
                    <dt>Ссылка</dt>
                    <dd className="min-w-0 break-all"><a href={link} target="_blank" rel="noreferrer" className={EXTERNAL}>{link} <ExternalLink size={11} className="shrink-0" aria-hidden /></a></dd>
                  </>
                )}
              </dl>
              {item.description && (
                <>
                  <div className={SECTION}>Описание</div>
                  <p className="mb-3 leading-relaxed text-text">{item.description}</p>
                </>
              )}

              {item.is_cve && d?.factors && (
                <>
                  <div className={SECTION}>CVE</div>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-text-secondary">
                    <dt>CVSS</dt>
                    <dd className="font-mono text-text">{item.cvss ?? '—'} {item.cvss_source && <span className="text-[10px] text-text-secondary">{CVSS_SOURCE_LABELS[item.cvss_source]}</span>}</dd>
                    <dt>EPSS</dt><dd className="font-mono text-text">{item.epss === null ? '—' : item.epss.toFixed(4)}</dd>
                    <dt>CISA KEV</dt><dd className={item.kev ? 'text-risk-critical' : 'text-text'}>{item.kev ? 'в каталоге' : 'нет'}</dd>
                    {d.nvd_url && (
                      <>
                        <dt>NVD</dt>
                        <dd><a href={d.nvd_url} target="_blank" rel="noreferrer" className={EXTERNAL}>{item.cve_id} <ExternalLink size={11} aria-hidden /></a></dd>
                      </>
                    )}
                  </dl>
                </>
              )}
              {item.is_cve && d && !d.factors && d.nvd_url && (
                <a href={d.nvd_url} target="_blank" rel="noreferrer" className={EXTERNAL}>{item.cve_id} в NVD <ExternalLink size={11} aria-hidden /></a>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
