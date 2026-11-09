import type { Trend } from '../../api/trends'
const labels = { critical: 'Критическая', high: 'Высокая', medium: 'Средняя', low: 'Низкая', none: 'Нулевая', unknown: 'Нет данных' }
const colors = { critical: 'text-risk-critical', high: 'text-risk-high', medium: 'text-risk-medium', low: 'text-risk-low', none: 'text-text-secondary', unknown: 'text-text-secondary' }
const sources: Record<string, string> = { collector_nvd: 'NVD · сборщик', collector_cna: 'CNA · сборщик', collector_unknown: 'Сборщик', nvd_v3: 'NVD', nvd_v2: 'NVD', trivy: 'Trivy', none: 'Локальные данные' }
export function SeverityBadge({ value }: { value: Pick<Trend, 'severity' | 'cvss' | 'cvss_source' | 'cvss_version'> }) {
  const level = value.severity ?? 'unknown'
  return <span className="inline-flex flex-col gap-0.5" title="Критичность уязвимости; не оценка локального риска">
    <span className={`font-semibold ${colors[level]}`}>{labels[level]}{value.cvss != null ? ` · ${value.cvss.toFixed(1)}` : ''}</span>
    <span className="text-[11px] text-text-secondary">{value.cvss != null ? `CVSS${value.cvss_version ? ' ' + value.cvss_version : ''} · ` : level !== 'unknown' ? 'Оценка ' : 'CVSS не получен'}{(value.cvss != null || level !== 'unknown') && (sources[value.cvss_source] || value.cvss_source || 'Источник не указан')}</span>
  </span>
}
