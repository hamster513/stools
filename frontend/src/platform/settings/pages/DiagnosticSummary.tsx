import type { Summary } from '../api/diagnostics'

const LABELS: Record<string, string> = {
  asset: 'Хосты', asset_observation: 'Наблюдения хостов',
  asset_user: 'Пользователи', asset_user_observation: 'Наблюдения пользователей',
  asset_user_host: 'Связи хостов и пользователей', asset_user_group: 'Группы пользователей',
  asset_group: 'Группы', asset_group_member: 'Членство в группах', asset_group_gpo: 'Связи групп и политик AD',
  ad_domain: 'Домены AD', ad_snapshot: 'Снимки AD', ad_exports: 'Выгрузки AD',
  ksc_server: 'Серверы KSC', ksc_snapshot: 'Снимки KSC', ksc_host: 'Хосты KSC',
  ksc_policy: 'Политики KSC', ksc_policy_scope: 'Области действия политик KSC',
  ksc_profile: 'Профили политик KSC', ksc_net_rule: 'Сетевые правила KSC',
  ksc_policy_firewall: 'Настройки межсетевого экрана KSC',
}
export function DiagnosticSummary({ summary }: { summary: Summary }) {
  return <div className="space-y-3 text-sm">
    <details><summary className="cursor-pointer font-medium">Состав пакета · {Object.values(summary.counts).reduce((sum, count) => sum + count, 0)} записей</summary>
      <dl className="mt-2 grid gap-2 sm:grid-cols-2">{Object.entries(summary.counts).map(([key, count]) => <div key={key} className="flex justify-between gap-4 rounded bg-app-bg px-3 py-2"><dt>{LABELS[key] ?? 'Дополнительные записи'}</dt><dd className="tabular-nums">{count}</dd></div>)}</dl>
    </details>
    {summary.limitations.length > 0 && <div><h3 className="font-medium">Ограничения пакета</h3><ul className="mt-1 list-disc space-y-1 pl-5 text-text-secondary">{summary.limitations.map((note, index) => <li key={index}>{note}</li>)}</ul></div>}
  </div>
}
