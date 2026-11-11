import type { ImagePullPolicy } from '@/modules/vm/api/types'

const labels = { allowed: 'Разрешено', blocked: 'Заблокировано', unknown: 'Недостаточно данных', not_applicable: 'Не применяется' }
const colors = { allowed: 'text-kind-accepted', blocked: 'text-kind-1', unknown: 'text-risk-medium', not_applicable: 'text-text-secondary' }
const severity: Record<string, string> = { none: 'любая', low: 'низкая', medium: 'средняя', high: 'высокая', critical: 'критическая' }
const stamp = (value: string | number) => new Date(value).toLocaleString('ru-RU')

export function PullPolicyBadge({ policy }: { policy?: ImagePullPolicy }) {
  const state = policy?.state ?? 'unknown'
  return <span className={colors[state]} title={policy?.reason ?? 'Выполните синхронизацию Harbor для получения политики.'}>{labels[state]}</span>
}

export function ImagePullPolicyDetails({ policy }: { policy?: ImagePullPolicy }) {
  return <details className="rounded border border-grid bg-surface p-3">
    <summary className="cursor-pointer font-medium">Скачивание по политике уязвимостей: <PullPolicyBadge policy={policy} /></summary>
    <div className="mt-3 space-y-2 text-xs">
      <p>{policy?.reason ?? 'Выполните синхронизацию Harbor для получения политики проекта.'}</p>
      {policy?.checked_at && <p className="text-text-secondary">Настройки получены: {stamp(policy.checked_at)}</p>}
      {policy?.enabled && <>
        <p>Порог блокировки: {severity[policy.threshold ?? ''] ?? 'не определён'} и выше.</p>
        <p>Исключения: {policy.allowlist_source === 'project' ? 'список проекта (заменяет общий)' : 'общий список Harbor'}.
          {policy.allowlist_expires_at ? ` Срок действия: ${stamp(policy.allowlist_expires_at * 1000)}.` : ' Без срока действия.'}
          {policy.allowlist_expired && <span className="text-kind-1"> Срок истёк, исключения не применяются.</span>}
        </p>
        {policy.evaluated && <p>Блокирующих уязвимостей: {policy.blocking_count} · Исключённых: {policy.excluded_count}</p>}
        {policy.blocking_cves.length > 0 && <p className="break-words text-kind-1">Блокируют: {policy.blocking_cves.join(', ')}{policy.blocking_count > policy.blocking_cves.length && ' …'}</p>}
        {policy.excluded_cves.length > 0 && <p className="break-words">Учтены исключения: {policy.excluded_cves.join(', ')}{policy.excluded_count > policy.excluded_cves.length && ' …'}</p>}
      </>}
      {policy?.error && <p className="text-kind-1">Не удалось прочитать настройки: {policy.error}. Подробности — в результате синхронизации Harbor.</p>}
      {policy?.signature_required && <p>В проекте также требуется подпись артефакта.</p>}
      <p className="text-text-secondary">Оценка по последним данным Harbor. Права на скачивание и наличие требуемой подписи здесь не проверяются. Исключения не удаляют уязвимости из отчёта.</p>
    </div>
  </details>
}
