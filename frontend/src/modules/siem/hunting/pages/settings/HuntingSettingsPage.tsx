import { Link } from '@/lib/router'
import { useScrollToAnchor } from '@/platform/settings/useScrollToAnchor'
import { HuntingSettings } from './HuntingSettings'

export function HuntingSettingsPage() {
  useScrollToAnchor(true)

  return (
    <div className="h-full overflow-y-auto p-6">
      <h1 className="mb-2 text-base font-semibold text-text">SIEM Threat Hunting</h1>
      <p className="mb-5 max-w-2xl text-xs text-text-secondary">
        Выполнение запросов хантов, хранение событий и папка сохранённых фильтров SIEM.
      </p>
      <div className="grid max-w-2xl gap-5">
        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Подключение к MaxPatrol</h2>
          <p className="text-xs text-text-secondary">
            Rules Analyzer и Threat Hunting используют общее подключение. Изменение сервера
            или API-токена применяется к обоим разделам.
          </p>
          <Link to="/settings/siem#kb" className="mt-2 inline-block text-xs text-primary hover:underline">
            Настроить подключение к MaxPatrol
          </Link>
        </section>
        <HuntingSettings />
      </div>
    </div>
  )
}
