import type { HarborSyncError, LastSyncView } from '../../api/types'

const stages: Record<HarborSyncError['stage'], string> = {
  project_policy: 'Чтение политики скачивания и CVE-исключений',
  repositories: 'Чтение списка репозиториев',
  artifacts: 'Чтение списка образов',
  report: 'Чтение отчёта об уязвимостях',
  unknown: 'Этап не сохранён',
}
const legacyHint = 'Причина не была сохранена старой версией STools. Повторите синхронизацию, чтобы получить подробности.'

function groupErrors(sync: LastSyncView) {
  const details = [...(sync.error_details ?? [])]
  const known = new Set(details.map(item => item.target))
  for (const target of sync.errors) {
    if (!known.has(target)) details.push({ target, stage: 'unknown', reason: null, http_status: null, hint: legacyHint })
  }
  const groups = new Map<string, { error: HarborSyncError; targets: Set<string> }>()
  for (const error of details) {
    const key = JSON.stringify([error.stage, error.reason, error.http_status, error.hint])
    const group = groups.get(key) ?? { error, targets: new Set<string>() }
    group.targets.add(error.target)
    groups.set(key, group)
  }
  return [...groups.values()]
}

export function HarborLastSync({ sync }: { sync: LastSyncView | null }) {
  if (!sync) return <p className="mt-3 text-xs text-text-secondary">Синхронизаций ещё не было.</p>
  const failed = sync.errors.length > 0
  return <section className="mt-3 space-y-2 text-xs" aria-label="Результат синхронизации Harbor">
    <p className={failed ? 'text-kind-1' : 'text-kind-accepted'}>
      {failed ? 'Синхронизация завершена с ошибками' : 'Синхронизация завершена без ошибок'}
      {' · '}{new Date(sync.finished_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })}
    </p>
    <p className="text-text-secondary">В базе образов: {sync.images}, пар образ–находка: {sync.cves}
      {sync.skipped_unscanned > 0 && `, без готового скана: ${sync.skipped_unscanned}`}
    </p>
    {failed && <details className="rounded border border-grid bg-surface p-3">
      <summary className="cursor-pointer font-medium text-kind-1">Подробности ошибок ({sync.errors.length})</summary>
      <div className="mt-3 space-y-3">
        <p>Объектов с ошибками: {sync.errors.length}. Данные проблемных проектов, репозиториев или отчётов не обновлены; ранее загруженные данные сохранены.</p>
        {groupErrors(sync).map(({ error, targets }, index) => <div key={index} className="space-y-1">
          <p className="font-medium text-kind-1">{error.reason ?? 'Причина ошибки не сохранена'}{error.http_status != null && ` · HTTP ${error.http_status}`}</p>
          <p className="text-text-secondary">{stages[error.stage]}</p>
          <p>{error.hint}</p>
          <details><summary className="cursor-pointer text-text-secondary">Проекты и репозитории ({targets.size})</summary>
            <ul className="mt-1 list-disc space-y-1 pl-4">{[...targets].map(target => <li key={target} className="break-all">{target}</li>)}</ul>
          </details>
        </div>)}
      </div>
    </details>}
  </section>
}
