import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { ApiRequestError } from '@/api/client'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'

/** Экран «Настройки и данные» модуля: загрузка настроек и колонка блоков. */
export function ModuleSettingsPage<T>({ settings, about, children }: {
  settings: UseQueryResult<T, ApiRequestError>
  about: string
  children: (data: T) => ReactNode
}) {
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) {
    const msg = settings.error instanceof ApiRequestError ? settings.error.message : 'Не удалось загрузить настройки'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => settings.refetch()} /></div>
  }
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">{about}</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        {children(settings.data)}
      </div>
    </div>
  )
}
