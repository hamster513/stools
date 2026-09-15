import { ApiRequestError } from '@/api/client'
import { useVmSettings } from '@/modules/vm/api/queries'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { VmConnection } from './settings/VmConnection'
import { FileImport } from './settings/FileImport'
import { ZonesSection } from './settings/ZonesSection'
import { WeightsSection } from './settings/WeightsSection'
import { AttackThresholdSection } from './settings/AttackThresholdSection'
import { ReferencesSection } from './settings/ReferencesSection'

/** Всё, что человек настраивает и загружает в модуль, — в одном месте. */
export function SettingsPage() {
  const settings = useVmSettings()
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) {
    const msg = settings.error instanceof ApiRequestError ? settings.error.message : 'Не удалось загрузить настройки'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => settings.refetch()} /></div>
  }
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">
          Подключение к MaxPatrol VM, импорт, разметка зон, веса формулы и справочники. Файлы остаются внутри периметра.
        </p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <VmConnection settings={settings.data} />
        <FileImport />
        <ZonesSection />
        <WeightsSection settings={settings.data} />
        <AttackThresholdSection settings={settings.data} />
        <ReferencesSection />
      </div>
    </div>
  )
}
