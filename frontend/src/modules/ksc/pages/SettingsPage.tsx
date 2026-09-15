import { ApiRequestError } from '@/api/client'
import { useKscSettings } from '@/modules/ksc/api/queries'
import { ErrorState } from '@/components/ui/ErrorState'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { CollectorScript } from './settings/CollectorScript'
import { ExportUpload } from './settings/ExportUpload'
import { ConnectionsSection } from './settings/ConnectionsSection'
import { RulesSection } from './settings/RulesSection'

export function SettingsPage() {
  // Аудитору грузить нечем: сервер ответит 403, а в блоке загрузки, кроме
  // зоны для файла, ничего нет.
  const { write } = useCan()
  const settings = useKscSettings()
  if (settings.isLoading) return <FullPageSpinner />
  if (settings.isError || !settings.data) {
    const msg = settings.error instanceof ApiRequestError ? settings.error.message : 'Не удалось загрузить настройки'
    return <div className="p-6"><ErrorState message={msg} onRetry={() => settings.refetch()} /></div>
  }
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Два режима сбора — скрипт внутри сети или подключение к Open API из STools — дают одну и ту же выгрузку; проверки одни и те же.</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <CollectorScript />
        {write && <ExportUpload />}
        <ConnectionsSection />
        <RulesSection settings={settings.data} />
      </div>
    </div>
  )
}
