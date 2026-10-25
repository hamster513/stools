import { useKscSettings } from '@/modules/ksc/api/queries'
import { useCan } from '@/lib/can'
import { ModuleSettingsPage } from '@/platform/collector/SettingsPage'
import { moduleTitle } from '@/platform/modules'
import { CollectorScript } from './settings/CollectorScript'
import { ExportUpload } from './settings/ExportUpload'
import { ConnectionsSection } from './settings/ConnectionsSection'
import { RulesSection } from './settings/RulesSection'

export function SettingsPage() {
  // Аудитору грузить нечем: сервер ответит 403, а в блоке загрузки, кроме
  // зоны для файла, ничего нет.
  const { write } = useCan()
  const settings = useKscSettings()
  return (
    <ModuleSettingsPage settings={settings} title={moduleTitle('ksc')} about="Два режима сбора — скрипт внутри сети или подключение к Open API из STools — дают одну и ту же выгрузку; проверки одни и те же.">
      {(data) => (
        <>
          <CollectorScript />
          {write && <ExportUpload />}
          <ConnectionsSection />
          <RulesSection settings={data} />
        </>
      )}
    </ModuleSettingsPage>
  )
}
