import { useAdSettings } from '@/modules/ad/api/queries'
import { useCan } from '@/lib/can'
import { ModuleSettingsPage } from '@/platform/collector/SettingsPage'
import { CaDataSection } from './settings/CaDataSection'
import { CollectorScript } from './settings/CollectorScript'
import { ExportUpload } from './settings/ExportUpload'
import { ConnectionsSection } from './settings/ConnectionsSection'
import { RulesSection } from './settings/RulesSection'

export function SettingsPage() {
  // Аудитору грузить нечем: сервер ответит 403, а в блоке загрузки, кроме
  // зоны для файла, ничего нет.
  const { write } = useCan()
  const settings = useAdSettings()
  return (
    <ModuleSettingsPage settings={settings} about="Два режима сбора — скрипт на доменной машине или подключение по LDAP из STools — дают одну и ту же выгрузку; проверки одни и те же.">
      {(data) => (
        <>
          <CollectorScript />
          {write && <ExportUpload />}
          <CaDataSection />
          <ConnectionsSection />
          <RulesSection settings={data} />
        </>
      )}
    </ModuleSettingsPage>
  )
}
