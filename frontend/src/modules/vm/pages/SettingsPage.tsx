import { useVmSettings } from '@/modules/vm/api/queries'
import { ModuleSettingsPage } from '@/platform/collector/SettingsPage'
import { moduleTitle } from '@/platform/modules'
import { VmConnection } from './settings/VmConnection'
import { HarborSection } from './settings/HarborSection'
import { FileImport } from './settings/FileImport'
import { ZonesSection } from './settings/ZonesSection'
import { WeightsSection } from './settings/WeightsSection'
import { AttackThresholdSection } from './settings/AttackThresholdSection'
import { ReferencesSection } from './settings/ReferencesSection'

/** Всё, что человек настраивает и загружает в модуль, — в одном месте. */
export function SettingsPage() {
  const settings = useVmSettings()
  return (
    <ModuleSettingsPage settings={settings} title={moduleTitle('vm')} about="Подключение к MaxPatrol VM и Harbor, импорт, разметка зон, веса формулы и справочники. Файлы остаются внутри периметра.">
      {(data) => (
        <>
          <VmConnection settings={data} />
          <HarborSection />
          <FileImport />
          <ZonesSection />
          <WeightsSection settings={data} />
          <AttackThresholdSection settings={data} />
          <ReferencesSection />
        </>
      )}
    </ModuleSettingsPage>
  )
}
