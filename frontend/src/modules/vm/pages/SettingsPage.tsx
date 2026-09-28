import { useVmSettings } from '@/modules/vm/api/queries'
import { ModuleSettingsPage } from '@/platform/collector/SettingsPage'
import { VmConnection } from './settings/VmConnection'
import { FileImport } from './settings/FileImport'
import { ZonesSection } from './settings/ZonesSection'
import { WeightsSection } from './settings/WeightsSection'
import { AttackThresholdSection } from './settings/AttackThresholdSection'
import { ReferencesSection } from './settings/ReferencesSection'

/** Всё, что человек настраивает и загружает в модуль, — в одном месте. */
export function SettingsPage() {
  const settings = useVmSettings()
  return (
    <ModuleSettingsPage settings={settings} about="Подключение к MaxPatrol VM, импорт, разметка зон, веса формулы и справочники. Файлы остаются внутри периметра.">
      {(data) => (
        <>
          <VmConnection settings={data} />
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
