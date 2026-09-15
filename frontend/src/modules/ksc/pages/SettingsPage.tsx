import { useCan } from '@/lib/can'
import { CollectorScript } from './settings/CollectorScript'
import { ExportUpload } from './settings/ExportUpload'

export function SettingsPage() {
  // Аудитору грузить нечем: сервер ответит 403, а в блоке загрузки, кроме
  // зоны для файла, ничего нет. Подключения и пороги проверок добавит Task 11.
  const { write } = useCan()
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Настройки и данные</h1>
        <p className="max-w-2xl text-xs text-text-secondary">Два режима сбора — скрипт внутри сети или подключение к Open API из STools — дают одну и ту же выгрузку; проверки одни и те же.</p>
      </div>
      <div className="flex max-w-5xl flex-col gap-4">
        <CollectorScript />
        {write && <ExportUpload />}
      </div>
    </div>
  )
}
