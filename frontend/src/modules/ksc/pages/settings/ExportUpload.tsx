import { useJob, useUploadExport } from '@/modules/ksc/api/queries'
import { CollectorExportUpload } from '@/platform/collector/ExportUpload'

export function ExportUpload() {
  const upload = useUploadExport()
  return (
    <CollectorExportUpload
      upload={upload}
      useJob={useJob}
      fileError="Нужен файл выгрузки: .json или .json.gz."
      about="Файл скрипта или онлайн-сборщика (формат stools-ksc/1). Сервер определяется по имени из выгрузки; снапшот сравнивается с предыдущим по времени сбора."
    />
  )
}
