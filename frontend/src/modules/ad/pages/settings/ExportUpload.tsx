import { useJob, useUploadExport } from '@/modules/ad/api/queries'
import { CollectorExportUpload } from '@/platform/collector/ExportUpload'

export function ExportUpload() {
  const upload = useUploadExport()
  return (
    <CollectorExportUpload
      upload={upload}
      useJob={useJob}
      fileError="Нужен файл выгрузки скрипта: .json или .json.gz."
      about="Файл скрипта (формат stools-ad/1). Домен определяется по SID из выгрузки; снапшот сравнивается с предыдущим по времени сбора."
    />
  )
}
