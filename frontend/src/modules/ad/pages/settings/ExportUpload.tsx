import { useJob, useUploadExport } from '@/modules/ad/api/queries'
import { CollectorExportUpload } from '@/platform/collector/ExportUpload'

export function ExportUpload() {
  const upload = useUploadExport()
  return (
    <CollectorExportUpload
      upload={upload}
      useJob={useJob}
      fileError="Нужен файл сборщика: .json или .json.gz."
      label="Выгрузка AD или данные ЦС (файлы сборщика)"
      about="Файл скрипта: выгрузка домена (stools-ad/1) или данные центра сертификации (stools-ad-ca/1) — формат определяется по содержимому. Домен определяется по SID из файла; снапшот сравнивается с предыдущим по времени сбора, данные ЦС сохраняются у домена и пересчитывают его последний снапшот."
    />
  )
}
