import { useRef, useState, type DragEvent } from 'react'
import { AlertTriangle, CheckCircle2, FileText, UploadCloud } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useJob, useUploadExport } from '@/modules/ksc/api/queries'
import { STAGE_LABELS } from '@/modules/ksc/api/types'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import { Section } from './ui'

export function ExportUpload() {
  const upload = useUploadExport()
  const [dragOver, setDragOver] = useState(false)
  const [jobId, setJobId] = useState<number | undefined>()
  const [localError, setLocalError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const job = useJob(jobId)
  const busy = upload.isPending || job.data?.status === 'running'

  function handle(file: File) {
    setLocalError(null)
    const n = file.name.toLowerCase()
    if (!n.endsWith('.json') && !n.endsWith('.gz')) { setLocalError('Нужен файл выгрузки: .json или .json.gz.'); return }
    upload.mutate(file, { onSuccess: (r) => setJobId(r.job_id) })
  }
  function onDrop(e: DragEvent<HTMLDivElement>) { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handle(f) }
  const error = localError ?? (upload.error instanceof ApiRequestError ? upload.error.message : upload.error ? 'Не удалось загрузить' : null) ?? (job.data?.status === 'failed' ? job.data.error : null)

  return (
    <Section title="Загрузить выгрузку" about="Файл скрипта или онлайн-сборщика (формат stools-ksc/1). Сервер определяется по имени из выгрузки; снапшот сравнивается с предыдущим по времени сбора.">
      <div onDragOver={(e) => { e.preventDefault(); setDragOver(true) }} onDragLeave={() => setDragOver(false)} onDrop={onDrop} onClick={() => !busy && inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && !busy) inputRef.current?.click() }} aria-label="Выбрать файл выгрузки" className={cn('flex flex-col items-center justify-center gap-3 rounded border-2 border-dashed px-6 py-10 text-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', dragOver ? 'border-primary bg-primary/5' : 'border-grid bg-surface', busy ? 'cursor-default opacity-80' : 'cursor-pointer hover:border-border')}>
        <input ref={inputRef} type="file" accept=".json,.gz" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) handle(f); e.target.value = '' }} />
        {!busy && job.data?.status !== 'done' && <><UploadCloud size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden /><div className="text-sm text-text">Перетащите файл сюда или нажмите, чтобы выбрать</div></>}
        {busy && <div className="w-full max-w-sm"><FileText size={28} strokeWidth={1.5} className="mx-auto mb-3 text-text-secondary" aria-hidden /><div className="text-xs text-text">{upload.isPending ? 'загрузка файла…' : `${STAGE_LABELS[job.data?.stage ?? ''] ?? job.data?.stage} — ${job.data?.message ?? ''}`}</div></div>}
        {job.data?.status === 'done' && !busy && <><CheckCircle2 size={28} className="text-kind-accepted" aria-hidden /><div className="text-sm text-text">{job.data.message}</div></>}
      </div>
      {error && <div role="alert" className="mt-3 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden /><div className="flex-1">{error}<div className="mt-2"><Button onClick={() => { setJobId(undefined); setLocalError(null); upload.reset() }}>Попробовать снова</Button></div></div></div>}
    </Section>
  )
}
