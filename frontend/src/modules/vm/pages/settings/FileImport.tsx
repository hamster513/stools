import { useRef, useState, type DragEvent } from 'react'
import { AlertTriangle, CheckCircle2, FileText, UploadCloud } from 'lucide-react'
import { ApiRequestError } from '@/api/client'
import { useImportState, useJob, useUploadImport } from '@/modules/vm/api/queries'
import { STAGE_LABELS } from '@/modules/vm/api/types'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Section } from '@/platform/collector/ui'

/** Импорт из файла: CSV-экспорт MaxPatrol VM или JSON первой итерации. */
export function FileImport() {
  // Аудитору зоны загрузки нет — ни клика, ни перетаскивания: сервер ответит
  // 403. Прогресс идущего импорта виден на экране «Задачи», итог прошлого —
  // строкой ниже.
  const { write } = useCan()
  const upload = useUploadImport()
  const state = useImportState()
  const [dragOver, setDragOver] = useState(false)
  const [jobId, setJobId] = useState<number | undefined>()
  const [localError, setLocalError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const job = useJob(jobId)
  const active = state.data?.active ?? null
  const shown = job.data ?? active
  const busy = upload.isPending || shown?.status === 'running'

  function handle(file: File) {
    setLocalError(null)
    const name = file.name.toLowerCase()
    if (!name.endsWith('.csv') && !name.endsWith('.json')) {
      setLocalError('Нужен CSV-экспорт MaxPatrol VM или JSON первой итерации.')
      return
    }
    upload.mutate(file, { onSuccess: (r) => setJobId(r.job_id) })
  }
  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) handle(f)
  }

  const error = localError ?? (upload.error instanceof ApiRequestError ? upload.error.message : upload.error ? 'Не удалось загрузить файл' : null) ?? (shown?.status === 'failed' ? shown.error : null)
  const last = state.data?.last

  return (
    <Section
      id="upload"
      title="Импорт из файла"
      about="Тот же экспорт, что отдаёт API MaxPatrol VM (CSV с «;»), или JSON первой итерации STools. Файл разбирается потоково — гигабайтные выгрузки проходят. Импорт заменяет текущее состояние целиком; разметка зон и справочники остаются."
    >
      {write && (
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => !busy && inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && !busy) inputRef.current?.click() }}
        aria-label="Выбрать файл выгрузки"
        className={cn(
          'flex flex-col items-center justify-center gap-3 rounded border-2 border-dashed px-6 py-10 text-center',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
          dragOver ? 'border-primary bg-primary/5' : 'border-grid bg-surface',
          busy ? 'cursor-default opacity-80' : 'cursor-pointer hover:border-border',
        )}
      >
        <input ref={inputRef} type="file" accept=".csv,.json" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) handle(f); e.target.value = '' }} />
        {!busy && shown?.status !== 'done' && (
          <>
            <UploadCloud size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden />
            <div className="text-sm text-text">Перетащите файл сюда или нажмите, чтобы выбрать</div>
          </>
        )}
        {busy && (
          <div className="w-full max-w-sm">
            <FileText size={28} strokeWidth={1.5} className="mx-auto mb-3 text-text-secondary" aria-hidden />
            <div className="text-xs text-text">{upload.isPending ? 'загрузка файла на сервер…' : `${STAGE_LABELS[shown?.stage ?? ''] ?? shown?.stage} — ${shown?.message ?? ''}`}</div>
            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-grid">
              <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${shown?.progress ?? (upload.isPending ? 3 : 0)}%` }} />
            </div>
          </div>
        )}
        {shown?.status === 'done' && !busy && (
          <>
            <CheckCircle2 size={28} className="text-kind-accepted" aria-hidden />
            <div className="text-sm text-text">Импорт завершён: {shown.message}</div>
          </>
        )}
      </div>
      )}
      {write && error && (
        <div role="alert" className="mt-3 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />
          <div className="flex-1">
            {error}
            <div className="mt-2"><Button onClick={() => { setJobId(undefined); setLocalError(null); upload.reset() }}>Попробовать снова</Button></div>
          </div>
        </div>
      )}
      {last && (
        <p className="mt-3 text-xs text-text-secondary">
          Последний импорт: {new Date(last.finished_at).toLocaleString('ru-RU')}, {last.source === 'vm' ? 'MaxPatrol VM' : last.filename} —{' '}
          <span className="font-mono tabular-nums">{last.hosts.toLocaleString('ru-RU')} хостов, {last.pairs.toLocaleString('ru-RU')} пар, {last.cves.toLocaleString('ru-RU')} CVE</span>
          {last.new_zones > 0 && `, новых зон: ${last.new_zones}`}
        </p>
      )}
    </Section>
  )
}
