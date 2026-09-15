import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react'
import { AlertTriangle, CheckCircle2, FileArchive, UploadCloud } from 'lucide-react'
import { useJobStatus, useUploadSnapshot } from '@/modules/siem/api/queries'
import { ApiRequestError } from '@/api/client'
import type { JobStage } from '@/modules/siem/api/types'
import { useRouter } from '@/lib/router'
import { cn } from '@/lib/cn'
import { Button } from '@/components/ui/Button'

/**
 * Загрузка выгрузки правил.
 *
 * Живёт в настройках рядом с остальными файлами: человек, которому нужно
 * что-то загрузить, ищет одно место, а не вспоминает, какой файл в каком
 * экране. Разбор идёт заданием, и прогресс показывается здесь же —
 * увести человека со страницы в этот момент значит потерять его.
 */
const STAGES: { key: JobStage; label: string }[] = [
  { key: 'parsing', label: 'Разбор' },
  { key: 'analyzing', label: 'Анализ' },
  { key: 'persisting', label: 'Запись' },
]

function stageIndex(stage: JobStage): number {
  return STAGES.findIndex((s) => s.key === stage)
}

export function SnapshotUpload() {
  const { navigate } = useRouter()
  const [dragOver, setDragOver] = useState(false)
  const [jobId, setJobId] = useState<number | undefined>(undefined)
  const [snapshotId, setSnapshotId] = useState<number | undefined>(undefined)
  const [localError, setLocalError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const upload = useUploadSnapshot()
  const job = useJobStatus(jobId, { enabled: jobId !== undefined })

  useEffect(() => {
    if (job.data?.status === 'done' && snapshotId !== undefined) {
      navigate(`/siem/snapshots/${snapshotId}/hygiene`, { replace: true })
    }
  }, [job.data?.status, snapshotId, navigate])

  const handleFile = useCallback(
    (file: File) => {
      setLocalError(null)
      if (!file.name.toLowerCase().endsWith('.zip')) {
        setLocalError('Нужен zip-архив выгрузки базы знаний MaxPatrol SIEM.')
        return
      }
      upload.mutate(file, {
        onSuccess: (res) => {
          setSnapshotId(res.snapshot_id)
          if (res.duplicate) {
            // Тот же архив уже разбирался — открываем существующий снапшот,
            // не запускаем разбор заново.
            navigate(`/siem/snapshots/${res.snapshot_id}/hygiene`, { replace: true })
            return
          }
          setJobId(res.job_id)
        },
      })
    },
    [upload, navigate],
  )

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }

  const uploadError =
    upload.error instanceof ApiRequestError ? upload.error.message : upload.error ? 'Не удалось загрузить архив' : null
  const jobError = job.data?.error ?? null
  const errorMessage = localError ?? uploadError ?? jobError

  const isBusy = upload.isPending || (jobId !== undefined && job.data?.status === 'running')
  const currentStageIndex = job.data ? stageIndex(job.data.stage) : -1

  function reset() {
    setJobId(undefined)
    setSnapshotId(undefined)
    setLocalError(null)
    upload.reset()
  }

  return (
    <section className="rounded border border-grid bg-surface p-4">
      <div className="mb-3">
        <h2 className="mb-1 text-sm font-semibold text-text">Выгрузка правил</h2>
        <p className="text-xs text-text-secondary">
          Zip-архив выгрузки базы знаний MaxPatrol SIEM — то, что продукт разбирает и проверяет.
          Повторная загрузка того же архива откроет уже разобранный снапшот, а не разберёт его заново.
        </p>
      </div>

        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => !isBusy && inputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isBusy) inputRef.current?.click()
          }}
          aria-label="Выбрать zip-архив для загрузки"
          className={cn(
            'flex flex-col items-center justify-center gap-3 rounded border-2 border-dashed px-6 py-12 text-center transition-[transform,opacity] duration-150',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
            dragOver ? 'border-primary bg-primary/5 scale-[1.01]' : 'border-grid bg-surface',
            isBusy ? 'cursor-default opacity-80' : 'cursor-pointer hover:border-border',
          )}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) handleFile(file)
              e.target.value = ''
            }}
          />

          {!isBusy && job.data?.status !== 'done' && (
            <>
              <UploadCloud size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden />
              <div className="text-sm text-text">Перетащите архив сюда или нажмите, чтобы выбрать файл</div>
            </>
          )}

          {isBusy && (
            <div className="w-full max-w-xs">
              <FileArchive size={28} strokeWidth={1.5} className="mx-auto mb-3 text-text-secondary" aria-hidden />
              <div className="flex justify-between text-xs text-text-secondary">
                {STAGES.map((s, i) => (
                  <span key={s.key} className={cn(i <= currentStageIndex && 'text-text')}>
                    {s.label}
                  </span>
                ))}
              </div>
              <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-grid">
                <div
                  className="h-full rounded-full bg-primary transition-[transform] duration-300"
                  style={{ width: `${job.data?.progress ?? (upload.isPending ? 3 : 0)}%` }}
                />
              </div>
              <div className="mt-2 font-mono text-xs tabular-nums text-text-secondary">
                {upload.isPending ? 'загрузка файла…' : `${job.data?.progress ?? 0}%`}
              </div>
            </div>
          )}

          {job.data?.status === 'done' && (
            <>
              <CheckCircle2 size={28} className="text-kind-accepted" aria-hidden />
              <div className="text-sm text-text">Готово, открываю снапшот…</div>
            </>
          )}
        </div>

        {errorMessage && (
          <div role="alert" className="mt-4 flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />
            <div className="flex-1 text-sm text-text">
              {errorMessage}
              <div className="mt-2">
                <Button variant="secondary" onClick={reset}>
                  Попробовать снова
                </Button>
              </div>
            </div>
          </div>
      )}
    </section>
  )
}
