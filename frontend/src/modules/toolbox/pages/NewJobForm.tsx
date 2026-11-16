import { useRef, useState, type DragEvent, type FormEvent } from 'react'
import { AlertTriangle, ArrowLeft, FileText, Lock, UploadCloud } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { FIELD } from '@/components/ui/Field'
import { useCan } from '@/lib/can'
import { cn } from '@/lib/cn'
import { Link, useRouter } from '@/lib/router'
import { Section } from '@/platform/collector/ui'
import { useCreateJob } from '../api/queries'
import { FILE_MAX, formatSize as size, KNOWN_EXTENSIONS, TEXT_MAX } from '../api/types'

type Mode = 'file' | 'text'

const TAB = 'rounded px-3 py-1 text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Новое задание: файл (до 200 МБ) или вставленный текст (до 1 МБ). Текст сервер сканирует сразу,
 * файл — в фоне; в обоих случаях после 202 — карточка задания, ход там.
 */
export function NewJobForm() {
  const { write } = useCan()
  const { navigate } = useRouter()
  const create = useCreateJob()
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [text, setText] = useState('')
  const [usersFromAd, setUsersFromAd] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  if (!write) {
    return <div className="p-6"><EmptyState icon={Lock} title="Только для аналитика и администратора" description="Загруженный файл и предпросмотр показывают настоящие значения — аудитору они не открываются." /></div>
  }

  const textBytes = new TextEncoder().encode(text).length
  const fileTooBig = file !== null && file.size > FILE_MAX
  const unknownExt = file !== null && !KNOWN_EXTENSIONS.some((ext) => file.name.toLowerCase().endsWith(ext))
  const ready = mode === 'file' ? file !== null && !fileTooBig && file.size > 0 : text.trim() !== '' && textBytes <= TEXT_MAX

  function pick(f: File | undefined) {
    if (f) { setFile(f); create.reset() }
  }
  function onDrop(e: DragEvent<HTMLDivElement>) { e.preventDefault(); setDragOver(false); pick(e.dataTransfer.files[0]) }
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!ready || create.isPending) return
    const form = new FormData()
    if (mode === 'file' && file) form.append('file', file)
    // Текст — файлом, а не строковым полем: строковое поле multipart браузер переводит в CRLF (размер
    // растёт, в результате другие переводы строк). Blob под именем `text` сервер не примет — поле
    // объявлено строкой, — поэтому `file` с именем text.txt: задание становится файловым.
    else form.append('file', new Blob([text], { type: 'text/plain' }), 'text.txt')
    form.append('users_from_ad', usersFromAd ? 'true' : 'false')
    create.mutate(form, { onSuccess: (r) => navigate(`/toolbox/scrub/${r.job_id}`) })
  }

  return (
    <form onSubmit={submit} className="h-full overflow-y-auto p-6">
      <Link to="/toolbox" className="mb-3 inline-flex items-center gap-1 text-xs text-text-secondary hover:text-text"><ArrowLeft size={13} aria-hidden />Задания</Link>
      <h2 className="mb-4 text-base font-semibold text-text">Новое задание</h2>
      <div className="max-w-3xl space-y-4">
        <Section title="Что очистить" about="Текстовые форматы и архивы с ними: json, json.gz, gz, zip (и вложенные), csv, txt, log, xml, conf, ini, yaml. Также Office (DOC/DOCX, XLS/XLSX, PPT/PPTX), RTF, ODT/ODS/ODP и письма EML/MSG с вложениями. Документ или письмо — до 64 МБ. Старые форматы преобразуются в DOCX/XLSX/PPTX и EML; изображения, макросы и непроверяемые части исключаются с отметкой в отчёте. PDF и OCR не поддерживаются.">
          <div className="mb-3 inline-flex gap-1 rounded border border-border p-0.5" role="tablist">
            {(['file', 'text'] as const).map((m) => (
              <button key={m} type="button" role="tab" aria-selected={mode === m} onClick={() => { setMode(m); create.reset() }} className={cn(TAB, mode === m ? 'bg-row-selected text-text' : 'text-text-secondary hover:text-text')}>
                {m === 'file' ? 'Файл' : 'Текст'}
              </button>
            ))}
          </div>

          {mode === 'file' ? (
            <>
              <div onDragOver={(e) => { e.preventDefault(); setDragOver(true) }} onDragLeave={() => setDragOver(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inputRef.current?.click() } }} aria-label="Выбрать файл" className={cn('flex cursor-pointer flex-col items-center justify-center gap-3 rounded border-2 border-dashed px-6 py-10 text-center hover:border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring', dragOver ? 'border-primary bg-primary/5' : 'border-grid bg-app-bg')}>
                <input ref={inputRef} type="file" className="hidden" onChange={(e) => { pick(e.target.files?.[0]); e.target.value = '' }} />
                {file ? (
                  <><FileText size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden /><div className="text-sm text-text">{file.name}</div><div className="font-mono text-xs text-text-secondary">{size(file.size)} · нажмите, чтобы выбрать другой</div></>
                ) : (
                  <><UploadCloud size={28} strokeWidth={1.5} className="text-text-secondary" aria-hidden /><div className="text-sm text-text">Перетащите файл сюда или нажмите, чтобы выбрать</div><div className="text-xs text-text-secondary">до 200 МБ</div></>
                )}
              </div>
              {fileTooBig && <p role="alert" className="mt-2 text-xs text-kind-1">Файл {size(file.size)} — больше 200 МБ. Разбейте выгрузку на части.</p>}
              {file !== null && file.size === 0 && <p role="alert" className="mt-2 text-xs text-kind-1">Файл пустой.</p>}
              {file !== null && !fileTooBig && unknownExt && <p className="mt-2 flex items-center gap-1.5 text-xs text-text-secondary"><AlertTriangle size={13} className="text-risk-medium" aria-hidden />Расширение не из списка — файл будет прочитан как текст; двоичный файл сервер отклонит.</p>}
            </>
          ) : (
            <>
              <textarea className={cn(FIELD, 'min-h-[240px] font-mono text-xs')} value={text} onChange={(e) => setText(e.target.value)} placeholder="Вставьте фрагмент лога, конфига или переписки" aria-label="Текст для очистки" spellCheck={false} />
              <div className={cn('mt-1 text-right font-mono text-[11px] tabular-nums', textBytes > TEXT_MAX ? 'text-kind-1' : 'text-text-secondary')}>
                {size(textBytes)} из 1 МБ{textBytes > TEXT_MAX && ' — слишком много, загрузите файлом'}
              </div>
            </>
          )}

          <label className="mt-3 flex items-start gap-2 text-xs text-text">
            <input type="checkbox" className="mt-0.5" checked={usersFromAd} onChange={(e) => setUsersFromAd(e.target.checked)} />
            <span>Учётные записи из последнего снапшота AD<span className="block text-text-secondary">Искать в тексте sAMAccountName пользователей домена; для крупного домена сканирование дольше на секунды.</span></span>
          </label>
        </Section>

        {create.error && <div role="alert" className="flex items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{create.error.message}</div>}

        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={!ready} loading={create.isPending}>Сканировать</Button>
          <span className="text-xs text-text-secondary">{create.isPending && mode === 'file' ? 'загрузка файла…' : 'Сначала только поиск: заменит значения кнопка «Очистить» после предпросмотра.'}</span>
        </div>
      </div>
    </form>
  )
}
