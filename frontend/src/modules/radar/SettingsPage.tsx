import { useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { useCan } from '@/lib/can'
import { useRouter } from '@/lib/router'
import { sendFiles, type Preview, type Snapshot } from './api'

export function RadarSettingsPage() {
  const { write } = useCan('radar')
  const { navigate } = useRouter()
  const qc = useQueryClient()
  const input = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<File[]>([])
  const [error, setError] = useState('')
  const preview = useMutation({ mutationFn: (selected: File[]) => sendFiles<{ items: Preview[] }>('preview', selected) })
  const save = useMutation({ mutationFn: (selected: File[]) => sendFiles<{ items: Snapshot[] }>('import', selected), onSuccess: () => qc.invalidateQueries({ queryKey: ['radar'] }) })
  const busy = preview.isPending || save.isPending
  function select(list: FileList | null) {
    preview.reset(); save.reset(); setError('')
    const selected = Array.from(list ?? [])
    setFiles(selected)
    if (selected.length > 32) setError('Можно выбрать не более 32 файлов.')
    else if (selected.some(f => !f.name.toLowerCase().endsWith('.conf'))) setError('Выберите файлы имя-сервера.conf.')
    else if (selected.some(f => f.size > 2 * 1024 ** 2)) setError('Один файл не должен превышать 2 МиБ.')
    else if (selected.reduce((n, f) => n + f.size, 0) > 16 * 1024 ** 2) setError('Пачка не должна превышать 16 МиБ.')
  }
  const failure = error || preview.error?.message || save.error?.message
  return <div className="space-y-6 p-4 md:p-6">
    <h1 className="text-xl font-semibold">Радар</h1>
    <section className="space-y-4 rounded border border-border bg-panel p-4">
      <h2 className="font-semibold">Конфигурации nginx</h2>
      <p className="text-sm text-text-secondary">Загрузите полные выгрузки nginx -T. Имя файла без .conf — имя сервера. Можно вместе выбрать внешние и внутренние серверы. Доступность из интернета по одному конфигу не определяется.</p>
      <p className="text-sm text-text-secondary">До 32 файлов, 2 МиБ на файл и 16 МиБ на пачку. Включаемые файлы должны присутствовать в выгрузке. Оригиналы хранятся зашифрованными; произвольные значения директив скрыты при просмотре.</p>
      {write && <>
        <input ref={input} className="hidden" aria-label="Файлы конфигураций nginx" type="file" accept=".conf" multiple disabled={busy} onChange={e => select(e.target.files)} />
        <div className="flex flex-wrap items-center gap-3"><Button disabled={busy} onClick={() => input.current?.click()}>Выбрать конфигурации</Button><span className="text-sm text-text-secondary">{files.length ? `Выбрано файлов: ${files.length}` : 'Файлы не выбраны'}</span></div>
        <Button disabled={!files.length || !!error || busy} loading={preview.isPending} onClick={() => { save.reset(); preview.mutate(files) }}><Upload size={16} />Предварительный просмотр</Button>
      </>}
      {failure && <p role="alert" className="text-sm text-kind-1">{failure}</p>}
      {preview.data && <div className="space-y-3">
        {preview.data.items.map((item, i) => <div key={`${item.filename}-${i}`} className="rounded border border-border p-3 text-sm">
          <strong className="break-all">{item.filename}</strong>
          {item.error ? <p className="text-kind-1">{item.error}</p> : item.document && <>
            <p>Сервер: {item.document.hostname}. Виртуальных серверов: {item.document.servers.length}. Маршрутов: {item.document.servers.reduce((n, s) => n + s.routes.length, 0)}.</p>
            <p className="text-text-secondary">Новый снимок будет сохранён; неизменившийся файл повторно не сохраняется.</p>
            {!!item.document.warnings.length && <details className="mt-2"><summary className="cursor-pointer">Ограничения разбора: {item.document.warnings.length}</summary><ul className="mt-2 list-disc space-y-1 pl-5">{item.document.warnings.map(w => <li key={w}>{w}</li>)}</ul></details>}
          </>}
        </div>)}
        {write && <Button variant="primary" loading={save.isPending} disabled={busy || !!save.data || preview.data.items.some(i => i.error)} onClick={() => save.mutate(files)}>Сохранить снимки</Button>}
      </div>}
      {save.data && <div role="status" className="space-y-2 text-sm"><p>Сохранено: {save.data.items.filter(i => !i.unchanged).length}. Без изменений: {save.data.items.filter(i => i.unchanged).length}.</p><Button onClick={() => navigate('/radar')}>Открыть серверы nginx</Button></div>}
    </section>
    <section className="space-y-2 rounded border border-border p-4 text-sm"><h2 className="font-semibold">ScanFactory и NetTrace</h2><p className="text-text-secondary">Источники пока не подключены. Внешние наблюдения и сетевые пути не участвуют в оценке доступности.</p></section>
  </div>
}
