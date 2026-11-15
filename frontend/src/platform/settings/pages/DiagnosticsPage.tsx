import { useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Package, Upload } from 'lucide-react'
import { useMe } from '@/api/auth'
import { errorText } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { FIELD, Field } from '@/components/ui/Field'
import { Link, useRouter } from '@/lib/router'
import { atLeast } from '@/platform/access/types'
import { Forbidden } from '../Forbidden'
import { diagnosticApi, type Candidate, type DiagnosticKind } from '../api/diagnostics'
import { DiagnosticDossier } from './DiagnosticDossier'
import { DiagnosticModuleImport } from './DiagnosticModuleImport'
import { DiagnosticSummary } from './DiagnosticSummary'

const IMPORTS_KEY = ['settings', 'diagnostic-imports']
const CARD = 'space-y-4 rounded border border-grid bg-surface p-4'

export function DiagnosticsPage() {
  const { data: me } = useMe()
  if (!me || !['ad', 'assets', 'ksc'].every(area => atLeast(me.access, area as 'ad' | 'assets' | 'ksc', 'read'))) return <Forbidden kind="settings" />
  return <DiagnosticWorkspace />
}

function DiagnosticWorkspace() {
  const { path, navigate } = useRouter()
  const { data: me } = useMe()
  const canImport = !!me && ['ad', 'assets', 'ksc'].every(area => atLeast(me.access, area as 'ad' | 'assets' | 'ksc', 'write'))
  const id = path.replace(/\/+$/, '').split('/')[3]
  const client = useQueryClient()
  const imports = useQuery({ queryKey: IMPORTS_KEY, queryFn: diagnosticApi.imports, gcTime: 0 })
  const [kind, setKind] = useState<DiagnosticKind>('host')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<Candidate | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const candidates = useMutation({ mutationFn: ({ query, kind }: { query: string; kind: DiagnosticKind }) => diagnosticApi.candidates(query, kind), gcTime: 0 })
  const prepare = useMutation({ mutationFn: diagnosticApi.prepare, gcTime: 0 })
  const download = useMutation({ mutationFn: diagnosticApi.download, gcTime: 0 })
  const upload = useMutation({ mutationFn: diagnosticApi.upload, gcTime: 0, onSuccess: async item => {
    setFile(null); if (fileInput.current) fileInput.current.value = ''
    await client.invalidateQueries()
    navigate(`/settings/diagnostics/${item.id}`)
  } })
  const remove = useMutation({ mutationFn: diagnosticApi.remove, onSuccess: async () => {
    setConfirmDelete(null)
    await client.invalidateQueries({ queryKey: IMPORTS_KEY })
  } })
  function resetSelection() { setSelected(null); candidates.reset(); prepare.reset(); download.reset() }
  function search(e: FormEvent) { e.preventDefault(); resetSelection(); candidates.mutate({ query: query.trim(), kind }) }
  function select(candidate: Candidate) { setSelected(candidate); prepare.reset(); download.reset() }
  function chooseFile(next: File | null) {
    upload.reset(); setFileError(null); setFile(null)
    if (!next) return
    if (!next.name.toLowerCase().endsWith('.zip')) { setFileError('Выберите ZIP с диагностическим пакетом.'); return }
    if (next.size > 20 * 1024 * 1024) { setFileError('Размер ZIP не должен превышать 20 МБ.'); return }
    setFile(next)
  }
  const active = imports.data?.items.find(item => item.id === id)
  const busy = candidates.isPending || prepare.isPending || download.isPending
  return <div className="h-full overflow-y-auto p-4 sm:p-6"><div className="mx-auto max-w-6xl space-y-6">
    <header><h1 className="flex items-center gap-2 text-xl font-semibold"><Package size={22} aria-hidden />Диагностические пакеты</h1>
      <p className="mt-2 text-sm text-text-secondary">Обезличенный срез продовых данных для воспроизведения проблем в обычных модулях AD, Assets и AV/KSC на стенде.</p></header>
    <div className="rounded border border-grid bg-row-selected p-4 text-sm space-y-2">
      <p>Пакет содержит только выбранный объект и связанные сведения. Отсутствие записи в пакете не доказывает её отсутствие в инфраструктуре.</p>
      <p className="text-text-secondary">Перед скачиванием имена и идентификаторы заменяются согласованными псевдонимами; секреты и настройки подключений исключаются. Связи, структура и настройки политик сохраняются для диагностики: обезличивание не гарантирует невозможность повторной идентификации.</p>
    </div>
    {imports.isPending && <p role="status">Загружаем список пакетов…</p>}
    {imports.isError && <div role="alert" className="text-sm text-kind-1">{errorText(imports.error, 'Не удалось загрузить пакеты.')} <Button onClick={() => void imports.refetch()}>Повторить</Button></div>}
    {id ? <>
      <Link to="/settings/diagnostics" className="text-sm text-primary hover:underline">← Все диагностические пакеты</Link>
      {active ? active.mode === 'modules' ? <DiagnosticModuleImport dataset={active} /> : <><p className="text-sm text-text-secondary">Старый формат: доступно только отдельное досье. Для загрузки в обычные модули подготовьте новый пакет на исходной системе.</p><DiagnosticDossier key={active.id} dataset={active} /></> : imports.isSuccess && <p role="alert">Пакет не найден или уже удалён.</p>}
    </> : <>
      <section className={CARD} aria-labelledby="diagnostic-export-title">
        <h2 id="diagnostic-export-title" className="text-lg font-medium">Подготовить пакет</h2>
        <form className="flex flex-wrap items-end gap-3" onSubmit={search}>
          <div className="w-48"><Field label="Тип объекта"><select className={FIELD} value={kind} disabled={busy} onChange={e => { setKind(e.target.value as DiagnosticKind); resetSelection() }}><option value="host">Хост</option><option value="user">Пользователь</option></select></Field></div>
          <div className="min-w-48 flex-1"><Field label="Имя или идентификатор"><input className={FIELD} value={query} maxLength={255} required autoComplete="off" disabled={busy} onChange={e => { setQuery(e.target.value); resetSelection() }} placeholder="Начните с имени хоста или логина" /></Field></div>
          <Button type="submit" loading={candidates.isPending} disabled={!query.trim() || busy}>Найти объект</Button>
        </form>
        {candidates.isError && <p role="alert" className="text-sm text-kind-1">{errorText(candidates.error, 'Не удалось найти объект.')}</p>}
        {candidates.data && <fieldset disabled={prepare.isPending || download.isPending} className="space-y-2"><legend className="mb-2 text-sm font-medium">Выберите объект для экспорта</legend>
          {!candidates.data.items.length && <p role="status" className="text-sm text-text-secondary">Совпадений нет. Уточните имя или идентификатор.</p>}
          {candidates.data.items.map(item => <label key={`${item.kind}:${item.id}`} className="flex min-h-12 cursor-pointer items-center gap-3 rounded border border-grid p-3 hover:bg-row-hover"><input type="radio" name="diagnostic-candidate" checked={selected?.id === item.id && selected.kind === item.kind} onChange={() => select(item)} /><span className="min-w-0 break-words text-sm"><span className="block font-medium">{item.title}</span><span className="text-text-secondary">{item.subtitle}</span></span></label>)}
          {candidates.data.items.length > 0 && <p className="text-xs text-text-secondary">Если нужного объекта нет, уточните запрос.</p>}
        </fieldset>}
        {selected && <Button variant="primary" loading={prepare.isPending} disabled={download.isPending} onClick={() => { download.reset(); prepare.mutate(selected) }}>Подготовить обезличенный пакет</Button>}
        {prepare.isPending && <p role="status" className="text-sm text-text-secondary">Собираем связанные сведения и заменяем идентификаторы…</p>}
        {prepare.isError && <p role="alert" className="text-sm text-kind-1">{errorText(prepare.error, 'Не удалось подготовить пакет.')}</p>}
        {prepare.data && !prepare.isPending && <div className="space-y-3 border-t border-grid pt-4">
          <DiagnosticSummary summary={prepare.data.summary} />
          <p className="text-xs text-text-secondary">Скачать может подготовивший пакет администратор до {new Date(prepare.data.expires_at).toLocaleString('ru-RU')}. После этого подготовьте пакет заново.</p>
          <Button variant="primary" loading={download.isPending} onClick={() => download.mutate(prepare.data!.id)}><Download size={16} aria-hidden />Скачать ZIP</Button>
          {download.isError && <p role="alert" className="text-sm text-kind-1">{errorText(download.error, 'Не удалось скачать пакет.')}</p>}
          {download.isSuccess && <p role="status" className="text-sm text-text-secondary">Пакет передан браузеру для скачивания.</p>}
        </div>}
      </section>
      <section className={CARD} aria-labelledby="diagnostic-import-title">
        <h2 id="diagnostic-import-title" className="text-lg font-medium">Загрузить срез в модули стенда</h2>
        <p className="text-sm text-text-secondary">ZIP до 20 МБ. Новый пакет добавит обезличенные объекты и снимки в рабочие AD, Assets и AV/KSC. Существующие записи сохраняются. Сбор и подключения к исходной инфраструктуре не запускаются.</p>
        <form className="flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault(); if (file && canImport) upload.mutate(file) }}>
          <div className="min-w-48 flex-1"><Field label="Диагностический пакет ZIP"><input ref={fileInput} type="file" accept=".zip,application/zip" className={FIELD} disabled={upload.isPending || !canImport} onChange={e => chooseFile(e.target.files?.[0] ?? null)} /></Field></div>
          <Button type="submit" loading={upload.isPending} disabled={!file || !canImport}><Upload size={16} aria-hidden />Загрузить в модули</Button>
        </form>
        {!canImport && <p className="text-sm text-text-secondary">Для загрузки нужны права записи в AD, Assets и AV.</p>}
        {upload.isPending && <p role="status" className="text-sm text-text-secondary">Проверяем пакет, добавляем объекты и подготавливаем снимки в модулях…</p>}
        {(fileError || upload.isError) && <p role="alert" className="text-sm text-kind-1">{fileError || errorText(upload.error, 'Не удалось импортировать пакет.')}</p>}
      </section>
      <section className="space-y-3" aria-labelledby="diagnostic-list-title">
        <h2 id="diagnostic-list-title" className="text-lg font-medium">Загруженные пакеты</h2>
        {imports.isSuccess && !imports.data.items.length && <p className="text-sm text-text-secondary">Загруженных пакетов пока нет.</p>}
        {remove.isError && <p role="alert" className="text-sm text-kind-1">{errorText(remove.error, 'Не удалось удалить пакет.')}</p>}
        {imports.data?.items.map(item => <article key={item.id} className={CARD}>
          <div className="flex flex-wrap items-start justify-between gap-3"><div><Link to={`/settings/diagnostics/${item.id}`} className="break-all font-medium text-primary hover:underline">{item.root.title}</Link><p className="mt-1 text-xs text-text-secondary">{item.mode === 'modules' ? 'В обычных модулях' : 'Старый формат · отдельное досье'} · {item.root.kind === 'host' ? 'Хост' : 'Пользователь'} · Загружен {new Date(item.created_at).toLocaleString('ru-RU')}</p></div>
            {item.mode === 'modules' ? <span className="text-xs text-text-secondary">{item.status && item.status !== 'ready' ? 'Записи изменены или удалены' : 'Доступен в модулях'}</span> : confirmDelete === item.id ? <div className="flex flex-wrap items-center gap-2 text-sm"><span>Удалить этот пакет?</span><Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(item.id)}>Удалить</Button><Button disabled={remove.isPending} onClick={() => setConfirmDelete(null)}>Отмена</Button></div> : <Button disabled={remove.isPending} onClick={() => { remove.reset(); setConfirmDelete(item.id) }}>Удалить пакет</Button>}
          </div><DiagnosticSummary summary={item.summary} />
        </article>)}
      </section>
    </>}
  </div></div>
}
