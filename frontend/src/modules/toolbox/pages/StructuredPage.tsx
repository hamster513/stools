import { useRef, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { FIELD, Field } from '@/components/ui/Field'
import { CopyButton } from '../components/CopyButton'
import { cellText, compareDocuments, MAX_INPUT_BYTES, parseDocument, selectRows, TABLE_LIMIT } from '../lib/structured'
import type { DataComparison, DataDocument, DataFormat, DataRow } from '../lib/structured'

const PREVIEW_LIMIT = 65_536
const FIELD_LIMIT = 100
const COLUMN_LIMIT = 30
const AREA = `${FIELD} min-h-[180px] resize-y font-mono text-xs`
const KINDS = { added: 'Добавлено', removed: 'Удалено', changed: 'Изменено' }

function download(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url; link.download = name; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Parsing happens only on an explicit click. Documents stay in component memory. */
export function StructuredPage() {
  const [format, setFormat] = useState<DataFormat>('json')
  const [delimiter, setDelimiter] = useState(',')
  const [inputs, setInputs] = useState<[string, string]>(['', ''])
  const [document, setDocument] = useState<DataDocument | null>(null)
  const [comparison, setComparison] = useState<DataComparison | null>(null)
  const [error, setError] = useState('')
  const [fields, setFields] = useState<string[]>([])
  const [filter, setFilter] = useState('')
  const [table, setTable] = useState<{ rows: DataRow[]; total: number; fields: string[] } | null>(null)
  const [loading, setLoading] = useState<[boolean, boolean]>([false, false])
  const fileRevision = useRef([0, 0])

  function clearResults() { setDocument(null); setComparison(null); setError(''); setTable(null) }
  function editInput(index: number, value: string) {
    fileRevision.current[index]++
    setLoading(old => index === 0 ? [false, old[1]] : [old[0], false])
    setInputs(old => index === 0 ? [value, old[1]] : [old[0], value]); clearResults()
  }
  async function readFile(index: number, file?: File) {
    if (!file) return
    const revision = ++fileRevision.current[index]
    clearResults()
    setLoading(old => index === 0 ? [false, old[1]] : [old[0], false])
    if (file.size > MAX_INPUT_BYTES) { setError(`Документ ${index ? 'B' : 'A'}: файл превышает 1 МиБ.`); return }
    setLoading(old => index === 0 ? [true, old[1]] : [old[0], true])
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer())
      if (fileRevision.current[index] !== revision) return
      setInputs(old => index === 0 ? [text, old[1]] : [old[0], text]); clearResults()
    } catch {
      if (fileRevision.current[index] === revision) setError('Не удалось прочитать файл как UTF-8.')
    } finally {
      if (fileRevision.current[index] === revision) setLoading(old => index === 0 ? [false, old[1]] : [old[0], false])
    }
  }
  function applyTable(doc: DataDocument, selected: string[], query: string) {
    const needle = query.toLocaleLowerCase()
    const matches = doc.rows.filter(row => !needle || selected.some(field => Object.hasOwn(row, field) && cellText(row[field]).toLocaleLowerCase().includes(needle)))
    setTable({ rows: selectRows(matches.slice(0, TABLE_LIMIT), selected, ''), total: matches.length, fields: selected })
  }
  function analyze() {
    clearResults()
    try {
      const parsed = parseDocument(inputs[0], format, delimiter)
      const selected = parsed.fields.slice(0, COLUMN_LIMIT)
      setDocument(parsed); setFields(selected); setFilter(''); applyTable(parsed, selected, '')
    } catch (e) { setError(`Документ A: ${e instanceof Error ? e.message : 'ошибка анализа'}`) }
  }
  function compare() {
    clearResults()
    let side = 'A'
    try {
      const a = parseDocument(inputs[0], format, delimiter)
      side = 'B'
      const b = parseDocument(inputs[1], format, delimiter)
      setComparison(compareDocuments(a, b))
    } catch (e) { setError(`Документ ${side}: ${e instanceof Error ? e.message : 'ошибка сравнения'}`) }
  }

  return (
    <div className="h-full overflow-y-auto p-4 sm:p-6">
      <p className="mb-4 max-w-3xl text-xs text-text-secondary">JSON, JSONL, CSV и XML: форматирование, таблица и сравнение двух документов. Данные обрабатываются в браузере и не сохраняются. До 1 МиБ на документ; файлы — UTF-8.</p>
      <div className="mb-4 flex flex-wrap gap-4">
        <Field label="Формат">
          <select className={FIELD} value={format} onChange={e => { setFormat(e.target.value as DataFormat); clearResults() }}>
            {(['json', 'jsonl', 'csv', 'xml'] as const).map(value => <option key={value} value={value}>{value.toUpperCase()}</option>)}
          </select>
        </Field>
        {format === 'csv' && <Field label="Разделитель CSV" hint="Первая строка — уникальные непустые заголовки.">
          <select className={FIELD} value={delimiter} onChange={e => { setDelimiter(e.target.value); clearResults() }}>
            <option value=",">Запятая (,)</option><option value=";">Точка с запятой (;)</option><option value={'\t'}>Табуляция</option><option value="|">Вертикальная черта (|)</option>
          </select>
        </Field>}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {inputs.map((input, index) => <div key={index} className="min-w-0 space-y-2">
          <Field label={`Документ ${index ? 'B — для сравнения' : 'A'}`}>
            <textarea aria-label={`Документ ${index ? 'B — для сравнения' : 'A'}`} className={AREA} value={input} onChange={e => editInput(index, e.target.value)} spellCheck={false} maxLength={MAX_INPUT_BYTES} placeholder={index ? 'Второй документ того же формата' : 'Вставьте документ или выберите файл'} />
          </Field>
          <Field label={`Файл ${index ? 'B' : 'A'}`}>
            <input className={`${FIELD} text-xs`} type="file" onChange={e => { void readFile(index, e.target.files?.[0]); e.target.value = '' }} />
          </Field>
          <p className="text-xs text-text-secondary" role="status">{loading[index] ? 'Чтение файла…' : `${input.length} символов`}</p>
        </div>)}
      </div>
      <div className="my-4 flex flex-wrap gap-2">
        <Button variant="primary" onClick={analyze} disabled={loading.some(Boolean)}>Анализировать A</Button>
        <Button onClick={compare} disabled={loading.some(Boolean)}>Сравнить A и B</Button>
      </div>
      {error && <p role="alert" className="mb-4 rounded border border-kind-1/40 p-3 text-sm text-text">{error}</p>}
      {!document && !comparison && !error && <p className="text-sm text-text-secondary">Введите данные и нажмите «Анализировать A» или «Сравнить A и B».</p>}
      {document && <div className="space-y-4">
        <Field label="Форматированный документ A" hint={`Показано ${Math.min(document.text.length, PREVIEW_LIMIT)} из ${document.text.length} символов. Копирование и скачивание содержат весь документ A.`}>
          <textarea aria-label="Форматированный документ A" className={AREA} value={document.text.slice(0, PREVIEW_LIMIT)} readOnly spellCheck={false} />
        </Field>
        <div className="flex flex-wrap gap-2"><CopyButton text={document.text} /><Button onClick={() => download(document.text, `document.${format}`)}>Скачать весь документ A</Button></div>
        {format === 'xml' ? <p className="text-xs text-text-secondary">XML отображается как текст. DTD и объявления ENTITY запрещены; смешанное содержимое сохраняется.</p> : <>
          <fieldset className="rounded border border-border p-3">
            <legend className="px-1 text-sm text-text">Поля таблицы</legend>
            <p className="mb-2 text-xs text-text-secondary">Доступны первые {FIELD_LIMIT} полей, одновременно до {COLUMN_LIMIT} столбцов. Всего полей: {document.fields.length}. Эти ограничения не влияют на полный документ.</p>
            <div className="flex max-h-40 flex-wrap gap-x-4 gap-y-2 overflow-auto">
              {document.fields.slice(0, FIELD_LIMIT).map(field => <label key={field} className="flex min-w-0 max-w-full items-center gap-1 text-xs text-text">
                <input type="checkbox" checked={fields.includes(field)} disabled={!fields.includes(field) && fields.length >= COLUMN_LIMIT} onChange={e => { setFields(old => e.target.checked ? [...old, field] : old.filter(x => x !== field)); setTable(null) }} />
                <span className="truncate" title={field}>{field || '(пустое имя)'}</span>
              </label>)}
            </div>
          </fieldset>
          <Field label="Текстовый фильтр" hint="По выбранным полям, без учёта регистра. Применяется кнопкой; документ не разбирается повторно.">
            <input className={FIELD} value={filter} onChange={e => { setFilter(e.target.value); setTable(null) }} />
          </Field>
          <Button onClick={() => applyTable(document, fields, filter)} disabled={!fields.length}>Применить поля и фильтр</Button>
          {table ? <>
            <p className="text-xs text-text-secondary" role="status">Показано {table.rows.length} из {table.total} подходящих строк (в документе {document.rows.length}). Лимит: {TABLE_LIMIT} строк; ячейки сокращены до 200 символов.</p>
            {table.rows.length && table.fields.length ? <div className="max-h-[440px] overflow-auto rounded border border-border">
              <table className="min-w-full text-left text-xs text-text">
                <caption className="sr-only">Данные документа A</caption>
                <thead className="sticky top-0 bg-app-bg"><tr>{table.fields.map(field => <th scope="col" key={field} className="max-w-64 truncate border-b border-border px-3 py-2">{field || '(пустое имя)'}</th>)}</tr></thead>
                <tbody>{table.rows.map((row, index) => <tr key={index}>{table.fields.map(field => <td key={field} className="max-w-64 whitespace-pre-wrap break-words border-b border-border px-3 py-2 align-top">{cellText(row[field]).slice(0, 200)}</td>)}</tr>)}</tbody>
              </table>
            </div> : <p className="text-sm text-text-secondary">Нет строк для отображения.</p>}
          </> : <p className="text-xs text-text-secondary">Примените выбранные поля и фильтр, чтобы обновить таблицу.</p>}
        </>}
      </div>}
      {comparison && <div className="space-y-3">
        <p role="status" className="text-sm text-text">{comparison.total === 0 ? 'Документы совпадают.' : `Различий: ${comparison.total}. Показано ${comparison.changes.length} (максимум 200), значения сокращены до 500 символов, пути — до 1024.`}</p>
        <p className="text-xs text-text-secondary">{format === 'json' ? 'Сравнение значений JSON: порядок ключей объектов не важен; порядок элементов массива важен. Пути — JSON Pointer.' : 'Построчное сравнение форматированного текста: общий префикс и суффикс исключены, оставшиеся строки сопоставлены по позиции. Вставки внутри блока могут дать несколько изменений.'}</p>
        {comparison.changes.map((change, index) => <div key={index} className="rounded border border-border p-3 text-xs text-text">
          <p className="mb-2 break-all font-medium">{KINDS[change.kind]} · {change.path || '(корень)'}</p>
          {change.before !== undefined && <p className="whitespace-pre-wrap break-all"><span className="font-semibold">− A: </span>{change.before}</p>}
          {change.after !== undefined && <p className="whitespace-pre-wrap break-all"><span className="font-semibold">+ B: </span>{change.after}</p>}
        </div>)}
      </div>}
    </div>
  )
}
