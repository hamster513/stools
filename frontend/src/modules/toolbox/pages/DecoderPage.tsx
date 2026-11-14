import { useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/components/ui/Field'
import { CopyButton } from '../components/CopyButton'
import { decodeStep, decodeText, DECODER_LIMIT, OPERATIONS, type Operation } from '../lib/decoder'
import { hexDump } from '../lib/base64'
import { downloadLocal } from '../lib/download'
interface Step { operation:Operation;bytes:Uint8Array }
export function DecoderPage() {
  const [input,setInput]=useState(''),[fileBytes,setFileBytes]=useState<Uint8Array|null>(null),[fileName,setFileName]=useState('')
  const [steps,setSteps]=useState<Step[]>([]),[operation,setOperation]=useState<Operation>('base64'),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  const current=steps.at(-1)?.bytes??fileBytes??new TextEncoder().encode(input)
  const text=decodeText(current),display=text===null?hexDump(current,4096):text.slice(0,128*1024)
  const reset=()=>{setSteps([]);setError('')}
  async function apply(){
    setError('');setBusy(true)
    try{const bytes=await decodeStep(current,operation);setSteps(prev=>[...prev,{operation,bytes}])}catch(e){setError(e instanceof Error?e.message:'Не удалось декодировать данные.')}finally{setBusy(false)}
  }
  async function upload(f:File|undefined){
    if(!f)return
    reset();setFileBytes(null);setFileName('');setInput('');setBusy(true)
    try{if(f.size>DECODER_LIMIT)throw new Error('Лимит файла — 1 МиБ.');setFileBytes(new Uint8Array(await f.arrayBuffer()));setFileName(f.name)}catch(e){setError(e instanceof Error?e.message:'Не удалось прочитать файл.')}finally{setBusy(false)}
  }
  return <div className="h-full overflow-y-auto p-4 sm:p-6"><div className="mx-auto max-w-6xl space-y-4">
    <p className="text-sm text-text-secondary">Применяйте преобразования по шагам. Байты сохраняются между шагами; декодированные команды показываются как текст. Всё выполняется в браузере, без запуска команд и отправки данных. До 1 МиБ на шаг и 12 шагов.</p>
    <fieldset disabled={busy} className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2"><div className="space-y-2">
        <Field label="Исходная строка или команда"><textarea maxLength={1024*1024} className={`${FIELD} min-h-56 resize-y font-mono text-xs`} aria-label="Исходная строка или команда" spellCheck={false} value={input} placeholder="Base64, URL, Hex, JWT или PowerShell -EncodedCommand…" onChange={e=>{setInput(e.target.value);setFileBytes(null);setFileName('');reset()}}/></Field>
        <Field label="Или загрузить файл (в том числе бинарный)"><input className="max-w-full text-xs text-text-secondary" type="file" onChange={e=>{void upload(e.target.files?.[0]);e.target.value=''}}/></Field>
        {fileName&&<p className="break-all text-xs text-text-secondary">Файл: {fileName} · {fileBytes?.length} байт</p>}
      </div><div className="space-y-2">
        <Field label={text===null?'Текущий результат — байты (Hex)':'Текущий результат — текст UTF-8'}><textarea maxLength={1024*1024} className={`${FIELD} min-h-56 resize-y font-mono text-xs`} aria-label={text===null?'Текущий результат — байты (Hex)':'Текущий результат — текст UTF-8'} value={display} readOnly spellCheck={false}/></Field>
        <p className="text-xs text-text-secondary">{current.length} байт · {steps.length} шагов.{text===null?' Не удалось прочитать как UTF-8; попробуйте UTF-16 или распаковку.':''}{(text===null&&current.length>4096)||(text!==null&&text.length>128*1024)?' Предпросмотр сокращён; файл скачивается целиком.':''}</p>
      </div></div>
      <div className="flex flex-wrap items-end gap-3"><div className="w-full sm:w-80"><Field label="Следующая операция"><select className={FIELD} value={operation} onChange={e=>{setOperation(e.target.value as Operation);setError('')}}>{Object.entries(OPERATIONS).map(([id,label])=><option key={id} value={id}>{label}</option>)}</select></Field></div><Button variant="primary" loading={busy} disabled={!current.length||steps.length>=12} onClick={()=>void apply()}>Применить шаг</Button><Button disabled={!steps.length} onClick={()=>{setSteps(steps.slice(0,-1));setError('')}}>Отменить шаг</Button><Button onClick={()=>{setInput('');setFileBytes(null);setFileName('');reset()}}>Очистить</Button></div>
    </fieldset>
    {operation==='jwt'&&<p className="text-sm text-text-secondary">Разбираются только header и payload. Подпись, срок действия и доверие к токену не проверяются.</p>}
    {operation==='powershell'&&<p className="text-xs text-text-secondary">Вставьте Base64 или команду с -EncodedCommand / -enc. Содержимое читается как UTF-16 LE.</p>}
    {operation==='json'&&<p className="text-xs text-text-secondary">Ожидается JSON-строка в двойных кавычках, например «"line\nnext"».</p>}
    {operation==='url'&&<p className="text-xs text-text-secondary">Percent-decoding URI. Символ + остаётся плюсом (это не разбор HTML-формы).</p>}
    {error&&<p role="alert" className="rounded border border-kind-1/40 p-3 text-sm text-text">{error}</p>}
    {!!steps.length&&<section aria-label="Шаги декодирования" className="rounded border border-border p-4"><h2 className="text-sm font-semibold text-text">Цепочка преобразований</h2><ol className="mt-2 list-inside list-decimal space-y-1 text-xs text-text-secondary">{steps.map((s,i)=><li key={i}>{OPERATIONS[s.operation]} · {s.bytes.length} байт</li>)}</ol><p role="status" className="mt-2 text-xs text-text-secondary">Выполнено шагов: {steps.length}</p></section>}
    <div className="flex flex-wrap gap-3"><CopyButton text={text??''}/><Button disabled={!current.length||busy} onClick={()=>downloadLocal(text===null?'decoded.bin':'decoded.txt',current,text===null?'application/octet-stream':'text/plain;charset=utf-8')}>Скачать текущий результат</Button></div>
  </div></div>
}
