import { useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Field, FIELD } from '@/components/ui/Field'
import { CopyButton } from '../components/CopyButton'
import { compareLists, compareNetworks, COMPARE_LIMIT, type SetResults, type NetworkResults } from '../lib/compare'
import { downloadLocal } from '../lib/download'

const OPERATIONS={intersection:'Общее: A ∩ B',onlyA:'Только в A: A − B',onlyB:'Только в B: B − A',union:'Объединение: A ∪ B'}
type Operation=keyof typeof OPERATIONS|'coverage'
const coverageNames={covered:'Покрыта',partial:'Частично покрыта',uncovered:'Не покрыта'}
export function ComparePage() {
  const [a,setA]=useState(''),[b,setB]=useState(''),[mode,setMode]=useState<'lists'|'networks'>('lists')
  const [trim,setTrim]=useState(true),[ignoreCase,setIgnoreCase]=useState(false),[op,setOp]=useState<Operation>('intersection')
  const [result,setResult]=useState<SetResults|NetworkResults|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(false)
  const clear=()=>{setResult(null);setError('')}
  function compare(){clear();try{setResult(mode==='lists'?compareLists(a,b,{trim,ignoreCase}):compareNetworks(a,b))}catch(e){setError(e instanceof Error?e.message:'Не удалось сравнить списки.')}}
  async function file(f:File|undefined,side:'a'|'b'){
    if(!f)return
    clear();setLoading(true)
    try{if(f.size>COMPARE_LIMIT)throw new Error('Лимит файла — 1 МиБ.');const text=new TextDecoder('utf-8',{fatal:true}).decode(await f.arrayBuffer());(side==='a'?setA:setB)(text)}catch(e){setError(e instanceof Error?e.message:'Не удалось прочитать UTF-8 файл.')}finally{setLoading(false)}
  }
  const output=result ? op==='coverage' ? ('coverage' in result?result.coverage.map(r=>`${r.network}\t${coverageNames[r.status]}`):[]) : result[op] : []
  const text=output.join('\n'),shown=output.slice(0,500).join('\n')
  return <div className="h-full overflow-y-auto p-4 sm:p-6"><div className="mx-auto max-w-6xl space-y-4">
    <p className="text-sm text-text-secondary">Сравнение строк или адресного пространства IPv4/IPv6. Обработка в браузере, без отправки и сохранения данных. Один элемент на строку, до 5000 строк и 1 МиБ в каждом списке.</p>
    <fieldset disabled={loading} className="space-y-4">
      <div className="flex flex-wrap items-end gap-4">
        <div className="w-64"><Field label="Что сравниваем"><select className={FIELD} value={mode} onChange={e=>{setMode(e.target.value as typeof mode);setOp('intersection');clear()}}><option value="lists">Списки строк</option><option value="networks">IP-адреса и подсети</option></select></Field></div>
        {mode==='lists'&&<><label className="flex items-center gap-2 text-sm text-text"><input type="checkbox" checked={trim} onChange={e=>{setTrim(e.target.checked);clear()}}/>Убрать пробелы по краям</label><label className="flex items-center gap-2 text-sm text-text"><input type="checkbox" checked={ignoreCase} onChange={e=>{setIgnoreCase(e.target.checked);clear()}}/>Без учёта регистра</label></>}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">{([['a',a,setA],['b',b,setB]] as const).map(([key,value,set])=><div key={key} className="space-y-2">
        <Field label={`Список ${key.toUpperCase()}`}><textarea maxLength={1024*1024} className={`${FIELD} min-h-56 resize-y font-mono text-xs`} aria-label={`Список ${key.toUpperCase()}`} value={value} spellCheck={false} onChange={e=>{set(e.target.value);clear()}} placeholder={mode==='lists'?'host01\nhost02':'192.0.2.0/24\n2001:db8::/32'}/></Field>
        <Field label={`Загрузить список ${key.toUpperCase()} (UTF-8)`}><input type="file" className="max-w-full text-xs text-text-secondary" onChange={e=>{void file(e.target.files?.[0],key);e.target.value=''}}/></Field>
      </div>)}</div>
      <div className="flex flex-wrap gap-3"><Button variant="primary" onClick={compare}>Сравнить</Button><Button onClick={()=>{setA(b);setB(a);clear()}}>Поменять A и B</Button><Button onClick={()=>{setA('');setB('');clear()}}>Очистить</Button></div>
    </fieldset>
    {mode==='networks'&&<p className="text-xs text-text-secondary">CIDR или одиночный IP. Адрес с маской приводится к сети. Сравниваются все адреса диапазона, включая адрес сети и broadcast; IPv4 и IPv6 считаются отдельно. Результат объединяет смежные диапазоны в минимальный набор CIDR.</p>}
    {loading&&<p role="status" className="text-sm text-text-secondary">Читаем файл…</p>}
    {error&&<p role="alert" className="rounded border border-kind-1/40 p-3 text-sm text-text">{error}</p>}
    {result&&<section aria-label="Результат сравнения" className="space-y-3 rounded border border-border p-4">
      <p role="status" className="text-sm text-text-secondary">Дубликатов удалено: A — {result.duplicatesA}, B — {result.duplicatesB}. Пустые строки пропущены.</p>
      <div className="flex flex-wrap gap-2">{Object.entries(OPERATIONS).map(([key,label])=><Button key={key} aria-pressed={op===key} variant={op===key?'primary':'secondary'} onClick={()=>setOp(key as Operation)}>{label} · {result[key as keyof typeof OPERATIONS].length}</Button>)}{'coverage' in result&&<Button aria-pressed={op==='coverage'} variant={op==='coverage'?'primary':'secondary'} onClick={()=>setOp('coverage')}>Покрытие A списком B</Button>}</div>
      {op==='coverage'&&<p className="text-xs text-text-secondary">Каждая исходная сеть A проверяется против объединения всех сетей B.</p>}
      <Field label="Результат"><textarea maxLength={1024*1024} className={`${FIELD} min-h-48 resize-y font-mono text-xs`} aria-label="Результат" value={shown} readOnly placeholder="В выбранной операции результатов нет"/></Field>
      <p className="text-xs text-text-secondary">Элементов: {output.length}.{output.length>500?' Показаны первые 500; копирование и скачивание содержат весь результат.':''}</p>
      <div className="flex flex-wrap gap-3"><CopyButton text={text}/><Button disabled={!text} onClick={()=>downloadLocal('comparison.txt',text)}>Скачать результат</Button></div>
    </section>}
  </div></div>
}
