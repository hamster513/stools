import { decodeBase64 } from './base64.ts'
export const DECODER_LIMIT=1024*1024
export type Operation='base64'|'base64encode'|'url'|'urlencode'|'hex'|'hexencode'|'utf8'|'utf16le'|'utf16be'|'json'|'jwt'|'powershell'|'gzip'|'deflate'
export const OPERATIONS:Record<Operation,string>={base64:'Base64 → байты',base64encode:'Байты → Base64',url:'URL decode',urlencode:'URL encode',hex:'Hex → байты',hexencode:'Байты → Hex',utf8:'Прочитать UTF-8',utf16le:'UTF-16 LE → UTF-8',utf16be:'UTF-16 BE → UTF-8',json:'JSON-строка → текст',jwt:'JWT: заголовок и payload',powershell:'PowerShell EncodedCommand',gzip:'Распаковать gzip',deflate:'Распаковать deflate (zlib)'}
const encode=(text:string)=>new TextEncoder().encode(text)
export function decodeText(bytes:Uint8Array):string|null {
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes)}catch{return null}
}
function asText(bytes:Uint8Array):string {
  const text=decodeText(bytes)
  if(text===null)throw new Error('Байты не являются UTF-8. Выберите подходящую кодировку или распаковку.')
  return text
}
function base64(s:string):Uint8Array {
  const decoded=decodeBase64(s)
  if(!decoded.ok)throw new Error(decoded.error)
  return decoded.bytes
}
function utf16(bytes:Uint8Array,encoding:string):Uint8Array {
  if(bytes.length%2)throw new Error('UTF-16: нечётное число байт.')
  return encode(new TextDecoder(encoding,{fatal:true}).decode(bytes))
}
async function decompress(bytes:Uint8Array,format:'gzip'|'deflate'):Promise<Uint8Array> {
  if(typeof DecompressionStream==='undefined')throw new Error('Этот браузер не поддерживает распаковку.')
  const reader=new Blob([bytes.slice().buffer]).stream().pipeThrough(new DecompressionStream(format)).getReader()
  const chunks:Uint8Array[]=[];let length=0
  try{
    while(true){
      const {value,done}=await reader.read();if(done)break
      length+=value.byteLength
      if(length>DECODER_LIMIT)throw new Error('Распакованные данные превышают лимит 1 МиБ.')
      chunks.push(value)
    }
  }catch(e){await reader.cancel().catch(()=>{});throw e}finally{reader.releaseLock()}
  const result=new Uint8Array(length);let offset=0
  for(const c of chunks){result.set(c,offset);offset+=c.length}
  return result
}
export async function decodeStep(input:Uint8Array,op:Operation):Promise<Uint8Array> {
  if(input.byteLength>DECODER_LIMIT)throw new Error('Лимит данных — 1 МиБ.')
  let output:Uint8Array
  switch(op) {
    case 'base64': output=base64(asText(input));break
    case 'base64encode': {
      let binary='';for(let i=0;i<input.length;i+=32768)binary+=String.fromCharCode(...input.subarray(i,i+32768))
      output=encode(btoa(binary));break
    }
    case 'url':output=encode(decodeURIComponent(asText(input)));break
    case 'urlencode':output=encode(encodeURIComponent(asText(input)));break
    case 'hex':{
      const s=asText(input).trim().replace(/^0x/i,'').replace(/\s/g,'')
      if(!/^(?:[a-f\d]{2})*$/i.test(s))throw new Error('Hex: нужны пары шестнадцатеричных цифр.')
      output=Uint8Array.from(s.match(/../g)??[],v=>parseInt(v,16));break
    }
    case 'hexencode':output=encode(Array.from(input,b=>b.toString(16).padStart(2,'0')).join(' '));break
    case 'utf8':output=encode(asText(input));break
    case 'utf16le':output=utf16(input,'utf-16le');break
    case 'utf16be':output=utf16(input,'utf-16be');break
    case 'json':{
      const text=JSON.parse(asText(input));if(typeof text!=='string')throw new Error('Нужна JSON-строка в двойных кавычках, а не объект.')
      output=encode(text);break
    }
    case 'jwt':{
      const parts=asText(input).trim().split('.')
      if(parts.length!==3 || !parts[0] || !parts[1] || parts.some(p=>!/^[\w-]*$/.test(p)))throw new Error('Нужен JWT из трёх Base64URL-частей.')
      output=encode(JSON.stringify({header:JSON.parse(asText(base64(parts[0]))),payload:JSON.parse(asText(base64(parts[1]))),signature:'Подпись не проверена. Данные не подтверждены.'},null,2));break
    }
    case 'powershell':{
      const text=asText(input).trim()
      const match=/(?:^|\s)-(?:encodedcommand|enc)\s+(?:"([\w+/=-]+)"|'([\w+/=-]+)'|([\w+/=-]+))(?=\s|$)/i.exec(text)
      const encoded=match?(match[1]??match[2]??match[3]):text
      output=utf16(base64(encoded),'utf-16le');break
    }
    case 'gzip':case 'deflate':output=await decompress(input,op);break
    default:throw new Error('Неизвестная операция.')
  }
  if(output.byteLength>DECODER_LIMIT)throw new Error('Результат превышает лимит 1 МиБ.')
  return output
}
