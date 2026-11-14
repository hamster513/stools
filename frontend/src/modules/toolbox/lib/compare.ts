import { parseNetwork, mergeRanges, intersectRanges, subtractRanges, toCidrs, type Range } from './networks.ts'
export const COMPARE_LIMIT=1024*1024
export interface SetResults { union:string[];intersection:string[];onlyA:string[];onlyB:string[];duplicatesA:number;duplicatesB:number }
export interface NetworkResults extends SetResults { coverage:{network:string;status:'covered'|'partial'|'uncovered'}[] }
function lines(raw:string):string[] {
  if(new TextEncoder().encode(raw).length>COMPARE_LIMIT)throw new Error('Лимит каждого списка — 1 МиБ.')
  const result=raw.replace(/^\uFEFF/,'').split(/\r?\n/)
  if(result.length>5000)throw new Error('Лимит каждого списка — 5000 строк.')
  return result
}
export function compareLists(a:string,b:string,options:{trim:boolean;ignoreCase:boolean}):SetResults {
  function index(raw:string) {
    const values=new Map<string,string>();let duplicates=0
    for(const line of lines(raw)) {
      const value=options.trim?line.trim():line
      if(!value.trim())continue
      const key=options.ignoreCase?value.toLowerCase():value
      if(values.has(key))duplicates++;else values.set(key,value)
    }
    return {values,duplicates}
  }
  const x=index(a),y=index(b)
  return {union:[...x.values.values(),...[...y.values].filter(([k])=>!x.values.has(k)).map(([,v])=>v)],intersection:[...x.values].filter(([k])=>y.values.has(k)).map(([,v])=>v),onlyA:[...x.values].filter(([k])=>!y.values.has(k)).map(([,v])=>v),onlyB:[...y.values].filter(([k])=>!x.values.has(k)).map(([,v])=>v),duplicatesA:x.duplicates,duplicatesB:y.duplicates}
}
export function compareNetworks(a:string,b:string):NetworkResults {
  function parse(raw:string,side:string) {
    const values=new Map<string,Range>();let duplicates=0
    lines(raw).forEach((line,i)=>{
      if(!line.trim())return
      let r:Range
      try{r=parseNetwork(line.trim())}catch(e){throw new Error(`Список ${side}, строка ${i+1}: ${e instanceof Error?e.message:'неверная сеть'}.`)}
      const key=`${r.family}:${r.start}:${r.end}`
      if(values.has(key))duplicates++;else values.set(key,r)
    })
    return {values:[...values.values()],duplicates}
  }
  const x=parse(a,'A'),y=parse(b,'B'),left=mergeRanges(x.values),right=mergeRanges(y.values)
  return {union:toCidrs(mergeRanges([...left,...right])),intersection:toCidrs(intersectRanges(left,right)),onlyA:toCidrs(subtractRanges(left,right)),onlyB:toCidrs(subtractRanges(right,left)),duplicatesA:x.duplicates,duplicatesB:y.duplicates,
    coverage:x.values.map(r=>({network:toCidrs([r])[0],status:subtractRanges([r],right).length===0?'covered':intersectRanges([r],right).length?'partial':'uncovered'}))}
}
