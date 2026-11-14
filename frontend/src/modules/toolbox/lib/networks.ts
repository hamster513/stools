/** Exact IPv4/IPv6 interval algebra. Addresses are never expanded into individual hosts. */
export interface Range { family: 4 | 6; start: bigint; end: bigint }
const cap = 20_000

function ipv4(raw: string): bigint {
  const parts = raw.split('.')
  if (parts.length !== 4 || parts.some(s => !/^\d{1,3}$/.test(s) || Number(s) > 255)) throw new Error('неверный IPv4')
  return parts.reduce((n,s) => (n << 8n) + BigInt(s), 0n)
}
function ipv6(raw: string): bigint {
  let s = raw
  if (s.includes('.')) {
    const pos=s.lastIndexOf(':'), v=ipv4(s.slice(pos+1))
    s=s.slice(0,pos+1)+(v>>16n).toString(16)+':'+(v&65535n).toString(16)
  }
  const halves=s.split('::')
  if (halves.length>2) throw new Error('неверный IPv6')
  const left=halves[0] ? halves[0].split(':') : [], right=halves.length===2 && halves[1] ? halves[1].split(':') : []
  const missing=8-left.length-right.length
  if ((halves.length===1 && missing!==0) || (halves.length===2 && missing<1)) throw new Error('неверный IPv6')
  const words=halves.length===2 ? [...left,...Array(missing).fill('0'),...right] : left
  if (words.some(w=>!/^([\da-f]{1,4})$/i.test(w))) throw new Error('неверный IPv6')
  return words.reduce((n,w)=>(n<<16n)+BigInt('0x'+w),0n)
}
export function parseNetwork(raw: string): Range {
  const parts=raw.split('/')
  if (parts.length>2) throw new Error('лишний символ /')
  const family=parts[0].includes(':') ? 6 : 4, bits=family===4?32:128
  const address=family===4 ? ipv4(parts[0]) : ipv6(parts[0])
  if (parts[1]!==undefined && !/^\d{1,3}$/.test(parts[1])) throw new Error('неверная длина префикса')
  const prefix=parts[1]===undefined ? bits : Number(parts[1])
  if (prefix>bits) throw new Error('слишком длинный префикс')
  const size=1n<<BigInt(bits-prefix),start=(address/size)*size
  return {family,start,end:start+size-1n}
}
function address(n: bigint,family: 4|6): string {
  if (family===4) return [24n,16n,8n,0n].map(shift=>Number((n>>shift)&255n)).join('.')
  const words=Array.from({length:8},(_,i)=>((n>>BigInt(16*(7-i)))&65535n).toString(16))
  let start=-1,len=1
  for(let i=0;i<8;) {
    if(words[i]!=='0'){i++;continue}
    let j=i;while(j<8&&words[j]==='0')j++
    if(j-i>len){start=i;len=j-i}i=j
  }
  return start<0 ? words.join(':') : words.slice(0,start).join(':')+'::'+words.slice(start+len).join(':')
}
const order=(a:Range,b:Range)=>a.family-b.family || (a.start<b.start?-1:a.start>b.start?1:0)
export function mergeRanges(values: Range[]): Range[] {
  const result:Range[]=[]
  for(const r of [...values].sort(order)) {
    const last=result.at(-1)
    if(last && last.family===r.family && r.start<=last.end+1n) {if(r.end>last.end)last.end=r.end}
    else result.push({...r})
  }
  return result
}
export function intersectRanges(a:Range[],b:Range[]):Range[] {
  let i=0,j=0;const out:Range[]=[]
  while(i<a.length && j<b.length) {
    const x=a[i],y=b[j]
    if(x.family<y.family || (x.family===y.family && x.end<y.start)){i++;continue}
    if(x.family>y.family || y.end<x.start){j++;continue}
    out.push({family:x.family,start:x.start>y.start?x.start:y.start,end:x.end<y.end?x.end:y.end})
    if(x.end<=y.end)i++;else j++
  }
  return out
}
export function subtractRanges(a:Range[],b:Range[]):Range[] {
  const out:Range[]=[];let j=0
  for(const x of a) {
    while(j<b.length && (b[j].family<x.family || (b[j].family===x.family && b[j].end<x.start)))j++
    let start=x.start
    for(let k=j;k<b.length&&b[k].family===x.family&&b[k].start<=x.end;k++) {
      if(b[k].start>start)out.push({family:x.family,start,end:b[k].start-1n})
      if(b[k].end>=start)start=b[k].end+1n
      if(start>x.end)break
    }
    if(start<=x.end)out.push({family:x.family,start,end:x.end})
  }
  return out
}
export function toCidrs(ranges:Range[]):string[] {
  const out:string[]=[]
  for(const r of ranges) {
    let n=r.start;const bits=r.family===4?32:128
    while(n<=r.end) {
      let power=0
      while(power<bits && n%(1n<<BigInt(power+1))===0n && n+(1n<<BigInt(power+1))-1n<=r.end)power++
      out.push(`${address(n,r.family)}/${bits-power}`)
      if(out.length>cap)throw new Error('Результат превышает 20 000 подсетей. Разделите входные списки.')
      n+=1n<<BigInt(power)
    }
  }
  return out
}
