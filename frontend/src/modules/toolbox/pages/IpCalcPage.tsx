import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { CopyButton } from '../components/CopyButton'
import { calcIpv4, ipToString, toBinary, type Ipv4Info } from '../lib/ipcalc'

const num = (n: number) => n.toLocaleString('ru-RU')

/** Двоичный вид с границей префикса: биты сети — ярко, биты узла — приглушённо. */
function Bits({ value, prefix }: { value: number; prefix: number }) {
  const text = toBinary(value)
  // В строке есть точки между октетами: граница по счёту цифр, не по позиции символа.
  let cut = 0
  for (let digits = 0; cut < text.length && digits < prefix; cut++) if (text[cut] !== '.') digits++
  return (
    <span className="font-mono text-xs">
      <span className="text-text">{text.slice(0, cut)}</span>
      <span className="text-text-secondary">{text.slice(cut)}</span>
    </span>
  )
}

function rows(i: Ipv4Info): [string, string, string?][] {
  const hosts = i.prefix === 32 ? 'один адрес' : i.prefix === 31 ? 'канал точка-точка, RFC 3021' : 'без адреса сети и широковещательного'
  return [
    ['Адрес', ipToString(i.address)],
    ['Маска', `${ipToString(i.mask)} = /${i.prefix}`],
    ['Обратная маска', ipToString(i.wildcard), 'wildcard: так маску пишут в ACL Cisco и правилах OSPF'],
    ['Сеть', `${ipToString(i.network)}/${i.prefix}`],
    ['Широковещательный', ipToString(i.broadcast)],
    ['Первый узел', ipToString(i.first)],
    ['Последний узел', ipToString(i.last)],
    ['Узлов', num(i.usable), hosts],
    ['Всего адресов', num(i.total)],
    ['Вид адреса', i.kind],
    ['Класс', i.cls, 'классовая адресация устарела, приведено для справки'],
    ['Целым числом', String(i.address), 'так адрес хранят некоторые базы и SIEM'],
    ['Шестнадцатерично', `0x${i.address.toString(16).toUpperCase().padStart(8, '0')}`],
  ]
}

/** IPv4-калькулятор: адрес с маской или префиксом → сеть, диапазон узлов, маски, вид адреса. Считается в браузере. */
export function IpCalcPage() {
  const [input, setInput] = useState('192.168.1.10/24')
  const r = input.trim() ? calcIpv4(input) : null

  return (
    <div className="h-full overflow-y-auto p-6">
      <p className="mb-4 max-w-2xl text-xs text-text-secondary">
        Адрес IPv4 с префиксом или маской: <span className="font-mono">10.0.0.1/24</span>, <span className="font-mono">10.0.0.1 255.255.255.0</span>, <span className="font-mono">10.0.0.1/255.255.255.0</span>. Без маски адрес считается одиночным (/32). Всё считается в браузере.
      </p>

      <label className="block max-w-md">
        <span className="mb-1 block text-xs font-medium text-text">Адрес и маска</span>
        <input className={cn(FIELD, 'font-mono')} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} autoComplete="off" placeholder="192.168.1.10/24" />
      </label>

      {r && !r.ok && <div role="alert" className="mt-4 flex max-w-2xl items-start gap-2 rounded border border-kind-1/40 bg-kind-1/5 px-3 py-2.5 text-sm text-text"><AlertTriangle size={16} className="mt-0.5 shrink-0 text-kind-1" aria-hidden />{r.error}</div>}

      {r?.ok && (
        <>
          <table className="mt-5 w-full max-w-3xl text-sm">
            <tbody>
              {rows(r.info).map(([label, value, note]) => (
                <tr key={label} className="border-b border-grid">
                  <th scope="row" className="w-48 py-2 pr-4 text-left align-top text-xs font-medium text-text-secondary">{label}</th>
                  <td className="py-2 align-top">
                    <span className="font-mono text-text">{value}</span>
                    {note && <span className="ml-3 text-xs text-text-secondary">{note}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="mt-5 max-w-3xl">
            <div className="mb-2 text-xs font-medium text-text">Двоичный вид <span className="font-normal text-text-secondary">— первые {r.info.prefix} бит задают сеть</span></div>
            <div className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-1">
              <span className="text-xs text-text-secondary">Адрес</span><Bits value={r.info.address} prefix={r.info.prefix} />
              <span className="text-xs text-text-secondary">Маска</span><Bits value={r.info.mask} prefix={r.info.prefix} />
              <span className="text-xs text-text-secondary">Сеть</span><Bits value={r.info.network} prefix={r.info.prefix} />
            </div>
          </div>

          <div className="mt-5"><CopyButton text={`${ipToString(r.info.network)}/${r.info.prefix}`} label="Скопировать сеть" /></div>
        </>
      )}
    </div>
  )
}
