// IPv4-калькулятор: адрес с маской → сеть, широковещательный, диапазон узлов, вид адреса. Числа — беззнаковые 32 бита.

export interface Ipv4Info {
  address: number
  prefix: number
  mask: number
  wildcard: number
  network: number
  broadcast: number
  first: number
  last: number
  /** Адресов для узлов: /32 — 1, /31 — 2 (RFC 3021), иначе всего минус сеть и широковещательный. */
  usable: number
  total: number
  kind: string
  cls: string
}
export type IpCalcResult = { ok: true; info: Ipv4Info } | { ok: false; error: string }

const u32 = (n: number) => n >>> 0

export function ipToString(n: number): string {
  return [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.')
}

export function toBinary(n: number): string {
  return [24, 16, 8, 0].map((sh) => ((n >>> sh) & 255).toString(2).padStart(8, '0')).join('.')
}

/** Адрес из четырёх октетов или текст ошибки. */
function parseAddress(text: string, what: string): number | string {
  const parts = text.split('.')
  if (parts.length !== 4) return `${what} «${text}»: нужно четыре числа через точку`
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return `${what} «${text}»: октет «${p}» должен быть числом от 0 до 255`
    n = n * 256 + Number(p)
  }
  return n
}

const prefixMask = (prefix: number) => (prefix === 0 ? 0 : u32(0xffffffff << (32 - prefix)))

function parsePrefix(text: string): number | string {
  if (/^\d{1,2}$/.test(text)) {
    const p = Number(text)
    return p <= 32 ? p : `Префикс /${text}: должен быть от 0 до 32`
  }
  if (!text.includes('.')) return `Маска «${text}»: ожидается префикс (24) или маска точками (255.255.255.0)`
  const mask = parseAddress(text, 'Маска')
  if (typeof mask === 'string') return mask
  const prefix = 32 - Math.log2(u32(~mask) + 1)
  if (!Number.isInteger(prefix) || prefixMask(prefix) !== mask) return `Маска «${text}» с разрывами: единицы должны идти подряд слева`
  return prefix
}

// Особые диапазоны (RFC 6890 и соседние): от узкого к широкому, первый подходящий.
const SPECIAL: [string, number, string][] = [
  ['255.255.255.255', 32, 'Broadcast'],
  ['192.0.2.0', 24, 'Документация (RFC 5737)'],
  ['198.51.100.0', 24, 'Документация (RFC 5737)'],
  ['203.0.113.0', 24, 'Документация (RFC 5737)'],
  ['192.0.0.0', 24, 'Служебный IETF (RFC 6890)'],
  ['169.254.0.0', 16, 'Link-local'],
  ['192.168.0.0', 16, 'Частный (RFC 1918)'],
  ['198.18.0.0', 15, 'Тестирование сетевых устройств (RFC 2544)'],
  ['172.16.0.0', 12, 'Частный (RFC 1918)'],
  ['100.64.0.0', 10, 'Общий адрес провайдера, CGNAT (RFC 6598)'],
  ['0.0.0.0', 8, '«Эта сеть» (RFC 1122)'],
  ['10.0.0.0', 8, 'Частный (RFC 1918)'],
  ['127.0.0.0', 8, 'Loopback'],
  ['224.0.0.0', 4, 'Multicast'],
  ['240.0.0.0', 4, 'Зарезервирован'],
]

function kindOf(address: number): string {
  for (const [net, prefix, label] of SPECIAL) {
    if (u32(address & prefixMask(prefix)) === (parseAddress(net, '') as number)) return label
  }
  return 'Публичный'
}

function classOf(address: number): string {
  const first = address >>> 24
  return first < 128 ? 'A' : first < 192 ? 'B' : first < 224 ? 'C' : first < 240 ? 'D' : 'E'
}

/** Разбирает «адрес», «адрес/24», «адрес/255.255.255.0», «адрес 255.255.255.0», «адрес 24»; без маски — /32. */
export function calcIpv4(input: string): IpCalcResult {
  const parts = input.trim().split(/\s*\/\s*|\s+/).filter(Boolean)
  if (parts.length === 0) return { ok: false, error: 'Введите адрес IPv4, например 192.168.1.10/24' }
  if (parts.length > 2) return { ok: false, error: 'Лишнее в строке: ожидается адрес и, через «/» или пробел, маска или префикс' }
  const address = parseAddress(parts[0], 'Адрес')
  if (typeof address === 'string') return { ok: false, error: address }
  const prefix = parts.length === 2 ? parsePrefix(parts[1]) : 32
  if (typeof prefix === 'string') return { ok: false, error: prefix }

  const mask = prefixMask(prefix)
  const wildcard = u32(~mask)
  const network = u32(address & mask)
  const broadcast = u32(network | wildcard)
  const total = 2 ** (32 - prefix)
  const edge = prefix >= 31
  return {
    ok: true,
    info: {
      address,
      prefix,
      mask,
      wildcard,
      network,
      broadcast,
      first: prefix === 32 ? address : edge ? network : network + 1,
      last: prefix === 32 ? address : edge ? broadcast : broadcast - 1,
      usable: edge ? total : total - 2,
      total,
      kind: kindOf(address),
      cls: classOf(address),
    },
  }
}
