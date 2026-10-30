import { test } from 'node:test'
import assert from 'node:assert/strict'
import { calcIpv4, ipToString, toBinary } from './ipcalc.ts'

function calc(input: string) {
  const r = calcIpv4(input)
  if (!r.ok) throw new Error(`${input}: ${r.error}`)
  return r.info
}
const fail = (input: string) => {
  const r = calcIpv4(input)
  assert.equal(r.ok, false, `${input} должна быть ошибкой`)
  return r.ok ? '' : r.error
}
const s = ipToString

test('/24: сеть, широковещательный, узлы, маски', () => {
  const i = calc('192.168.1.10/24')
  assert.equal(s(i.address), '192.168.1.10')
  assert.equal(i.prefix, 24)
  assert.equal(s(i.mask), '255.255.255.0')
  assert.equal(s(i.wildcard), '0.0.0.255')
  assert.equal(s(i.network), '192.168.1.0')
  assert.equal(s(i.broadcast), '192.168.1.255')
  assert.equal(s(i.first), '192.168.1.1')
  assert.equal(s(i.last), '192.168.1.254')
  assert.equal(i.usable, 254)
  assert.equal(i.total, 256)
  assert.equal(i.kind, 'Частный (RFC 1918)')
  assert.equal(i.cls, 'C')
})

test('маска точками, через пробел и через «/»; без маски — /32', () => {
  assert.equal(calc('10.1.2.3 255.255.0.0').prefix, 16)
  assert.equal(calc('10.1.2.3/255.255.255.128').prefix, 25)
  assert.equal(calc('10.1.2.3 20').prefix, 20)
  const one = calc(' 8.8.8.8 ')
  assert.equal(one.prefix, 32)
  assert.equal(one.usable, 1)
  assert.equal(s(one.first), '8.8.8.8')
  assert.equal(one.kind, 'Публичный')
})

test('крайние префиксы: /31 — два узла (RFC 3021), /0 — всё пространство', () => {
  const p2p = calc('10.0.0.1/31')
  assert.equal(p2p.usable, 2)
  assert.equal(s(p2p.first), '10.0.0.0')
  assert.equal(s(p2p.last), '10.0.0.1')
  const all = calc('1.2.3.4/0')
  assert.equal(s(all.mask), '0.0.0.0')
  assert.equal(s(all.network), '0.0.0.0')
  assert.equal(s(all.broadcast), '255.255.255.255')
  assert.equal(all.total, 4294967296)
  assert.equal(all.usable, 4294967294)
})

test('особые диапазоны', () => {
  assert.equal(calc('172.20.0.1').kind, 'Частный (RFC 1918)')
  assert.equal(calc('172.32.0.1').kind, 'Публичный')
  assert.equal(calc('100.64.1.1').kind, 'Общий адрес провайдера, CGNAT (RFC 6598)')
  assert.equal(calc('127.0.0.1').kind, 'Loopback')
  assert.equal(calc('169.254.10.1').kind, 'Link-local')
  assert.equal(calc('224.0.0.251').kind, 'Multicast')
  assert.equal(calc('192.0.2.5').kind, 'Документация (RFC 5737)')
  assert.equal(calc('255.255.255.255').kind, 'Broadcast')
  assert.equal(calc('240.0.0.1').kind, 'Зарезервирован')
})

test('двоичный вид — октеты по 8 бит', () => {
  assert.equal(toBinary(calc('192.168.1.10').address), '11000000.10101000.00000001.00001010')
})

test('ошибки ввода', () => {
  assert.match(fail(''), /адрес/i)
  assert.match(fail('300.1.1.1'), /октет/)
  assert.match(fail('1.2.3'), /четыре/)
  assert.match(fail('1.2.3.4/33'), /0 до 32/)
  assert.match(fail('1.2.3.4/255.0.255.0'), /разрыв/)
  assert.match(fail('1.2.3.4/abc'), /маск/)
  assert.match(fail('1.2.3.4 5.6.7.8 9'), /лишн/i)
})
