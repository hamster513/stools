import assert from 'node:assert/strict'
import test from 'node:test'
import { buildCheck, outcomeTitle } from './checkModel.ts'
const form = { source: 'host-1', destinationKind: 'address' as const, address: ' 192.0.2.20 ', host: '', protocol: 'tcp' as const, port: '443', icmpType: '' }

test('проверка связи отправляет исходный хост, адрес и порт назначения', () => {
  assert.deepEqual(buildCheck(form).input, { source_host_id: 'host-1', destination: { address: '192.0.2.20' }, protocol: 'tcp', port: 443, icmp_type: null })
  assert.deepEqual(buildCheck({ ...form, destinationKind: 'host', host: 'host-2' }).input?.destination, { host_id: 'host-2' })
})
test('проверка связи требует источник и выбранное назначение', () => {
  assert.ok(buildCheck({ ...form, source: '' }).error)
  assert.ok(buildCheck({ ...form, address: '  ' }).error)
  assert.ok(buildCheck({ ...form, destinationKind: 'host', host: '' }).error)
})
test('проверка связи не отправляет некорректные порты или посторонние параметры протокола', () => {
  for (const port of ['65536', '-1', '1.5', '1e3', 'https']) assert.ok(buildCheck({ ...form, port }).error)
  assert.equal(buildCheck({ ...form, port: '' }).input?.port, null)
  const icmp = buildCheck({ ...form, protocol: 'icmp', port: 'wrong', icmpType: '8' }).input
  assert.equal(icmp?.port, null); assert.equal(icmp?.icmp_type, 8)
  assert.ok(buildCheck({ ...form, protocol: 'icmpv6', icmpType: '256' }).error)
  assert.equal(buildCheck({ ...form, protocol: 'any', port: 'wrong', icmpType: 'wrong' }).input?.port, null)
})
test('расчёт только источника не выдаётся за проверку всей связи', () => {
  assert.match(outcomeTitle({ overall: 'allow', source: { verdict: 'allow' }, destination: null }), /Исходящий трафик/)
  assert.match(outcomeTitle({ overall: 'allow', source: { verdict: 'not_applied' }, destination: null }), /не применяются/)
  assert.match(outcomeTitle({ overall: 'allow', source: { verdict: 'not_applied' }, destination: { verdict: 'not_applied' } }), /не применяются/)
  assert.match(outcomeTitle({ overall: 'deny', source: { verdict: 'allow' }, destination: { verdict: 'deny' } }), /Запрещено/)
})
