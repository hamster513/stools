import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareLists, compareNetworks } from './compare.ts'

test('lists: normalized sets preserve first spelling and report duplicates', () => {
  const r = compareLists(' Foo \nfoo\n\nBar', 'FOO\nBaz', { trim: true, ignoreCase: true })
  assert.deepEqual(r.intersection, ['Foo'])
  assert.deepEqual(r.onlyA, ['Bar'])
  assert.deepEqual(r.onlyB, ['Baz'])
  assert.equal(r.duplicatesA, 1)
  assert.equal(r.union.length, 3)
})
test('lists: case and whitespace options are real', () => {
  assert.equal(compareLists(' x', 'x', { trim: false, ignoreCase: false }).intersection.length, 0)
  assert.equal(compareLists('X', 'x', { trim: true, ignoreCase: false }).intersection.length, 0)
})
test('networks: intersections and difference are minimal CIDRs', () => {
  const r = compareNetworks('10.0.0.9/24', '10.0.0.0/25\n10.0.0.128/26')
  assert.deepEqual(r.onlyA, ['10.0.0.192/26'])
  assert.deepEqual(r.intersection, ['10.0.0.0/25', '10.0.0.128/26'])
  assert.deepEqual(r.union, ['10.0.0.0/24'])
  assert.equal(r.coverage[0].status, 'partial')
})
test('IPv6 range math does not enumerate addresses; families stay separate', () => {
  const r = compareNetworks('::/0\n0.0.0.0/0', '::/1')
  assert.deepEqual(r.intersection, ['::/1'])
  assert.deepEqual(r.onlyA, ['0.0.0.0/0', '8000::/1'])
})
test('coverage supports union of smaller subnets and singleton hosts', () => {
  const r = compareNetworks('192.0.2.0/24\n198.51.100.1', '192.0.2.0/25\n192.0.2.128/25')
  assert.deepEqual(r.coverage.map(x => x.status), ['covered', 'uncovered'])
  assert.deepEqual(r.onlyA, ['198.51.100.1/32'])
})
test('IPv6 canonical form, compressed and mapped literals', () => {
  const r = compareNetworks('2001:0DB8:0:0::1\n::ffff:192.0.2.1', '2001:db8::1/128\n::ffff:c000:201')
  assert.equal(r.onlyA.length, 0)
  assert.equal(r.intersection.length, 2)
})
test('bad networks report input side and line', () => {
  for (const bad of ['10.0.0.1/33','1.2.3.999','2001:::1','fe80::1%en0','abc','1.2.3.4/-1']) {
    assert.throws(() => compareNetworks('10.0.0.0/24', '\n'+bad), /B.*2/)
  }
})
test('empty and duplicate inputs', () => {
  assert.deepEqual(compareNetworks('', '').union, [])
  const r = compareNetworks('10.0.0.1/24\n10.0.0.0/24', '')
  assert.equal(r.duplicatesA, 1)
  assert.deepEqual(r.onlyA, ['10.0.0.0/24'])
})
