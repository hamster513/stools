import { test } from 'node:test'
import assert from 'node:assert/strict'
import { formatUtc, fromDateInput, parseTimestamp, relative } from './unixtime.ts'

function ts(input: string) {
  const r = parseTimestamp(input)
  if (!r.ok) throw new Error(`${input}: ${r.error}`)
  return r
}

test('единица по числу цифр: секунды, миллисекунды, микро- и наносекунды', () => {
  assert.deepEqual(ts('1761734400'), { ok: true, ms: 1761734400000, unit: 's' })
  assert.deepEqual(ts('1761734400123'), { ok: true, ms: 1761734400123, unit: 'ms' })
  assert.deepEqual(ts('1761734400123456'), { ok: true, ms: 1761734400123, unit: 'us' })
  assert.deepEqual(ts('1761734400123456789'), { ok: true, ms: 1761734400123, unit: 'ns' })
  assert.equal(ts('0').ms, 0)
  assert.equal(ts('-86400').ms, -86400000)
  assert.equal(ts('1761734400.5').ms, 1761734400500)
  assert.equal(ts(' 1 761 734 400 ').ms, 1761734400000)
})

test('ошибки: не число, дробь не у секунд, слишком длинное', () => {
  for (const bad of ['', 'abc', '12:30', '1761734400123.5', '12345678901234567890']) {
    assert.equal(parseTimestamp(bad).ok, false, bad)
  }
})

test('UTC: дата, время и миллисекунды, если есть', () => {
  assert.equal(formatUtc(1761734400000), '2025-10-29 10:40:00 UTC')
  assert.equal(formatUtc(1761734400123), '2025-10-29 10:40:00.123 UTC')
  assert.equal(formatUtc(0), '1970-01-01 00:00:00 UTC')
})

test('дата из поля ввода — по UTC и по местному времени', () => {
  assert.equal(fromDateInput('1970-01-02T00:00', true), 86400000)
  assert.equal(fromDateInput('2025-10-29T10:40:00', true), 1761734400000)
  assert.equal(fromDateInput('2025-10-29T10:40', false), new Date(2025, 9, 29, 10, 40).getTime())
  assert.equal(fromDateInput('', true), null)
  assert.equal(fromDateInput('мусор', false), null)
})

test('относительное время по-русски', () => {
  const now = 1761734400000
  assert.equal(relative(now, now), 'сейчас')
  assert.equal(relative(now - 5 * 60_000, now), '5 минут назад')
  assert.equal(relative(now + 3 * 86_400_000, now), 'через 3 дня')
  assert.equal(relative(now - 2 * 365 * 86_400_000, now), '2 года назад')
  assert.equal(relative(now + 43 * 3_600_000, now), 'через 2 дня')
  assert.equal(relative(now + 86_400_000, now), 'через 1 день')
})
