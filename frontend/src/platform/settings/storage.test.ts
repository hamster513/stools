import { test } from 'node:test'
import assert from 'node:assert/strict'
import { bytes, growth, type HistoryPoint } from './storage.ts'
const point = (n: number, complete = true, coverage = 'pg+files'): HistoryPoint => ({ measured_at: '2026-11-12', total_bytes: n, complete, coverage, modules: [{ id: 'ad', total_bytes: n, complete }] })
test('bytes distinguish unknown, zero, growth and decrease', () => {
  assert.equal(bytes(null), 'Нет данных'); assert.equal(bytes(0), '0 Б'); assert.equal(bytes(1024), '1 КиБ'); assert.equal(bytes(-1024), '−1 КиБ')
})
test('growth requires two complete comparable measurements', () => {
  assert.equal(growth([point(100)], 'all'), null)
  assert.equal(growth([point(100), point(200, false)], 'all'), null)
  assert.equal(growth([point(100), point(200, true, 'new')], 'all'), null)
  assert.equal(growth([point(100), point(200)], 'all'), 100)
  assert.equal(growth([point(200), point(100)], 'ad'), -100)
  assert.equal(growth([point(200), point(100)], 'missing'), null)
})
