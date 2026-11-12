import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canRunRetention, retentionConfirmation, validRetentionPolicy, type RetentionPolicy, type RetentionPreview } from './retention.ts'

const policy: RetentionPolicy = { receipt_payload_days: 14, collector_changes_days: 30, successful_jobs_days: 30, failed_jobs_days: 90, source_runs_days: 90, clear_staging: true }
const preview: RetentionPreview = {
  preview_id: 'preview-1', created_at: '2026-11-12T10:00:00Z', expires_at: '2026-11-12T10:05:00Z', warnings: ['Коллектор недоступен'],
  items: [
    { id: 'receipts', title: 'Тела квитанций', eligible_rows: 12, protected_rows: 3, estimated_bytes: 100, status: 'ready', reason: null },
    { id: 'collector', title: 'Журнал коллектора', eligible_rows: null, protected_rows: null, estimated_bytes: null, status: 'unavailable', reason: 'Коллектор недоступен' },
  ],
}

test('cleanup requires a current preview with saved policy and known candidates', () => {
  const now = Date.parse('2026-11-12T10:04:00Z')
  assert.equal(canRunRetention(preview, false, false, now), true)
  assert.equal(canRunRetention(preview, true, false, now), false)
  assert.equal(canRunRetention(preview, false, true, now), false)
  assert.equal(canRunRetention(preview, false, false, Date.parse(preview.expires_at)), false)
  assert.equal(canRunRetention(null, false, false, now), false)
  assert.equal(canRunRetention({ ...preview, items: [preview.items[1]] }, false, false, now), false)
  assert.equal(canRunRetention({ ...preview, expires_at: 'invalid' }, false, false, now), false)
  assert.equal(canRunRetention({ ...preview, items: [{ ...preview.items[0], eligible_rows: 0, estimated_bytes: 1024 }] }, false, false, now), true)
  assert.equal(canRunRetention({ ...preview, items: [{ ...preview.items[0], status: 'protected' }] }, false, false, now), false)
})

test('confirmation names concrete categories and counts, with warnings and protection', () => {
  const message = retentionConfirmation(preview)
  assert.match(message, /Тела квитанций: 12/)
  assert.match(message, /Защищено: 3/)
  assert.match(message, /Коллектор недоступен/)
  assert.doesNotMatch(message, /Журнал коллектора: 0/)
})

test('retention days must be integers within the supported range', () => {
  assert.equal(validRetentionPolicy(policy), true)
  for (const value of [0, 3651, 1.5, NaN, Infinity]) assert.equal(validRetentionPolicy({ ...policy, receipt_payload_days: value }), false)
  for (const value of [1, 3650]) assert.equal(validRetentionPolicy({ ...policy, failed_jobs_days: value }), true)
})
