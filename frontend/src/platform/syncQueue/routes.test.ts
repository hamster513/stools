import { test } from 'node:test'
import assert from 'node:assert/strict'
import { synchronizationPost } from './routes.ts'

test('module update buttons share queue identities and preserve reference parameters', () => {
  assert.deepEqual(synchronizationPost('/api/ad/connections/7/collect'), {
    task: { module: 'ad', kind: 'collect', target_id: 7, options: {} }, response: 'job',
  })
  assert.deepEqual(synchronizationPost('/api/vm/refs/nvd/download', { years: [2024], mode: 'full' })?.task.options,
    { years: [2024], mode: 'full' })
  assert.equal(synchronizationPost('/api/assets/racktables/5/run')?.task.kind, 'rt')
  assert.equal(synchronizationPost('/api/siem/logons/run')?.task.kind, 'logons')
  assert.deepEqual(synchronizationPost('/api/vm/trends/sync/full')?.task.options, { reset: true })
})

test('hunting, uploads, previews, configuration tests and arbitrary routes bypass queue', () => {
  for (const path of ['/api/siem/hunting/run', '/api/vm/import/file', '/api/ad/connections/7/test',
    '/api/settings/storage/retention/preview', '/api/settings/llm/test', '/api/settings/sync-runs']) {
    assert.equal(synchronizationPost(path), null, path)
  }
})

test('storage cleanup preserves its explicit preview confirmation', () => {
  assert.deepEqual(synchronizationPost('/api/settings/storage/retention/run', { preview_id: 'confirmed-id' }), {
    task: { module: 'platform', kind: 'storage_cleanup', target_id: 0, options: { preview_id: 'confirmed-id' } },
    response: 'result',
  })
})
