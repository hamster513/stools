import { test } from 'node:test'
import assert from 'node:assert/strict'
import { queuedPost, QUEUE_ACCEPTED, type Send } from './client.ts'
import type { QueueRun } from './types.ts'

function run(status = 'queued', result: Record<string, unknown> | null = null): QueueRun {
  return { id: 42, actor: 'test', origin: 'manual', status, cancel_requested: false,
    created_at: '', started_at: null, finished_at: null,
    steps: [{ id: 1, module: 'platform', kind: 'storage_cleanup', target_id: 0,
      key: 'platform/storage_cleanup/0', title: 'Очистка', is_root: true, dependencies: [], status,
      message: 'Ошибка источника', job_id: null, checked_at: null, started_at: null, finished_at: null, result }] }
}
const error = (status: number, message: string) => Object.assign(new Error(message), { status })

test('module submission acknowledges acceptance before waiting and returns native job id', async t => {
  const target = new EventTarget()
  Object.defineProperty(globalThis, 'window', { value: target, configurable: true })
  t.after(() => { Reflect.deleteProperty(globalThis, 'window') })
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let acknowledged = false
  target.addEventListener(QUEUE_ACCEPTED, () => { acknowledged = true })
  const calls: string[] = []
  const pending = run()
  pending.steps[0] = { ...pending.steps[0], module: 'ad', kind: 'collect', target_id: 7, key: 'ad/collect/7' }
  const send: Send = async <T>(path: string, init?: RequestInit): Promise<T> => {
    calls.push(path)
    if (calls.length === 1) assert.deepEqual(JSON.parse(String(init?.body)).tasks[0], { module: 'ad', kind: 'collect', target_id: 7, options: {} })
    return (calls.length === 1 ? pending : { ...pending, steps: [{ ...pending.steps[0], status: 'running', job_id: 19 }] }) as T
  }
  const response = queuedPost('/api/ad/connections/7/collect', undefined, send, error)
  await Promise.resolve()
  assert.equal(acknowledged, true)
  t.mock.timers.tick(2000)
  assert.deepEqual(await response, { job_id: 19 })
  assert.deepEqual(calls, ['/api/settings/sync-runs', '/api/settings/sync-runs/42'])
})

test('cleanup keeps the detailed failed result for its existing outcome panel', async t => {
  Object.defineProperty(globalThis, 'window', { value: new EventTarget(), configurable: true })
  t.after(() => { Reflect.deleteProperty(globalThis, 'window') })
  const result = { status: 'failed', warnings: ['Очистка отменена'], items: [] }
  const send: Send = async <T>(): Promise<T> => run('failed', result) as T
  assert.deepEqual(await queuedPost('/api/settings/storage/retention/run', { preview_id: 'confirmed' }, send, error), result)
})

test('failed dependency rejects the module request and hunting bypasses submission', async t => {
  Object.defineProperty(globalThis, 'window', { value: new EventTarget(), configurable: true })
  t.after(() => { Reflect.deleteProperty(globalThis, 'window') })
  const send: Send = async <T>(): Promise<T> => run('blocked') as T
  await assert.rejects(queuedPost('/api/settings/storage/retention/run', { preview_id: 'confirmed' }, send, error), /Ошибка источника/)
  let called = ''
  const direct: Send = async <T>(path: string): Promise<T> => { called = path; return { ok: true } as T }
  assert.deepEqual(await queuedPost('/api/siem/hunting/run', {}, direct, error), { ok: true })
  assert.equal(called, '/api/siem/hunting/run')
})
