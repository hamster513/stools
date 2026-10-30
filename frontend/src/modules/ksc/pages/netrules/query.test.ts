import assert from 'node:assert/strict'
import test from 'node:test'

test('пустой profile= выбирает саму политику, а не все профили', async () => {
  const module = await import('../../api/netRulesQuery.ts').catch(error => {
    if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error
    return undefined
  })
  assert.ok(module, 'Запрос секции должен сохранять пустой профиль')
  const qs = new URLSearchParams(module.netRulesSearch({ profile: '', layer: 'packet', policy_id: [1], enabled: false }))
  assert.equal(qs.has('profile'), true)
  assert.equal(qs.get('profile'), '')
  assert.equal(qs.get('enabled'), 'false')
  assert.equal(new URLSearchParams(module.netRulesSearch({})).has('profile'), false)
})
