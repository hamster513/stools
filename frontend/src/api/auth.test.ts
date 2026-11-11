import assert from 'node:assert/strict'
import { afterEach, mock, test } from 'node:test'
import { QueryClient } from '@tanstack/react-query'
import { fetchMe } from './auth.ts'
import { ApiRequestError } from './client.ts'

const user = { login: 'session-test', theme: 'dark', access: {} }
afterEach(() => mock.restoreAll())

function respond(status: number, body: unknown) {
  mock.method(globalThis, 'fetch', async () => Response.json(body, { status }))
}

test('expired session replaces a previously cached user with null', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  client.setQueryData(['me'], user)
  respond(401, { detail: 'Session expired' })
  try {
    assert.equal(await client.fetchQuery({ queryKey: ['me'], queryFn: fetchMe }), null)
    assert.equal(client.getQueryData(['me']), null)
    assert.equal(client.getQueryState(['me'])?.status, 'success')
  } finally { client.clear() }
})

test('missing session is unauthenticated on the first request', async () => {
  respond(401, { detail: 'Not authenticated' })
  assert.equal(await fetchMe(), null)
})

test('valid session returns the user', async () => {
  respond(200, user)
  assert.deepEqual(await fetchMe(), user)
})

for (const status of [403, 500, 503]) {
  test(`HTTP ${status} remains a retryable error rather than a signed-out session`, async () => {
    respond(status, { detail: 'Unavailable' })
    await assert.rejects(fetchMe, error => error instanceof ApiRequestError && error.status === status)
  })
}

test('network failure remains an error', async () => {
  mock.method(globalThis, 'fetch', async () => { throw new TypeError('Failed to fetch') })
  await assert.rejects(fetchMe, TypeError)
})
