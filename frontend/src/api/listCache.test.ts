import assert from 'node:assert/strict'
import { test } from 'node:test'
import { MutationObserver, QueryObserver } from '@tanstack/react-query'
import { ApiRequestError } from './client.ts'
import { createAppQueryClient, LIST_QUERY_OPTIONS, viewOwner, readViewState, writeViewState } from './listCache.ts'

const a = { login: 'a', auth_source: 'local', access: { assets: 'admin' }, theme: 'dark' }
const b = { ...a, login: 'b' }
const tick = () => new Promise(resolve => setTimeout(resolve, 0))

test('fresh lists return without GET; invalidation still refetches, auth TTL stays short', async () => {
  const client = createAppQueryClient()
  let calls = 0
  const options = { ...LIST_QUERY_OPTIONS, queryKey: ['assets-list', {}], queryFn: async () => ++calls }
  try {
    client.setQueryData(['me'], a)
    assert.equal(await client.fetchQuery(options), 1)
    const observer = new QueryObserver(client, options)
    const unsubscribe = observer.subscribe(() => {})
    await tick()
    assert.equal(calls, 1)
    await client.invalidateQueries({ queryKey: ['assets-list'] })
    assert.equal(calls, 2)
    assert.equal(client.getDefaultOptions().queries?.staleTime, 15_000)
    unsubscribe()
  } finally { client.clear() }
})

test('logout or identity/access change removes private pages and view state; theme does not', () => {
  const client = createAppQueryClient()
  try {
    client.setQueryData(['me'], a)
    const owner = viewOwner(client)
    client.setQueryData(['assets-list'], ['a-only'])
    writeViewState(client, 'assets', owner, { search: 'private' })
    client.setQueryData(['me'], { ...a, theme: 'light' })
    assert.deepEqual(client.getQueryData(['assets-list']), ['a-only'])
    client.setQueryData(['me'], { ...a, access: { assets: 'deny' } })
    assert.equal(client.getQueryData(['assets-list']), undefined)
    assert.equal(readViewState(client, 'assets'), undefined)
    client.setQueryData(['assets-list'], ['denied-old'])
    client.setQueryData(['me'], null)
    assert.equal(client.getQueryData(['assets-list']), undefined)
    client.setQueryData(['me'], b)
    writeViewState(client, 'assets', owner, { search: 'late-a-unmount' })
    assert.equal(readViewState(client, 'assets'), undefined)
  } finally { client.clear() }
})

test('late query A cannot populate the cache after login B and receives cancellation', async () => {
  const client = createAppQueryClient()
  let finish!: (value: string[]) => void
  let aborted = false
  try {
    client.setQueryData(['me'], a)
    const pending = client.fetchQuery({ queryKey: ['assets-list'], queryFn: ({ signal }) => {
      signal.addEventListener('abort', () => { aborted = true })
      return new Promise<string[]>(resolve => { finish = resolve })
    } }).catch(() => undefined)
    client.setQueryData(['me'], b)
    client.setQueryData(['assets-list'], ['b-only'])
    finish(['a-only'])
    await pending
    assert.equal(aborted, true)
    assert.deepEqual(client.getQueryData(['assets-list']), ['b-only'])
  } finally { client.clear() }
})

test('401 from a list expires the session even while me was fresh', async () => {
  const client = createAppQueryClient()
  try {
    client.setQueryData(['me'], a)
    client.setQueryData(['assets-list'], ['private'])
    await assert.rejects(client.fetchQuery({ queryKey: ['vm-vulns'], retry: false, queryFn: async () => { throw new ApiRequestError(401, 'expired') } }))
    assert.equal(client.getQueryData(['me']), null)
    assert.equal(client.getQueryData(['assets-list']), undefined)
  } finally { client.clear() }
})

test('late mutation A cannot write private data or expire session B', async () => {
  const client = createAppQueryClient()
  let finish!: (value: string[]) => void
  try {
    client.setQueryData(['me'], a)
    const mutation = new MutationObserver(client, {
      mutationFn: () => new Promise<string[]>(resolve => { finish = resolve }),
      onSuccess: value => { client.setQueryData(['assets-list'], value) },
    })
    const pending = mutation.mutate().catch(() => undefined)
    await tick()
    client.setQueryData(['me'], b)
    client.setQueryData(['assets-list'], ['b-only'])
    finish(['a-only'])
    await pending
    assert.deepEqual(client.getQueryData(['assets-list']), ['b-only'])
    assert.deepEqual(client.getQueryData(['me']), b)
  } finally { client.clear() }
})

test('relogin as the same user still rejects a mutation from the previous session', async () => {
  const client = createAppQueryClient()
  let finish!: (value: string[]) => void
  try {
    client.setQueryData(['me'], a)
    const owner = viewOwner(client)
    const mutation = new MutationObserver(client, {
      mutationFn: () => new Promise<string[]>(resolve => { finish = resolve }),
      onSuccess: value => { client.setQueryData(['assets-list'], value) },
    })
    const pending = mutation.mutate().catch(() => undefined)
    await tick()
    client.setQueryData(['me'], null)
    client.setQueryData(['me'], a)
    client.setQueryData(['assets-list'], ['new-session'])
    writeViewState(client, 'assets', owner, 'old-session')
    finish(['old-session'])
    await pending
    assert.deepEqual(client.getQueryData(['assets-list']), ['new-session'])
    assert.equal(readViewState(client, 'assets'), undefined)
  } finally { client.clear() }
})

test('403 refreshes permissions; effective denial removes old private cache', async () => {
  const client = createAppQueryClient()
  try {
    client.setQueryData(['me'], a)
    const observer = new QueryObserver(client, {queryKey:['me'], queryFn:async()=>({...a, access:{assets:'deny'}})})
    const unsubscribe=observer.subscribe(()=>{})
    client.setQueryData(['assets-list'], ['private'])
    await assert.rejects(client.fetchQuery({queryKey:['vm-vulns'], retry:false, queryFn:async()=>{throw new ApiRequestError(403,'denied')}}))
    await tick()
    assert.equal(client.getQueryData(['assets-list']), undefined)
    assert.deepEqual(client.getQueryData(['me']), {...a,access:{assets:'deny'}})
    unsubscribe()
  } finally {client.clear()}
})

test('a delayed me response cannot restore a session after a private 401', async () => {
  const client=createAppQueryClient()
  let finish!: (value: typeof a) => void
  try {
    client.setQueryData(['me'],a)
    const pending=client.fetchQuery({queryKey:['me'], staleTime:0, queryFn:()=>new Promise<typeof a>(resolve=>{finish=resolve})}).catch(()=>undefined)
    await assert.rejects(client.fetchQuery({queryKey:['assets-list'],retry:false,queryFn:async()=>{throw new ApiRequestError(401,'expired')}}))
    finish(a)
    await pending
    assert.equal(client.getQueryData(['me']),null)
  } finally {client.clear()}
})
