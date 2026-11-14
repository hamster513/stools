import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

let server
let DossierSections
let diagnosticApi
before(async () => {
  server = await createServer({ server: { middlewareMode: true, watch: null }, appType: 'custom' })
  ;({ DossierSections } = await server.ssrLoadModule('/src/platform/search/DossierSections.tsx'))
  ;({ diagnosticApi } = await server.ssrLoadModule('/src/platform/settings/api/diagnostics.ts'))
})
after(async () => { await server?.close() })

test('diagnostic dossier preserves relation controls without rendering live source links', () => {
  const entity = { id: 'user:7', kind: 'user', title: '<img src=x onerror=alert(1)>', domain: 'domain.invalid', href: '/assets/users/7', facts: [] }
  const dossier = {
    entity,
    notes: [],
    sections: [{ id: 'groups', title: 'Группы', note: '', has_more: true, items: [{
      id: 'row-1', title: entity.title, reason: 'Связь из пакета', source: 'AD',
      href: '/ad/live-source', observed_at: null, date_label: '', facts: [], target: entity,
    }] }],
  }
  const html = renderToStaticMarkup(createElement(DossierSections, { dossier, onOpen() {}, showSourceLinks: false }))
  assert.doesNotMatch(html, /href=|\/ad\/live-source|\/assets\/users\/7|<img/)
  assert.match(html, /&lt;img/)
  assert.match(html, /Связь из пакета/)
  assert.match(html, /сведения за пределами пакета недоступны/)
  assert.match(html, /<button/)
})

test('diagnostic relation lookups use only the chosen imported dataset endpoint', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init })
    return new Response(JSON.stringify({ query: 'user-1', matches: [], dossier: null, groups: [], has_more: false, notes: [] }), { status: 200, headers: { 'content-type': 'application/json' } })
  }
  try {
    await diagnosticApi.search('a'.repeat(32), { query: 'user-1', kind: 'user', entity_id: 'user:7' })
    await diagnosticApi.search('b'.repeat(32), { query: 'user-1', kind: 'user', entity_id: 'user:7' })
    assert.deepEqual(calls.map(call => call.url), [
      `/api/settings/diagnostics/imports/${'a'.repeat(32)}/search`,
      `/api/settings/diagnostics/imports/${'b'.repeat(32)}/search`,
    ])
    for (const { init } of calls) {
      assert.equal(init.method, 'POST')
      assert.equal(init.credentials, 'include')
      assert.equal(JSON.parse(init.body).entity_id, 'user:7')
    }
  } finally { globalThis.fetch = originalFetch }
})
