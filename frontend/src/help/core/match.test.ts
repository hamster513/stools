import { test } from 'node:test'
import assert from 'node:assert/strict'
import { articleForPath, matchRoute } from './match.ts'
import type { ArticleMeta } from './types.ts'

test('matchRoute: :id — ровно один сегмент, счёт = число литеральных сегментов', () => {
  assert.equal(matchRoute('/ad/domains/:id/findings', '/ad/domains/7/findings'), 3)
  assert.equal(matchRoute('/ad/domains/:id/findings', '/ad/domains/findings'), null)
  assert.equal(matchRoute('/ad/domains/:id', '/ad/domains/7/findings'), null)
  assert.equal(matchRoute('/ad/domains/:id', '/ad/domains/'), null)
})

test('matchRoute: * в конце — любой хвост, включая пустой', () => {
  assert.equal(matchRoute('/siem/hunting/*', '/siem/hunting'), 2)
  assert.equal(matchRoute('/siem/hunting/*', '/siem/hunting/library/5'), 2)
  assert.equal(matchRoute('/siem/hunting/*', '/siem/hunting/library'), 2)
  assert.equal(matchRoute('/siem/hunting/*', '/siem'), null)
  assert.equal(matchRoute('/siem/hunting/*', '/siem/other'), null)
})

test('matchRoute: точное совпадение, литералы различаются, префикс не совпадение', () => {
  assert.equal(matchRoute('/ad', '/ad'), 1)
  assert.equal(matchRoute('/ad', '/ad/jobs'), null)
  assert.equal(matchRoute('/ad/jobs', '/ad'), null)
  assert.equal(matchRoute('/ad/jobs', '/ad/logs'), null)
})

test('matchRoute: хвостовой слэш, query и hash в адресе не мешают', () => {
  assert.equal(matchRoute('/ad/jobs', '/ad/jobs/'), 2)
  assert.equal(matchRoute('/ad/jobs', '/ad/jobs?tab=1#x'), 2)
  assert.equal(matchRoute('/ad/*', '/ad?x=1'), 1)
})

test('matchRoute: * не последним сегментом и шаблон без / — ошибка', () => {
  assert.throws(() => matchRoute('/ad/*/x', '/ad/1/x'), /\*/)
  assert.throws(() => matchRoute('ad/x', '/ad/x'), /начинаться с/)
})

function meta(slug: string, routes: string[]): ArticleMeta {
  return { slug, title: slug, group: 'module', routes, concepts: [] }
}

const ARTICLES: ArticleMeta[] = [
  meta('stools', []),
  meta('ad', ['/ad']),
  meta('ad-domains', ['/ad/domains', '/ad/domains/:id/findings']),
  meta('ksc-servers', ['/ksc/servers/:id/*']),
  meta('ksc-policies', ['/ksc/servers/:id/policies/:policyId']),
  meta('ksc', ['/ksc']),
  meta('siem-hunting', ['/siem/hunting/*']),
]

test('articleForPath: побеждает больше литеральных сегментов', () => {
  const r = articleForPath(ARTICLES, '/ksc/servers/3/policies/12')
  assert.equal(r.article.slug, 'ksc-policies')
  assert.equal(r.fallback, 'none')
  assert.equal(articleForPath(ARTICLES, '/ksc/servers/3/groups').article.slug, 'ksc-servers')
  assert.equal(articleForPath(ARTICLES, '/ad/domains/7/findings').article.slug, 'ad-domains')
  assert.equal(articleForPath(ARTICLES, '/siem/hunting/library/5').article.slug, 'siem-hunting')
})

test('articleForPath: при равном счёте шаблон без * важнее шаблона с *', () => {
  const list = [meta('wild', ['/x/*']), meta('exact', ['/x/:id'])]
  assert.equal(articleForPath(list, '/x/5').article.slug, 'exact')
  assert.equal(articleForPath([...list].reverse(), '/x/5').article.slug, 'exact')
})

test('articleForPath: нет совпадения → статья корня модуля, fallback module', () => {
  const r = articleForPath(ARTICLES, '/ad/unknown')
  assert.equal(r.article.slug, 'ad')
  assert.equal(r.fallback, 'module')
  assert.equal(articleForPath(ARTICLES, '/ad/unknown/deep/er').fallback, 'module')
})

test('articleForPath: нет и корня модуля → stools, fallback root', () => {
  const r = articleForPath(ARTICLES, '/nowhere')
  assert.equal(r.article.slug, 'stools')
  assert.equal(r.fallback, 'root')
  assert.equal(articleForPath(ARTICLES, '/').article.slug, 'stools')
})

test('articleForPath: корень модуля берётся только из шаблона ровно /<модуль>', () => {
  const list = [meta('stools', []), meta('deep', ['/ad/domains']), meta('wild', ['/ad/x/*'])]
  assert.equal(articleForPath(list, '/ad/unknown').article.slug, 'stools')
})

test('articleForPath: нет stools и нет совпадения — исключение', () => {
  assert.throws(() => articleForPath([meta('ad', ['/ad'])], '/nowhere'), /stools/)
})
