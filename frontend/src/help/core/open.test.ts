import { test } from 'node:test'
import assert from 'node:assert/strict'
import { openRule, openTarget, type OpenLevel } from './open.ts'
import type { ArticleMeta } from './types.ts'

// Заглушка правила разделов настроек: как PAGES в platform/settings/pages.ts для этих разделов.
const NEED: Record<string, readonly [string, OpenLevel]> = { ad: ['ad', 'write'], access: ['platform', 'read'] }
const settingsNeed = (section: string) => NEED[section] ?? null

function meta(over: Partial<ArticleMeta>): ArticleMeta {
  return { slug: 'x', title: 'X', group: 'module', routes: [], concepts: [], ...over }
}

test('openRule: настройки модуля (group module, /settings/ad) — по правилу раздела, ad write', () => {
  const a = meta({ module: 'ad', routes: ['/settings/ad', '/settings/ad/*'], levels: { write: 'Т', admin: 'Т' } })
  assert.deepEqual(openRule(a, settingsNeed), { route: '/settings/ad', need: ['ad', 'write'] })
})

test('openRule: страница модуля только с write (toolbox-reverse) — нужен write в модуле', () => {
  const a = meta({ slug: 'toolbox-reverse', module: 'toolbox', routes: ['/toolbox/reverse'], levels: { write: 'Т' } })
  assert.deepEqual(openRule(a, settingsNeed), { route: '/toolbox/reverse', need: ['toolbox', 'write'] })
})

test('openRule: страница модуля с read — достаточно read; только admin — нужен admin', () => {
  const read = meta({ module: 'ad', routes: ['/ad'], levels: { read: 'Т', write: 'Т' } })
  assert.deepEqual(openRule(read, settingsNeed)?.need, ['ad', 'read'])
  const admin = meta({ module: 'ad', routes: ['/ad'], levels: { admin: 'Т' } })
  assert.deepEqual(openRule(admin, settingsNeed)?.need, ['ad', 'admin'])
})

test('openTarget: страница создания …/new и шаблоны с : и * (toolbox-scrub) — без кнопки', () => {
  const a = meta({ slug: 'toolbox-scrub', module: 'toolbox', routes: ['/toolbox/scrub/new', '/toolbox/scrub/:id'], levels: { read: 'Т', write: 'Т' } })
  assert.equal(openTarget(a), null)
  assert.equal(openRule(a, settingsNeed), null)
})

test('openRule: профиль (levels.any, /settings/profile) — открыт всем', () => {
  const a = meta({ slug: 'profile', group: 'settings', module: 'platform', routes: ['/settings/profile'], levels: { any: 'Т' } })
  assert.deepEqual(openRule(a, settingsNeed), { route: '/settings/profile', need: null })
})

test('openRule: вкладка «Доступа» — по правилу раздела access, platform read', () => {
  const a = meta({ group: 'settings', module: 'platform', routes: ['/settings/access/users'], levels: { read: 'Т', admin: 'Т' } })
  assert.deepEqual(openRule(a, settingsNeed)?.need, ['platform', 'read'])
})

test('openRule: начало и словарь — кнопки нет, даже с адресом', () => {
  assert.equal(openRule(meta({ group: 'start', routes: ['/findings'] }), settingsNeed), null)
  assert.equal(openRule(meta({ group: 'glossary', routes: [] }), settingsNeed), null)
})
