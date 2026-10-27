import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nestSections } from './toc.ts'
import type { ArticleMeta } from './types.ts'

const meta = (slug: string, title: string, section?: string): ArticleMeta => ({
  slug,
  title,
  group: 'settings',
  module: 'platform',
  routes: [`/settings/${slug}`],
  concepts: [],
  ...(section ? { section } : {}),
})

test('статьи с одним section — узел на месте первой, все статьи раздела — его дети', () => {
  const items = nestSections([
    meta('users', 'Пользователи', 'Доступ'),
    meta('groups', 'Группы', 'Доступ'),
    meta('audit', 'Журнал действий'),
    meta('login', 'Вход', 'Доступ'),
    meta('profile', 'Мой профиль'),
  ])
  assert.deepEqual(items, [
    {
      slug: 'users',
      title: 'Доступ',
      children: [
        { slug: 'users', title: 'Пользователи' },
        { slug: 'groups', title: 'Группы' },
        { slug: 'login', title: 'Вход' },
      ],
    },
    { slug: 'audit', title: 'Журнал действий' },
    { slug: 'profile', title: 'Мой профиль' },
  ])
})

test('без section — плоский список в том же порядке', () => {
  assert.deepEqual(nestSections([meta('a', 'А'), meta('b', 'Б')]), [
    { slug: 'a', title: 'А' },
    { slug: 'b', title: 'Б' },
  ])
})
