import { test } from 'node:test'
import assert from 'node:assert/strict'
import { HelpParseError, parseArticle, splitSections } from './frontmatter.ts'

const SAMPLE = `---
slug: ad-findings                 # адрес /help/ad-findings
title: Находки Active Directory
group: module                     # start | news | module | settings | glossary
module: ad
routes: ["/ad/findings", "/ad/findings/*"]   # адреса статьи страницы

where: Модуль AD → «Находки»
levels:                           # «Кому» и блок «Что здесь можно»
  read: Смотреть и выгружать таблицу.
  write: Менять статус, назначать исполнителя, принимать риск.
  admin: "Настраивать проверки: «Настройки → Active Directory»."
concepts: [ad-hygiene, snapshot, "risk-accept", severity]
order: 20
---

## Что это
Список находок домена.

## Как читать
Колонки и фильтры.

## Как настроить
Настройки лежат в разделе настроек.

## Частые вопросы
Пока пусто.
`

test('разбирает образец из спеки: все поля', () => {
  const a = parseArticle('articles/module/ad-findings.md', SAMPLE)
  assert.equal(a.file, 'articles/module/ad-findings.md')
  assert.equal(a.slug, 'ad-findings')
  assert.equal(a.title, 'Находки Active Directory')
  assert.equal(a.group, 'module')
  assert.equal(a.module, 'ad')
  assert.deepEqual(a.routes, ['/ad/findings', '/ad/findings/*'])
  assert.equal(a.where, 'Модуль AD → «Находки»')
  assert.deepEqual(a.levels, {
    read: 'Смотреть и выгружать таблицу.',
    write: 'Менять статус, назначать исполнителя, принимать риск.',
    admin: 'Настраивать проверки: «Настройки → Active Directory».',
  })
  assert.deepEqual(a.concepts, ['ad-hygiene', 'snapshot', 'risk-accept', 'severity'])
  assert.equal(a.order, 20)
})

test('секции извлекаются по заголовкам ##, тело начинается после фронтматтера', () => {
  const a = parseArticle('a.md', SAMPLE)
  assert.equal(a.sections['Что это'], 'Список находок домена.')
  assert.equal(a.sections['Как читать'], 'Колонки и фильтры.')
  assert.equal(a.sections['Как настроить'], 'Настройки лежат в разделе настроек.')
  assert.equal(a.sections['Частые вопросы'], 'Пока пусто.')
  assert.ok(a.body.trimStart().startsWith('## Что это'))
  assert.ok(!a.body.includes('slug:'))
})

test('необязательные поля: routes и concepts по умолчанию пусты', () => {
  const a = parseArticle('g.md', '---\nslug: g\ntitle: Т\ngroup: glossary\n---\n## Что это\nX\n')
  assert.deepEqual(a.routes, [])
  assert.deepEqual(a.concepts, [])
  assert.equal(a.levels, undefined)
  assert.equal(a.where, undefined)
  assert.equal(a.module, undefined)
})

test('одинарные кавычки, пустой список, CRLF и BOM', () => {
  const raw =
    '\uFEFF---\r\nslug: g\r\ntitle: \'Не "тот" # заголовок\'\r\ngroup: glossary\r\nroutes: []\r\n---\r\n## Что это\r\nX\r\n'
  const a = parseArticle('g.md', raw)
  assert.equal(a.title, 'Не "тот" # заголовок')
  assert.deepEqual(a.routes, [])
  assert.equal(a.sections['Что это'], 'X')
})

test('# внутри значения без пробела перед ним — не комментарий', () => {
  const a = parseArticle('g.md', '---\nslug: g\ntitle: C#sharp\ngroup: start\n---\n')
  assert.equal(a.title, 'C#sharp')
})

function parseError(raw: string): HelpParseError {
  try {
    parseArticle('bad.md', raw)
  } catch (e) {
    assert.ok(e instanceof HelpParseError, `ожидали HelpParseError, получили ${String(e)}`)
    return e
  }
  assert.fail('ожидали ошибку разбора')
}

test('нет обязательного поля slug → HelpParseError с файлом и номером строки закрывающего ---', () => {
  const e = parseError('---\ntitle: Т\ngroup: start\n---\n## Что это\n')
  assert.equal(e.file, 'bad.md')
  assert.equal(e.line, 4)
  assert.match(e.message, /slug/)
  assert.match(e.toString(), /bad\.md:4/)
})

test('нет title и нет group — ошибка про каждое', () => {
  assert.match(parseError('---\nslug: a\ngroup: start\n---\n').message, /title/)
  assert.match(parseError('---\nslug: a\ntitle: Т\n---\n').message, /group/)
})

test('нет фронтматтера / нет закрывающего --- → строка 1', () => {
  assert.equal(parseError('## Что это\n').line, 1)
  assert.equal(parseError('---\nslug: a\ntitle: Т\ngroup: start\n').line, 1)
})

test('неизвестная группа — ошибка на строке поля', () => {
  const e = parseError('---\nslug: a\ntitle: Т\ngroup: wiki\n---\n')
  assert.equal(e.line, 4)
  assert.match(e.message, /group/)
})

test('неизвестный ключ — ошибка на его строке', () => {
  const e = parseError('---\nslug: a\nfoo: 1\ntitle: Т\ngroup: start\n---\n')
  assert.equal(e.line, 3)
  assert.match(e.message, /foo/)
})

test('повтор ключа — ошибка', () => {
  assert.equal(parseError('---\nslug: a\nslug: b\ntitle: Т\ngroup: start\n---\n').line, 3)
})

test('строка без двоеточия и строка с табом — ошибки с номером строки', () => {
  assert.equal(parseError('---\nslug: a\nпросто текст\ntitle: Т\ngroup: start\n---\n').line, 3)
  assert.equal(parseError('---\nslug: a\n\ttitle: Т\ngroup: start\n---\n').line, 3)
})

test('вложенность вне levels и неверный отступ — ошибки', () => {
  assert.equal(parseError('---\nslug: a\n  title: Т\ngroup: start\n---\n').line, 3)
  assert.equal(parseError('---\nslug: a\ntitle: Т\ngroup: start\nlevels:\n    read: x\n---\n').line, 6)
})

test('levels.any и section разбираются', () => {
  const a = parseArticle(
    'p.md',
    '---\nslug: p\ntitle: Т\ngroup: settings\nsection: Доступ\nlevels:\n  any: Доступно всем вошедшим.\n---\n## Что это\nТекст.\n',
  )
  assert.deepEqual(a.levels, { any: 'Доступно всем вошедшим.' })
  assert.equal(a.section, 'Доступ')
})

test('levels: неизвестный уровень, пустое значение, дубль', () => {
  const head = '---\nslug: a\ntitle: Т\ngroup: module\n'
  assert.equal(parseError(head + 'levels:\n  owner: x\n---\n').line, 6)
  assert.equal(parseError(head + 'levels:\n  read:\n---\n').line, 6)
  assert.equal(parseError(head + 'levels:\n  read: a\n  read: b\n---\n').line, 7)
})

test('список: незакрытая скобка, пустой элемент, незакрытая кавычка, мусор после кавычки', () => {
  const head = '---\nslug: a\ntitle: Т\ngroup: module\n'
  assert.equal(parseError(head + 'routes: [/a, /b\n---\n').line, 5)
  assert.equal(parseError(head + 'routes: [/a, , /b]\n---\n').line, 5)
  assert.equal(parseError(head + 'routes: ["/a, /b]\n---\n').line, 5)
  assert.equal(parseError(head + 'where: "abc" xyz\n---\n').line, 5)
})

test('тип значения: список вместо скаляра, скаляр вместо списка, order не число', () => {
  assert.equal(parseError('---\nslug: [a]\ntitle: Т\ngroup: start\n---\n').line, 2)
  assert.equal(parseError('---\nslug: a\ntitle: Т\ngroup: start\nroutes: /a\n---\n').line, 5)
  assert.equal(parseError('---\nslug: a\ntitle: Т\ngroup: start\norder: first\n---\n').line, 5)
})

test('пустое значение у обычного ключа — ошибка', () => {
  assert.equal(parseError('---\nslug: a\ntitle:\ngroup: start\n---\n').line, 3)
})

test('splitSections: делит по ##, не трогает ### и заголовки внутри кодовых блоков', () => {
  const s = splitSections(
    'вступление\n\n## Один\nтекст\n### Подзаголовок\nещё\n\n## Два\n```\n## не заголовок\n```\nконец\n',
  )
  assert.deepEqual(Object.keys(s), ['Один', 'Два'])
  assert.equal(s['Один'], 'текст\n### Подзаголовок\nещё')
  assert.equal(s['Два'], '```\n## не заголовок\n```\nконец')
})
