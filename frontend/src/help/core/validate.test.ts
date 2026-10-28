import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validate } from './validate.ts'
import type { Article } from './types.ts'

const MODS = ['ad', 'platform']
const BODY_MODULE ='## Что это\nТекст.\n\n## Как читать\nТекст.\n\n## Как настроить\nТекст.\n'

function art(over: Partial<Article> & { slug: string }): Article {
  const base: Article = {
    slug: over.slug,
    title: 'Заголовок',
    group: 'module',
    module: 'ad',
    routes: [],
    where: 'Модуль AD',
    levels: { read: 'Смотреть.' },
    concepts: [],
    body: BODY_MODULE,
    file: `${over.slug}.md`,
    sections: { 'Что это': 'Текст.', 'Как читать': 'Текст.', 'Как настроить': 'Текст.' },
  }
  return { ...base, ...over }
}

function glossary(slug: string): Article {
  return art({
    slug,
    group: 'glossary',
    module: undefined,
    where: undefined,
    levels: undefined,
    body: '## Что это\nТермин.\n',
    sections: { 'Что это': 'Термин.' },
  })
}

function clean(): Article[] {
  return [
    art({
      slug: 'stools',
      group: 'start',
      module: undefined,
      where: undefined,
      levels: undefined,
      body: '## Что это\nО системе.\n',
      sections: { 'Что это': 'О системе.' },
    }),
    art({ slug: 'ad', routes: ['/ad', '/ad/findings/*'], concepts: ['snapshot'] }),
    art({
      slug: 'ad-set',
      group: 'settings',
      routes: ['/settings/ad'],
      body: BODY_MODULE + '\nСм. [находки](help:ad) и [/ad](/ad).\n',
    }),
    glossary('snapshot'),
  ]
}

test('чистый набор → []', () => {
  assert.deepEqual(validate(clean(), ['/ad', '/ad/findings/5', '/settings/ad'], MODS), [])
})

test('чистый набор без инвентаря маршрутов: покрытие пропускается', () => {
  assert.deepEqual(validate(clean(), [], MODS), [])
})

test('дубль slug: сообщение на втором файле называет первый', () => {
  const list = clean()
  list.push(art({ slug: 'ad', routes: ['/other'], file: 'second/ad.md' }))
  assert.deepEqual(validate(list, [], MODS), ['second/ad.md: slug «ad» уже занят статьёй ad.md'])
})

test('дубль шаблона routes в разных статьях', () => {
  const list = clean()
  list.push(art({ slug: 'dup', routes: ['/ad'], file: 'dup.md' }))
  assert.deepEqual(validate(list, [], MODS), ['dup.md: шаблон «/ad» уже указан в статье ad.md'])
})

test('дубль шаблона: параметры с разными именами — один шаблон', () => {
  const list = clean()
  list[1] = { ...list[1], routes: ['/ad', '/ad/:id'] }
  list.push(art({ slug: 'dup', routes: ['/ad/:domainId'], file: 'dup.md' }))
  assert.deepEqual(validate(list, [], MODS), ['dup.md: шаблон «/ad/:domainId» уже указан в статье ad.md как «/ad/:id»'])
})

test('дубль шаблона: хвостовой слэш не делает шаблон другим', () => {
  const list = clean()
  list.push(art({ slug: 'dup', routes: ['/ad/'], file: 'dup.md' }))
  assert.deepEqual(validate(list, [], MODS), ['dup.md: шаблон «/ad/» уже указан в статье ad.md как «/ad»'])
})

test('нет ## Как настроить у module', () => {
  const list = clean()
  list[1] = art({ slug: 'ad', routes: ['/ad'], sections: { 'Что это': 'Т', 'Как читать': 'Т' } })
  assert.deepEqual(validate(list, [], MODS), ['ad.md: нет раздела «## Как настроить»'])
})

test('нет ## Что это у start, нет ## Как читать у settings', () => {
  const list = clean()
  list[0] = { ...list[0], sections: {} }
  list[2] = { ...list[2], sections: { 'Что это': 'Т', 'Как настроить': 'Т' } }
  assert.deepEqual(validate(list, [], MODS), [
    'stools.md: нет раздела «## Что это»',
    'ad-set.md: нет раздела «## Как читать»',
  ])
})

test('у start и glossary «Как читать» и «Как настроить» не требуются', () => {
  assert.deepEqual(validate([clean()[0], glossary('g')], [], MODS), [])
})

test('пустой раздел считается отсутствующим', () => {
  const list = clean()
  list[1] = { ...list[1], sections: { 'Что это': '', 'Как читать': 'Т', 'Как настроить': 'Т' } }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: нет раздела «## Что это»'])
})

test('help:ghost → ошибка с именем файла и slug', () => {
  const list = clean()
  list[1] = { ...list[1], body: BODY_MODULE + '\nСм. [это](help:ghost) и [якорь](help:snapshot#x).\n' }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: ссылка help:ghost ведёт на несуществующую статью'])
})

test('help: внутри кодового блока не проверяется', () => {
  const list = clean()
  list[1] = { ...list[1], body: BODY_MODULE + '\n```\n[x](help:ghost)\n```\n' }
  assert.deepEqual(validate(list, [], MODS), [])
})

test('concept без статьи словаря', () => {
  const list = clean()
  list[1] = { ...list[1], concepts: ['snapshot', 'severity'] }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: понятие «severity» из concepts не имеет статьи словаря'])
})

test('concept указывает на статью не из словаря', () => {
  const list = clean()
  list[1] = { ...list[1], concepts: ['ad-set'] }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: понятие «ad-set» из concepts не имеет статьи словаря'])
})

test('адрес из инвентаря не покрыт ни одним шаблоном', () => {
  const msgs = validate(clean(), ['/ad', '/ad/jobs', '/ad/findings', '/settings/ad'], MODS)
  assert.deepEqual(msgs, ['routes.json: адрес /ad/jobs не покрыт ни одной статьёй'])
})

test('корень модуля как запасной вариант не считается покрытием', () => {
  assert.deepEqual(validate(clean(), ['/ad/jobs'], MODS), ['routes.json: адрес /ad/jobs не покрыт ни одной статьёй'])
})

test('адрес с :id из инвентаря покрывается шаблоном с :id и *', () => {
  const list = clean()
  list[1] = { ...list[1], routes: ['/ad/domains/:id/findings', '/ad/x/*'] }
  assert.deepEqual(validate(list, ['/ad/domains/:id/findings', '/ad/x/:id/y'], MODS), [])
})

test('нет обязательных полей у module: routes, where, levels', () => {
  const list = clean()
  list[1] = { ...list[1], routes: [], where: undefined, levels: undefined }
  assert.deepEqual(validate(list, [], MODS), [
    'ad.md: не заполнено поле routes',
    'ad.md: не заполнено поле where',
    'ad.md: не заполнено поле levels',
  ])
})

test('levels без единого уровня и where из пробелов считаются незаполненными', () => {
  const list = clean()
  list[2] = { ...list[2], levels: {}, where: '  ' }
  assert.deepEqual(validate(list, [], MODS), [
    'ad-set.md: не заполнено поле where',
    'ad-set.md: не заполнено поле levels',
  ])
})

test('levels только с any (страница открыта всем) считается заполненным', () => {
  const list = clean()
  list[2] = { ...list[2], levels: { any: 'Доступно всем вошедшим.' } }
  assert.deepEqual(validate(list, [], MODS), [])
})

test('нет slug / title у любой статьи', () => {
  const list = clean()
  list[2] = { ...list[2], slug: '', title: '' }
  assert.deepEqual(validate(list, [], MODS), [
    'ad-set.md: не заполнено поле slug',
    'ad-set.md: не заполнено поле title',
  ])
})

test('битый шаблон routes (* не последним) не роняет проверку, а даёт сообщение', () => {
  const list = clean()
  list[1] = { ...list[1], routes: ['/ad', '/ad/*/x'] }
  const msgs = validate(list, ['/ad'], MODS)
  assert.equal(msgs.length, 1)
  assert.match(msgs[0], /^ad\.md: шаблон «\/ad\/\*\/x»/)
})

test('нет module у статьи модуля и у статьи настроек', () => {
  const list = clean()
  list[1] = { ...list[1], module: undefined }
  list[2] = { ...list[2], module: ' ' }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: не заполнено поле module', 'ad-set.md: не заполнено поле module'])
})

test('неизвестный module: опечатка или модуль не из доступных', () => {
  const list = clean()
  list[1] = { ...list[1], module: 'fw' }
  assert.deepEqual(validate(list, [], MODS), ['ad.md: неизвестный модуль «fw» в поле module (допустимы: ad, platform)'])
})
