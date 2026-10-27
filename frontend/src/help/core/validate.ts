// Проверка набора статей справки (check:help и vite-плагин сборки).
// Возвращает сообщения вида «файл: текст»; пустой список — всё в порядке.

import { isFenceLine } from './frontmatter.ts'
import { canonicalPattern, checkPattern, matchRoute } from './match.ts'
import type { Article } from './types.ts'

function withoutCodeBlocks(body: string): string {
  let fenced = false
  const kept: string[] = []
  for (const line of body.split(/\r?\n/)) {
    if (isFenceLine(line)) fenced = !fenced
    else if (!fenced) kept.push(line)
  }
  return kept.join('\n')
}

/**
 * @param articles все статьи
 * @param routes инвентарь адресов приложения (routes.json); пустой — проверка покрытия пропускается
 */
export function validate(articles: Article[], routes: string[]): string[] {
  const msgs: string[] = []
  const slugOwner = new Map<string, string>()
  const routeOwner = new Map<string, { file: string; index: number; route: string }>()
  const glossary = new Set(articles.filter((a) => a.group === 'glossary').map((a) => a.slug))
  const allSlugs = new Set(articles.map((a) => a.slug))
  const validPatterns: string[] = []

  articles.forEach((a, index) => {
    const err = (text: string) => msgs.push(`${a.file}: ${text}`)
    const pageGroup = a.group === 'module' || a.group === 'settings'

    // обязательные поля
    if (!a.slug?.trim()) err('не заполнено поле slug')
    if (!a.title?.trim()) err('не заполнено поле title')
    if (!a.group) err('не заполнено поле group')
    if (pageGroup) {
      if (a.routes.length === 0) err('не заполнено поле routes')
      if (!a.where?.trim()) err('не заполнено поле where')
      if (!a.levels || !Object.values(a.levels).some((v) => v?.trim())) err('не заполнено поле levels')
    }

    // дубли
    if (a.slug) {
      const owner = slugOwner.get(a.slug)
      if (owner !== undefined) err(`slug «${a.slug}» уже занят статьёй ${owner}`)
      else slugOwner.set(a.slug, a.file)
    }
    for (const route of a.routes) {
      try {
        checkPattern(route)
      } catch (e) {
        err((e as Error).message)
        continue
      }
      validPatterns.push(route)
      // дубль считаем по каноническому виду: `/ad/:id` и `/ad/:domainId`, `/ad/jobs` и `/ad/jobs/` — один адрес
      const key = canonicalPattern(route)
      const owner = routeOwner.get(key)
      if (owner && owner.index !== index) {
        err(`шаблон «${route}» уже указан в статье ${owner.file}` + (owner.route === route ? '' : ` как «${owner.route}»`))
      } else if (!owner) routeOwner.set(key, { file: a.file, index, route })
    }

    // обязательные разделы
    const needed = pageGroup ? ['Что это', 'Как читать', 'Как настроить'] : ['Что это']
    for (const title of needed) {
      if (!(a.sections[title] ?? '').trim()) err(`нет раздела «## ${title}»`)
    }

    // ссылки help:<slug> в теле (кодовые блоки не в счёт)
    const ghosts = new Set<string>()
    for (const m of withoutCodeBlocks(a.body).matchAll(/\(help:([^)\s#]*)/g)) {
      if (!allSlugs.has(m[1])) ghosts.add(m[1])
    }
    for (const slug of ghosts) err(`ссылка help:${slug} ведёт на несуществующую статью`)

    // понятия
    for (const concept of a.concepts) {
      if (!glossary.has(concept)) err(`понятие «${concept}» из concepts не имеет статьи словаря`)
    }
  })

  // покрытие инвентаря адресов
  for (const route of routes) {
    if (!validPatterns.some((p) => matchRoute(p, route) !== null)) {
      msgs.push(`routes.json: адрес ${route} не покрыт ни одной статьёй`)
    }
  }
  return msgs
}
