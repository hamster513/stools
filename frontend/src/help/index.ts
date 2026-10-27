// Справка в бандле: статьи грузятся в момент загрузки модуля, дальше — чистые функции поиска,
// выбора статьи по адресу и оглавления. Правила проверки статей — в core/ и check:help.

import { MODULES } from '@/platform/modules'
import { HelpParseError, parseArticle } from './core/frontmatter.ts'
import { articleForPath } from './core/match.ts'
import type { Article } from './core/types.ts'

export interface TocItem {
  slug: string
  title: string
  children?: TocItem[]
}

export interface TocGroup {
  key: 'start' | 'modules' | 'settings' | 'glossary'
  title: string
  items: TocItem[]
}

const RAW = import.meta.glob<string>('./articles/**/*.md', { query: '?raw', import: 'default', eager: true })

function load(): Article[] {
  return Object.entries(RAW)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, raw]) => {
      const file = `src/help/${key.slice(2)}`
      try {
        return parseArticle(file, raw)
      } catch (e) {
        // HelpParseError уже называет файл; сборку от таких ошибок страхует vite-плагин helpCheck.
        if (import.meta.env.DEV && !(e instanceof HelpParseError)) throw new Error(`[help] ${file}: ${(e as Error).message}`)
        throw e
      }
    })
}

export const ARTICLES: Article[] = load()
export const BY_SLUG: Map<string, Article> = new Map(ARTICLES.map((a) => [a.slug, a]))

/** Статья страницы по адресу; без своей статьи — статья модуля или «Что такое STools» (в dev — с предупреждением). */
export function helpFor(path: string): { article: Article; fallback: 'none' | 'module' | 'root' } {
  const found = articleForPath(ARTICLES, path)
  if (import.meta.env.DEV && found.fallback !== 'none') console.warn('[help] нет статьи для', path)
  return found
}

const SNIPPET_RADIUS = 60
const MAX_RESULTS = 20

function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

function snippetAround(text: string, at: number, length: number): string {
  const from = Math.max(0, at - SNIPPET_RADIUS)
  const to = Math.min(text.length, at + length + SNIPPET_RADIUS)
  return `${from > 0 ? '…' : ''}${oneLine(text.slice(from, to))}${to < text.length ? '…' : ''}`
}

/** Регистронезависимое вхождение в заголовок и текст; совпадения в заголовке — первыми. */
export function search(q: string): { article: Article; snippet: string }[] {
  const needle = q.trim().toLowerCase()
  if (!needle) return []
  const inTitle: { article: Article; snippet: string }[] = []
  const inBody: { article: Article; snippet: string }[] = []
  for (const article of ARTICLES) {
    const bodyAt = article.body.toLowerCase().indexOf(needle)
    const titleHit = article.title.toLowerCase().includes(needle)
    if (bodyAt >= 0) {
      const hit = { article, snippet: snippetAround(article.body, bodyAt, needle.length) }
      if (titleHit) inTitle.push(hit)
      else inBody.push(hit)
    } else if (titleHit) {
      inTitle.push({ article, snippet: snippetAround(article.body, 0, 0) })
    }
  }
  return [...inTitle, ...inBody].slice(0, MAX_RESULTS)
}

function byOrderThenTitle(a: Article, b: Article): number {
  const oa = a.order ?? Number.MAX_SAFE_INTEGER
  const ob = b.order ?? Number.MAX_SAFE_INTEGER
  return oa - ob || a.title.localeCompare(b.title, 'ru')
}

const item = (a: Article): TocItem => ({ slug: a.slug, title: a.title })

/**
 * Оглавление: «Начало», «Модули» (доступные, в порядке рейки), «Настройки», «Словарь».
 * Узел модуля ведёт на статью его корня (`/<модуль>`); без неё — на первую статью модуля.
 * Внутри узла: статьи модуля по `order` и названию, затем настройки модуля, затем его понятия.
 */
export function toc(): TocGroup[] {
  const start = ARTICLES.filter((a) => a.group === 'start').sort(byOrderThenTitle)
  const platform = ARTICLES.filter((a) => a.group === 'settings' && (a.module ?? 'platform') === 'platform').sort(byOrderThenTitle)
  const glossary = ARTICLES.filter((a) => a.group === 'glossary').sort((a, b) => a.title.localeCompare(b.title, 'ru'))

  const modules: TocItem[] = []
  for (const m of MODULES) {
    if (m.status !== 'available') continue
    const pages = ARTICLES.filter((a) => a.group === 'module' && a.module === m.id).sort(byOrderThenTitle)
    const settings = ARTICLES.filter((a) => a.group === 'settings' && a.module === m.id).sort(byOrderThenTitle)
    const concepts = glossary.filter((a) => a.module === m.id)
    const all = [...pages, ...settings, ...concepts]
    if (all.length === 0) continue
    const head = pages.find((a) => a.routes.includes(`/${m.id}`)) ?? all[0]
    const children = all.filter((a) => a !== head).map(item)
    modules.push({ slug: head.slug, title: m.title, ...(children.length > 0 ? { children } : {}) })
  }

  return [
    { key: 'start', title: 'Начало', items: start.map(item) },
    { key: 'modules', title: 'Модули', items: modules },
    { key: 'settings', title: 'Настройки', items: platform.map(item) },
    { key: 'glossary', title: 'Словарь', items: glossary.map(item) },
  ]
}
