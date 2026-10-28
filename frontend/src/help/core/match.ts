// Сопоставление адреса страницы со статьёй справки.
// Шаблоны — по сегментам: `:id` — ровно один сегмент; `*` — только последним сегментом,
// любой хвост (включая пустой). Счёт совпадения — число литеральных сегментов.

import type { ArticleMeta } from './types.ts'

function segments(path: string): string[] {
  return path.split(/[?#]/, 1)[0].split('/').filter(Boolean)
}

/** Канонический вид шаблона: без query/hash и хвостового «/», каждый `:имя` → `:`. Для поиска дублей. */
export function canonicalPattern(pattern: string): string {
  return '/' + segments(pattern).map((s) => (s.startsWith(':') && s.length > 1 ? ':' : s)).join('/')
}

/** Бросает Error с русским текстом, если шаблон нарушает правила. */
export function checkPattern(pattern: string): void {
  if (!pattern.startsWith('/')) throw new Error(`шаблон «${pattern}»: должен начинаться с «/»`)
  const parts = segments(pattern)
  if (parts.slice(0, -1).includes('*')) throw new Error(`шаблон «${pattern}»: «*» допустим только последним сегментом`)
}

/** Число литеральных сегментов шаблона, если адрес ему соответствует, иначе null. */
export function matchRoute(pattern: string, path: string): number | null {
  checkPattern(pattern)
  const pat = segments(pattern)
  const parts = segments(path)
  const wild = pat[pat.length - 1] === '*'
  if (wild) pat.pop()
  if (wild ? parts.length < pat.length : parts.length !== pat.length) return null
  let score = 0
  for (let i = 0; i < pat.length; i++) {
    if (pat[i].startsWith(':') && pat[i].length > 1) continue
    if (pat[i] !== parts[i]) return null
    score++
  }
  return score
}

/**
 * Статья для адреса: самый специфичный шаблон (при равном счёте шаблон без `*` важнее);
 * иначе статья корня модуля (`routes` содержит ровно `/<первый сегмент>`), fallback 'module';
 * иначе статья `stools`, fallback 'root'. Нет и её — исключение.
 */
export function articleForPath<T extends ArticleMeta>(
  articles: T[],
  path: string,
): { article: T; fallback: 'none' | 'module' | 'root' } {
  let best: { article: T; score: number; wild: boolean } | null = null
  for (const article of articles) {
    for (const route of article.routes) {
      const score = matchRoute(route, path)
      if (score === null) continue
      const wild = route.endsWith('*')
      if (!best || score > best.score || (score === best.score && best.wild && !wild)) {
        best = { article, score, wild }
      }
    }
  }
  if (best) return { article: best.article, fallback: 'none' }

  const first = segments(path)[0]
  if (first) {
    const root = `/${first}`
    const moduleArticle = articles.find((a) => a.routes.includes(root))
    if (moduleArticle) return { article: moduleArticle, fallback: 'module' }
  }
  const stools = articles.find((a) => a.slug === 'stools')
  if (!stools) throw new Error(`нет статьи «stools»: для адреса ${path} не нашлось запасной статьи справки`)
  return { article: stools, fallback: 'root' }
}
