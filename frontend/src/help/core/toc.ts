// Узлы оглавления для группы статей: статьи с общим `section` собираются в один узел.

import type { ArticleMeta, TocItem } from './types.ts'

/**
 * @param sorted статьи группы, уже упорядоченные (по `order` и названию)
 * @returns пункты оглавления: статья без `section` — лист; статьи одного `section` — узел с этим
 *   названием на месте первой из них. Все статьи раздела — дети узла, сам узел ведёт на первую.
 */
export function nestSections(sorted: ArticleMeta[]): TocItem[] {
  const items: TocItem[] = []
  const nodes = new Map<string, TocItem & { children: TocItem[] }>()
  for (const a of sorted) {
    const leaf: TocItem = { slug: a.slug, title: a.title }
    if (!a.section) {
      items.push(leaf)
      continue
    }
    let node = nodes.get(a.section)
    if (!node) {
      node = { slug: a.slug, title: a.section, children: [] }
      nodes.set(a.section, node)
      items.push(node)
    }
    node.children.push(leaf)
  }
  return items
}
