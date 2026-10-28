// Кнопка «Открыть страницу →» у статьи справки: куда она ведёт и какой уровень нужен, чтобы её показать.
// Без React и алиасов: правило разделов настроек (settingsNeed) передаёт вызывающий.

import type { ArticleMeta } from './types.ts'

export type OpenLevel = 'read' | 'write' | 'admin'

/** Адрес для кнопки: первый шаблон без `:` и `*`, кроме страниц создания (`…/new`). */
export function openTarget(article: ArticleMeta): string | null {
  return article.routes.find((r) => !r.includes(':') && !r.includes('*') && !r.endsWith('/new')) ?? null
}

/** Наименьший заполненный уровень статьи: `any` и `read` → read, затем write, затем admin. */
function lowestLevel(levels: ArticleMeta['levels']): OpenLevel {
  if (levels?.any?.trim() || levels?.read?.trim()) return 'read'
  if (levels?.write?.trim()) return 'write'
  return 'admin'
}

/**
 * Куда ведёт кнопка и что нужно, чтобы её показать: область и уровень, `need: null` — открыта всем вошедшим;
 * null — кнопки нет (начало, словарь, нет адреса).
 * Решает адрес цели, а не группа статьи: `/settings/<раздел>` — по правилу раздела, как в SettingsShell;
 * страница модуля — наименьший уровень статьи в её модуле.
 */
export function openRule<L extends string>(
  article: ArticleMeta,
  settingsNeed: (section: string) => readonly [string, L] | null,
): { route: string; need: readonly [area: string, level: L | OpenLevel] | null } | null {
  if (article.group !== 'module' && article.group !== 'settings') return null
  const route = openTarget(article)
  if (route === null) return null
  if (route.startsWith('/settings/')) return { route, need: settingsNeed(route.split('/')[2] ?? '') }
  if (!article.module) return null
  return { route, need: [article.module, lowestLevel(article.levels)] }
}
