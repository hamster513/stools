import { PLATFORM_LEVEL_TITLES } from '@/platform/access/types'
import type { ArticleMeta } from './core/types.ts'

/** Уровни из `levels` статьи: от меньшего к большему, с подписями для читателя. */
const LEVEL_ROWS: { key: 'read' | 'write' | 'admin'; label: string }[] = [
  { key: 'read', label: 'Аудитор' },
  { key: 'write', label: 'Аналитик' },
  { key: 'admin', label: 'Администратор' },
]

const upperFirst = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

/** У платформы свои названия уровней («Чтение», «Администратор»), как в матрице роли. */
const PLATFORM_ROWS: { key: 'read' | 'admin'; label: string }[] = [
  { key: 'read', label: upperFirst(PLATFORM_LEVEL_TITLES.read) },
  { key: 'admin', label: upperFirst(PLATFORM_LEVEL_TITLES.admin) },
]

export interface LevelRow {
  label: string
  /** как уровень звучит в строке «Кому» */
  who: string
  text: string
}

/**
 * Непустые уровни статьи; у статей без `levels` (начало, словарь) их нет.
 * `levels.any` — страница открыта всем вошедшим: одна строка вместо уровней.
 */
export function filledLevels(levels: ArticleMeta['levels'], module?: string): LevelRow[] {
  const any = levels?.any?.trim()
  if (any) return [{ label: 'Все вошедшие', who: 'все вошедшие', text: any }]
  const rows = module === 'platform' ? PLATFORM_ROWS : LEVEL_ROWS
  return rows.flatMap(({ key, label }) => {
    const text = levels?.[key]?.trim()
    return text ? [{ label, who: label, text }] : []
  })
}
