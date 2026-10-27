import type { ArticleMeta } from './core/types.ts'

/** Уровни из `levels` статьи: от меньшего к большему, с подписями для читателя. */
const LEVEL_ROWS: { key: 'read' | 'write' | 'admin'; label: string }[] = [
  { key: 'read', label: 'Аудитор' },
  { key: 'write', label: 'Аналитик' },
  { key: 'admin', label: 'Администратор' },
]

/** Непустые уровни статьи; у статей без `levels` (начало, словарь) их нет. */
export function filledLevels(levels: ArticleMeta['levels']): { label: string; text: string }[] {
  return LEVEL_ROWS.flatMap(({ key, label }) => {
    const text = levels?.[key]?.trim()
    return text ? [{ label, text }] : []
  })
}
