import { cn } from '@/lib/cn'
import type { Article } from './core/types.ts'
import { filledLevels } from './levels'

/** Заголовок мелкого блока статьи: общий для панели подсказки и страницы справки. */
export const BLOCK_TITLE = 'mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

/** Уровни есть у страниц модулей и настроек; у «Начала», «Что нового» и словаря их нет. */
function levelsOf(article: Article) {
  return article.group === 'module' || article.group === 'settings' ? filledLevels(article.levels, article.module) : []
}

/** Строка «Где: … · Кому: …»: «Кому» — наименьший уровень, с которого статья применима. */
export function WhereWho({ article, className }: { article: Article; className?: string }) {
  if (!article.where) return null
  const levels = levelsOf(article)
  return (
    <p className={cn('text-text-secondary', className)}>
      Где: {article.where}
      {levels.length > 0 && <> · Кому: {levels[0].who}</>}
    </p>
  )
}

/** Блок «Что здесь можно»: по абзацу на уровень доступа. */
export function LevelsBlock({ article }: { article: Article }) {
  const levels = levelsOf(article)
  if (levels.length === 0) return null
  return (
    <section className="mb-4">
      <div className={BLOCK_TITLE}>Что здесь можно</div>
      <dl className="flex flex-col gap-2">
        {levels.map((l) => (
          <div key={l.label}>
            <dt className="font-semibold text-text">{l.label}</dt>
            <dd className="leading-relaxed text-text-secondary">{l.text}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}
