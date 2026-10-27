import { useState } from 'react'
import { Link, matchPath, useRouter } from '@/lib/router'
import { BY_SLUG } from '../index'
import { HelpArticle } from './HelpArticle'
import { HelpSearch } from './HelpSearch'
import { HelpToc } from './HelpToc'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Раздел справки: слева оглавление и поиск (ширина и рамка, как у сайдбаров модулей), справа статья. */
export function HelpPage() {
  const { path } = useRouter()
  const [query, setQuery] = useState('')
  // /help без статьи — «Что такое STools» на месте, без перенаправления.
  const slug = matchPath('/help/:slug', path)?.slug ?? 'stools'
  const article = BY_SLUG.get(slug)

  return (
    <div className="flex min-h-0 flex-1">
      <aside className="flex w-56 shrink-0 flex-col border-r border-grid bg-surface">
        <div className="px-4 pt-4 pb-2 text-sm font-semibold tracking-wide text-text">Справка</div>
        <HelpSearch query={query} onQuery={setQuery} />
        {/* Пока в поле есть запрос, оглавление скрыто под результатами: два списка в узкой колонке мешают друг другу. */}
        {!query.trim() && <HelpToc active={article?.slug ?? null} />}
      </aside>
      <div className="min-w-0 flex-1 overflow-y-auto">
        {article ? (
          // Ключ по статье: новая статья открывается сверху, а #якорь прокручивается заново.
          <HelpArticle key={article.slug} article={article} />
        ) : (
          <div className="p-6 text-sm text-text-secondary">
            <h1 className="text-lg font-semibold text-text">Статья не найдена</h1>
            <p className="mt-2">
              Статьи «{slug}» нет в справке.{' '}
              <Link to="/help" className={`text-text underline hover:no-underline ${FOCUS}`}>
                Вернуться к справке
              </Link>
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
