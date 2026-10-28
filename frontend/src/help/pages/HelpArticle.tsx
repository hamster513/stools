import { ChevronRight } from 'lucide-react'
import { useMe } from '@/api/auth'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { atLeast, type Area } from '@/platform/access/types'
import { findModule } from '@/platform/modules'
import { settingsNeed } from '@/platform/settings/pages'
import { useScrollToAnchor } from '@/platform/settings/useScrollToAnchor'
import { LevelsBlock, WhereWho } from '../ArticleBlocks'
import { openRule } from '../core/open.ts'
import type { Article } from '../core/types.ts'
import { toc } from '../index'
import { Markdown } from '../Markdown'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

const GROUP_TITLE: Record<string, string> = Object.fromEntries(toc().map((g) => [g.key, g.title]))

/** Статья справки целиком: крошки, заголовок, «Где · Кому», уровни и текст. */
export function HelpArticle({ article }: { article: Article }) {
  const { data: me } = useMe()
  useScrollToAnchor(true)

  // Кнопка — по тем же правилам, что и сама страница (App, SettingsShell): см. core/open.ts.
  const open = openRule(article, settingsNeed)
  const target = open && me && (open.need === null || atLeast(me.access, open.need[0] as Area, open.need[1])) ? open.route : null
  const section = article.group === 'module' ? (findModule(article.module ?? '')?.title ?? article.module) : GROUP_TITLE[article.group]

  return (
    <article className="px-6 py-5">
      <nav aria-label="Хлебные крошки" className="flex flex-wrap items-center gap-1 text-xs text-text-secondary">
        <Link to="/help" className={cn('rounded underline hover:text-text hover:no-underline', FOCUS)}>
          Справка
        </Link>
        <ChevronRight size={12} aria-hidden />
        <span>{section}</span>
        <ChevronRight size={12} aria-hidden />
        <span aria-current="page" className="text-text">
          {article.title}
        </span>
      </nav>

      <div className="mt-2 flex items-start justify-between gap-4">
        <h1 className="text-xl font-semibold text-text">{article.title}</h1>
        {target && (
          <Link to={target} className={cn('shrink-0 rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-row-hover', FOCUS)}>
            Открыть страницу →
          </Link>
        )}
      </div>

      <WhereWho article={article} className="mt-1 text-xs" />
      <div className="mt-4 max-w-3xl text-sm">
        <LevelsBlock article={article} />
        <Markdown source={article.body} />
      </div>
    </article>
  )
}
