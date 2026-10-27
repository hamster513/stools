import { useMemo } from 'react'
import { cn } from '@/lib/cn'
import { Link, useRouter } from '@/lib/router'
import { search } from '../index'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Текст с первым совпадением в `<mark>`; регистр не важен. */
function Marked({ text, needle }: { text: string; needle: string }) {
  const at = text.toLowerCase().indexOf(needle.toLowerCase())
  if (!needle || at < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, at)}
      <mark className="rounded-sm bg-row-selected px-0.5 text-text">{text.slice(at, at + needle.length)}</mark>
      {text.slice(at + needle.length)}
    </>
  )
}

/** Поле «Поиск по справке» и результаты под ним. Enter открывает первый результат, Esc очищает. */
export function HelpSearch({ query, onQuery }: { query: string; onQuery: (q: string) => void }) {
  const { navigate } = useRouter()
  const needle = query.trim()
  const results = useMemo(() => search(query), [query])

  return (
    <div className={cn('px-3 pb-2', needle && 'flex min-h-0 flex-1 flex-col')}>
      <input
        type="search"
        value={query}
        onChange={(e) => onQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && query) {
            e.preventDefault()
            onQuery('')
          } else if (e.key === 'Enter' && results.length > 0) {
            e.preventDefault()
            navigate(`/help/${results[0].article.slug}`)
            onQuery('')
          }
        }}
        placeholder="Поиск по справке"
        aria-label="Поиск по справке"
        className={cn('w-full rounded border border-border bg-app-bg px-2 py-1 text-xs text-text placeholder:text-text-secondary', FOCUS)}
      />
      {needle && (
        <div className="mt-2 min-h-0 flex-1 overflow-y-auto" role="region" aria-label="Результаты поиска" aria-live="polite">
          {results.length === 0 ? (
            <p className="px-1 py-2 text-xs text-text-secondary">Ничего не найдено</p>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {results.map(({ article, snippet }) => (
                <li key={article.slug}>
                  <Link to={`/help/${article.slug}`} onNavigate={() => onQuery('')} className={cn('block rounded px-2 py-1.5 hover:bg-row-hover', FOCUS)}>
                    <span className="block text-sm font-medium text-text">
                      <Marked text={article.title} needle={needle} />
                    </span>
                    {snippet && (
                      <span className="mt-0.5 block text-xs leading-snug text-text-secondary">
                        <Marked text={snippet} needle={needle} />
                      </span>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
