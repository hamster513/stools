import { Children, isValidElement, useMemo, type ReactNode } from 'react'
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Link } from '@/lib/router'

function textOf(node: ReactNode): string {
  return Children.toArray(node)
    .map((c) => (typeof c === 'string' || typeof c === 'number' ? String(c) : isValidElement<{ children?: ReactNode }>(c) ? textOf(c.props.children) : ''))
    .join('')
}

/** Якорь заголовка: строчные буквы, пробелы → «-», кириллица и цифры остаются. */
function headingId(text: string): string {
  return text.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\p{L}\p{N}-]/gu, '')
}

const LINK = 'text-text underline hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/** Ссылка из текста статьи: `help:` и адреса приложения — внутри SPA, http(s) — в новой вкладке, прочее — текстом. */
function anchor(onHelpNavigate?: () => void): Components['a'] {
  return function A({ href, children }) {
    if (href?.startsWith('help:')) return <Link to={`/help/${href.slice(5)}`} onNavigate={onHelpNavigate} className={LINK}>{children}</Link>
    // `//host` и `/\host` браузер понимает как чужой сайт: это не адрес приложения.
    if (href && /^\/(?![/\\])/.test(href)) return <Link to={href} className={LINK}>{children}</Link>
    if (href && /^https?:\/\//.test(href)) return <a href={href} target="_blank" rel="noopener noreferrer" className={LINK}>{children}</a>
    return <>{children}</>
  }
}

const components: Components = {
  // Картинок в справке нет: внешний адрес картинки грузился бы при открытии статьи.
  img: () => null,
  h2: ({ children }) => <h2 id={headingId(textOf(children))} className="mt-5 mb-2 text-base font-semibold text-text first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mt-4 mb-1.5 text-sm font-semibold text-text">{children}</h3>,
  p: ({ children }) => <p className="my-2 leading-relaxed">{children}</p>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5">{children}</ol>,
  strong: ({ children }) => <strong className="font-semibold text-text">{children}</strong>,
  blockquote: ({ children }) => <blockquote className="my-2 border-l-2 border-grid pl-3 text-text-secondary">{children}</blockquote>,
  hr: () => <hr className="my-4 border-grid" />,
  code: ({ children }) => <code className="rounded bg-row-hover px-1 py-0.5 font-mono text-[0.9em] text-text">{children}</code>,
  pre: ({ children }) => <pre className="my-2 overflow-x-auto rounded border border-grid bg-app-bg p-3 font-mono text-xs [&_code]:bg-transparent [&_code]:p-0">{children}</pre>,
  table: ({ children }) => <div className="my-2 overflow-x-auto"><table className="w-full border-collapse text-left">{children}</table></div>,
  th: ({ children }) => <th className="border border-grid bg-row-hover px-2 py-1 font-semibold text-text">{children}</th>,
  td: ({ children }) => <td className="border border-grid px-2 py-1 align-top">{children}</td>,
}

/**
 * Текст статьи справки: markdown с таблицами (GFM) и внутренними ссылками `help:<slug>`.
 * `onHelpNavigate` вызывается после перехода по ссылке `help:` (панель так закрывается).
 */
export function Markdown({ source, onHelpNavigate }: { source: string; onHelpNavigate?: () => void }) {
  const all = useMemo<Components>(() => ({ ...components, a: anchor(onHelpNavigate) }), [onHelpNavigate])
  // По умолчанию react-markdown вырезает неизвестные схемы, включая help:; допустимые адреса отбирает компонент `a`.
  return (
    <div className="text-sm text-text-secondary">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={all} urlTransform={(url) => url}>
        {source}
      </ReactMarkdown>
    </div>
  )
}
