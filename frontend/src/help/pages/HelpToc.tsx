import { useMemo, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import { cn } from '@/lib/cn'
import { Link } from '@/lib/router'
import { toc, type TocItem } from '../index'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

const contains = (node: TocItem, slug: string) => node.slug === slug || (node.children?.some((c) => c.slug === slug) ?? false)

function Leaf({ item, active, indent }: { item: TocItem; active: boolean; indent?: boolean }) {
  return (
    <Link
      to={`/help/${item.slug}`}
      aria-current={active ? 'page' : undefined}
      className={cn(
        'block min-w-0 flex-1 rounded px-2 py-1.5 text-sm',
        FOCUS,
        indent && 'pl-6',
        active ? 'bg-row-selected text-text' : 'text-text-secondary hover:bg-row-hover hover:text-text',
      )}
    >
      {item.title}
    </Link>
  )
}

/** Оглавление справки. Узел модуля раскрыт, если в нём открытая статья, и по клику на стрелку. */
export function HelpToc({ active }: { active: string | null }) {
  const groups = useMemo(() => toc(), [])
  // Ручное раскрытие и сворачивание по узлам. При переходе в статью узла его ручной выбор сбрасывается:
  // узел с открытой статьёй всегда раскрывается, остальные остаются как их оставил читатель.
  const [manual, setManual] = useState<Record<string, boolean>>({})
  const [seen, setSeen] = useState(active)
  if (seen !== active) {
    setSeen(active)
    const node = active ? groups.flatMap((g) => g.items).find((n) => contains(n, active)) : undefined
    if (node && node.slug in manual) {
      const rest = { ...manual }
      delete rest[node.slug]
      setManual(rest)
    }
  }

  return (
    <nav aria-label="Оглавление справки" className="flex-1 overflow-y-auto px-2 pb-4">
      {groups.map((g) => (
        <section key={g.key} className={cn(g.title ? 'mt-4 border-t border-grid pt-3' : 'mt-1')}>
          {/* Заголовок группы: заглавными, ярче и с линией сверху, чтобы не сливался с пунктами. */}
          {g.title && <h2 className="px-2 pb-1.5 text-xs font-bold tracking-widest text-text uppercase">{g.title}</h2>}
          <ul className="flex flex-col gap-0.5">
            {g.items.map((item) => {
              if (!item.children) {
                return (
                  <li key={item.slug}>
                    <Leaf item={item} active={item.slug === active} />
                  </li>
                )
              }
              const open = manual[item.slug] ?? (active !== null && contains(item, active))
              return (
                <li key={item.slug}>
                  <div className="flex items-center">
                    <button
                      type="button"
                      aria-expanded={open}
                      aria-label={`${open ? 'Свернуть' : 'Развернуть'}: ${item.title}`}
                      onClick={() => setManual((m) => ({ ...m, [item.slug]: !open }))}
                      className={cn('shrink-0 rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text', FOCUS)}
                    >
                      <ChevronRight size={14} aria-hidden className={cn('transition-transform', open && 'rotate-90')} />
                    </button>
                    {/* Узел раздела («Доступ») ведёт на свою первую статью, а она есть и среди детей: подсвечен ребёнок. */}
                    <Leaf item={item} active={item.slug === active && !item.children.some((c) => c.slug === item.slug)} />
                  </div>
                  {open && (
                    <ul className="mt-0.5 flex flex-col gap-0.5">
                      {item.children.map((c) => (
                        <li key={c.slug}>
                          <Leaf item={c} active={c.slug === active} indent />
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </nav>
  )
}
