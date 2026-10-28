import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { Link, useRouter } from '@/lib/router'
import { BY_SLUG, helpFor } from './index'
import { BLOCK_TITLE, LevelsBlock, WhereWho } from './ArticleBlocks'
import { Markdown } from './Markdown'
import { HELP_PANEL_ID } from './layout'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'

/**
 * Панель подсказки справа: короткая часть статьи текущей страницы. Без затемнения, страница под ней
 * кликабельна; содержимое следует за адресом. Выше модальных дроверов (z-40 и портала KSC z-50), поэтому
 * Esc ловится в capture-фазе окна и закрывает сначала её.
 */
export function HelpPanel({ open, onClose, buttonRef }: { open: boolean; onClose: () => void; buttonRef: RefObject<HTMLButtonElement | null> }) {
  const { path } = useRouter()
  const headingRef = useRef<HTMLHeadingElement>(null)
  const wasOpen = useRef(open)

  // Фокус только при смене состояния: панель, открытая с прошлой страницы, фокус не крадёт.
  useEffect(() => {
    if (open === wasOpen.current) return
    wasOpen.current = open
    if (open) headingRef.current?.focus()
    else buttonRef.current?.focus()
  }, [open, buttonRef])

  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key !== 'Escape') return
      // Панель закрывается первой, остальным (дровер, меню «Экспорт») нужен второй Esc. Слушатель на window
      // в capture-фазе стоит раньше любых слушателей document, сколько бы ни было открыто до панели.
      e.stopImmediatePropagation()
      onClose()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [open, onClose])

  // helpFor пишет предупреждение в dev: считаем один раз на адрес, а не на каждый рендер. Пока панель
  // закрыта, адрес не пересчитываем: при закрытии статья остаётся на месте, пока панель уезжает.
  const [shownPath, setShownPath] = useState<string | null>(open ? path : null)
  if (open && shownPath !== path) setShownPath(path)
  const article = useMemo(() => (shownPath === null ? null : helpFor(shownPath).article), [shownPath])
  const what = article?.sections['Что это']

  return (
    <aside
      id={HELP_PANEL_ID}
      role="complementary"
      aria-label="Справка"
      aria-hidden={!open}
      inert={!open}
      className={cn('fixed top-0 right-0 z-[60] flex h-full w-[400px] flex-col border-l border-grid bg-surface transition-transform duration-200', open ? 'translate-x-0' : 'translate-x-full')}
    >
      {article && (
        <>
          {/* Заголовок, строка «Где · Кому» и крестик закрытия. */}
          <div className="flex items-start justify-between gap-2 border-b border-grid px-4 py-3">
            <div className="min-w-0">
              <h2 ref={headingRef} tabIndex={-1} className="text-sm font-semibold text-text outline-none">{article.title}</h2>
              <WhereWho article={article} className="mt-1 text-xs" />
            </div>
            <button type="button" onClick={onClose} aria-label="Закрыть справку" className={cn('rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text', FOCUS)}>
              <X size={16} aria-hidden />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
            {what && (
              <section className="mb-4">
                <div className={BLOCK_TITLE}>Что это</div>
                <Markdown source={what} onHelpNavigate={onClose} />
              </section>
            )}
            <LevelsBlock article={article} />
            {article.concepts.length > 0 && (
              <section className="mb-2">
                <div className={BLOCK_TITLE}>Понятия</div>
                <ul className="flex flex-wrap gap-1.5">
                  {article.concepts.map((slug) => (
                    <li key={slug}>
                      <Link to={`/help/${slug}`} onNavigate={onClose} className={cn('inline-block rounded-full border border-grid px-2.5 py-0.5 text-text hover:bg-row-hover', FOCUS)}>
                        {BY_SLUG.get(slug)?.title ?? slug}
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>

          <div className="border-t border-grid px-4 py-3 text-sm">
            <Link to={`/help/${article.slug}`} onNavigate={onClose} className={cn('text-text underline hover:no-underline', FOCUS)}>Вся справка →</Link>
          </div>
        </>
      )}
    </aside>
  )
}
