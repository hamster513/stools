import { useEffect, useMemo, useRef, type RefObject } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { Link, useRouter } from '@/lib/router'
import { BY_SLUG, helpFor } from './index'
import { filledLevels } from './levels'
import { Markdown } from './Markdown'
import { HELP_PANEL_ID } from './layout'

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring'
const BLOCK_TITLE = 'mb-1 text-[11px] font-semibold tracking-wide text-text-secondary uppercase'

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

  // helpFor пишет предупреждение в dev: считаем один раз на адрес, а не на каждый рендер.
  const article = useMemo(() => (open ? helpFor(path).article : null), [open, path])
  const levels = article ? filledLevels(article.levels) : []
  const hasLevels = article !== null && article.group !== 'start' && article.group !== 'glossary'
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
          {/* Справа от заголовка остаётся место под вопросик: он лежит поверх угла панели. */}
          <div className="flex items-start justify-between gap-2 border-b border-grid py-3 pr-14 pl-4">
            <div className="min-w-0">
              <h2 ref={headingRef} tabIndex={-1} className="text-sm font-semibold text-text outline-none">{article.title}</h2>
              {article.where && (
                <p className="mt-1 text-xs text-text-secondary">
                  Где: {article.where}
                  {hasLevels && levels.length > 0 && <> · Кому: {levels[0].label}</>}
                </p>
              )}
            </div>
            <button type="button" onClick={onClose} aria-label="Закрыть справку" className={cn('rounded p-1 text-text-secondary hover:bg-row-hover hover:text-text', FOCUS)}>
              <X size={16} aria-hidden />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-4 py-3 text-xs">
            {what && (
              <section className="mb-4">
                <div className={BLOCK_TITLE}>Что это</div>
                <Markdown source={what} />
              </section>
            )}
            {hasLevels && levels.length > 0 && (
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
            )}
            {article.concepts.length > 0 && (
              <section className="mb-2">
                <div className={BLOCK_TITLE}>Понятия</div>
                <ul className="flex flex-wrap gap-1.5">
                  {article.concepts.map((slug) => (
                    <li key={slug}>
                      <Link to={`/help/${slug}`} className={cn('inline-block rounded-full border border-grid px-2.5 py-0.5 text-text hover:bg-row-hover', FOCUS)}>
                        {BY_SLUG.get(slug)?.title ?? slug}
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>

          <div className="border-t border-grid px-4 py-3 text-sm">
            <Link to={`/help/${article.slug}`} className={cn('text-text underline hover:no-underline', FOCUS)}>Вся справка →</Link>
          </div>
        </>
      )}
    </aside>
  )
}
