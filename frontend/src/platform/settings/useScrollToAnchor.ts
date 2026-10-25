import { useEffect } from 'react'

/** Сколько держать секцию у верха, пока страница догружается. */
const FOLLOW_MS = 5000
const USER_INPUT = ['wheel', 'touchstart', 'keydown', 'mousedown'] as const

/**
 * Прокрутка к секции из `#якоря` адреса: сводка «Данные» ведёт на
 * /settings/<модуль>#<секция>. Роутер хеш не читает, поэтому страница
 * зовёт хук сама, когда её секции уже отрисованы (`ready`). Смена хеша
 * без ухода со страницы (назад/вперёд) прокручивает снова.
 *
 * Секции грузят свои данные сами: нужной может ещё не быть, а секции
 * выше растут уже после прокрутки. Поэтому после каждой перемены в DOM
 * прокрутка повторяется — до первого действия пользователя или FOLLOW_MS.
 */
export function useScrollToAnchor(ready: boolean): void {
  useEffect(() => {
    if (!ready) return
    let release = () => {}

    const follow = () => {
      release()
      const id = decodeURIComponent(window.location.hash.slice(1))
      if (!id) return
      // Ищем по id каждый раз: секция появляется позже или перерисовывается другим элементом.
      const scroll = () => document.getElementById(id)?.scrollIntoView({ block: 'start' })
      scroll()
      const observer = new MutationObserver(scroll)
      observer.observe(document.body, { childList: true, subtree: true, characterData: true })
      const timer = window.setTimeout(() => release(), FOLLOW_MS)
      const stop = () => release()
      for (const e of USER_INPUT) window.addEventListener(e, stop, { passive: true })
      release = () => {
        observer.disconnect()
        window.clearTimeout(timer)
        for (const e of USER_INPUT) window.removeEventListener(e, stop)
        release = () => {}
      }
    }

    follow()
    window.addEventListener('hashchange', follow)
    return () => {
      window.removeEventListener('hashchange', follow)
      release()
    }
  }, [ready])
}
