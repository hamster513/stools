import { useEffect } from 'react'

/** Сколько держать секцию у верха, пока страница догружается. */
const FOLLOW_MS = 5000
const USER_INPUT = ['wheel', 'touchstart', 'keydown', 'mousedown'] as const

function scrollParent(el: HTMLElement): HTMLElement | null {
  for (let p = el.parentElement; p; p = p.parentElement) {
    const { overflowY } = getComputedStyle(p)
    if (overflowY === 'auto' || overflowY === 'scroll') return p
  }
  return null
}

/**
 * Прокрутка к секции из `#якоря` адреса: сводка «Данные» ведёт на
 * /settings/<модуль>#<секция>. Роутер хеш не читает, поэтому страница
 * зовёт хук сама, когда её секции уже отрисованы (`ready`). Смена хеша
 * без ухода со страницы (назад/вперёд) прокручивает снова.
 *
 * Секции грузят свои данные сами и растут уже после прокрутки — тогда
 * нужная уезжает вниз. Поэтому, пока страница меняет высоту, секция
 * удерживается у верха: до первого действия пользователя или FOLLOW_MS.
 */
export function useScrollToAnchor(ready: boolean): void {
  useEffect(() => {
    if (!ready) return
    let release = () => {}

    const follow = () => {
      release()
      const id = decodeURIComponent(window.location.hash.slice(1))
      const el = id ? document.getElementById(id) : null
      if (!el) return
      // Секция может перерисоваться другим элементом (загрузка → данные) — ищем по id каждый раз.
      const scroll = () => document.getElementById(id)?.scrollIntoView({ block: 'start' })
      scroll()
      const box = scrollParent(el)
      if (!box) return
      const observer = new ResizeObserver(scroll)
      for (const child of box.children) observer.observe(child)
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
