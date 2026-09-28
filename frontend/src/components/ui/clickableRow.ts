import type { KeyboardEvent } from 'react'

/** Класс видимого фокуса для строк-кнопок: только при навигации с клавиатуры. */
export const ROW_FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring'

/**
 * Свойства строки таблицы, которую можно открыть и мышью, и клавиатурой:
 * Enter и Пробел делают ровно то же, что щелчок. Нажатия во вложенных
 * элементах (ссылках, кнопках) строка не перехватывает.
 */
export function clickableRow(onActivate: () => void) {
  return {
    role: 'button' as const,
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
      if (e.target !== e.currentTarget) return
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        // Иначе Enter долетит до обработчиков страниц на document, которые
        // откроют ранее выбранную строку, а не эту.
        e.stopPropagation()
        onActivate()
      }
    },
  }
}
