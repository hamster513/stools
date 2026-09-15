/**
 * Оформление интерфейса. Хозяин темы — профиль на сервере (`/api/auth/me`),
 * чтобы выбор переезжал за учёткой в другой браузер. Но ответ приходит
 * не сразу, а экран нужно покрасить до первого кадра — иначе выбравший
 * светлую каждый раз получает вспышку тёмного. Поэтому последняя
 * применённая тема дублируется в localStorage и применяется ещё до
 * рендера (main.tsx), а ответ сервера её потом подтверждает или
 * поправляет (ThemeSync в App.tsx).
 */

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'stools-theme'

/** Красит документ и запоминает выбор для следующего запуска. */
export function applyTheme(theme: Theme): void {
  // Тёмная — умолчание самого CSS, атрибут для неё только мешал бы читать разметку.
  if (theme === 'dark') delete document.documentElement.dataset.theme
  else document.documentElement.dataset.theme = theme
  localStorage.setItem(STORAGE_KEY, theme)
}

/** Тема прошлого сеанса; null — человек ещё не выбирал. */
export function readStoredTheme(): Theme | null {
  const stored = localStorage.getItem(STORAGE_KEY)
  return stored === 'dark' || stored === 'light' ? stored : null
}
