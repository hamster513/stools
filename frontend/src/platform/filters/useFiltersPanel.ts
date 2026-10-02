import { useState } from 'react'

/**
 * Правило платформы для каждого списка с фильтрами: боковая панель фильтров
 * по умолчанию скрыта и открывается кнопкой «Фильтры» (FiltersButton), а
 * выбранные фильтры при закрытой панели видны чипами (FilterChips) — фильтр,
 * пришедший из ссылки, не должен действовать незаметно. Новые страницы со
 * списками и фильтрами делаются так же. Открыта ли панель, помнится на
 * каждую страницу отдельно (`pageKey`) в localStorage этого браузера.
 */
export function useFiltersPanel(pageKey: string): { open: boolean; toggle: () => void } {
  const storageKey = `stools-filters-open:${pageKey}`
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(storageKey) === '1'
    } catch {
      return false
    }
  })
  function toggle() {
    const next = !open
    setOpen(next)
    try {
      localStorage.setItem(storageKey, next ? '1' : '0')
    } catch {
      // Хранилище недоступно (приватный режим, запрет сайта) — панель просто не запомнится.
    }
  }
  return { open, toggle }
}
