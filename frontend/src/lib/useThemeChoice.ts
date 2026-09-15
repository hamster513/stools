/**
 * Переключение темы из интерфейса. Общее для двух мест, откуда её меняют:
 * значка на рейке модулей и строки в профиле.
 *
 * Красим сразу, не дожидаясь ответа: переключатель оформления, который
 * думает полсекунды, ощущается сломанным. Если сервер отказал — красим
 * обратно, иначе экран и профиль разошлись бы молча.
 */
import { useMe, usePatchMe } from '@/api/auth'
import { applyTheme, readStoredTheme, type Theme } from '@/lib/theme'

export function useThemeChoice() {
  const me = useMe()
  const patch = usePatchMe()

  // Пока профиль не доехал, показываем то, чем уже покрашен документ.
  const theme: Theme = me.data?.theme ?? readStoredTheme() ?? 'dark'

  function choose(next: Theme) {
    if (next === theme) return
    const previous = theme
    applyTheme(next)
    patch.mutate({ theme: next }, { onError: () => applyTheme(previous) })
  }

  return { theme, choose, error: patch.isError ? patch.error.message : null }
}
