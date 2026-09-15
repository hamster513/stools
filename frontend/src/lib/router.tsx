/**
 * Минимальный клиентский роутер поверх History API. Отдельного пакета
 * маршрутизации в стеке нет — экранов немного, велосипед оправдан.
 *
 * Файл намеренно экспортирует и компоненты, и хуки/утилиты — это не
 * компонентный модуль, поэтому предупреждение react-refresh об этом ниже
 * не устраняем.
 */
/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  use,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type AnchorHTMLAttributes,
  type ReactNode,
} from 'react'

interface RouterValue {
  path: string
  search: string
  navigate: (to: string, opts?: { replace?: boolean }) => void
}

const RouterContext = createContext<RouterValue | null>(null)

function readLocation() {
  return { path: window.location.pathname, search: window.location.search }
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(readLocation)

  useEffect(() => {
    const onPopState = () => setLocation(readLocation())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    if (opts?.replace) {
      window.history.replaceState({}, '', to)
    } else {
      window.history.pushState({}, '', to)
    }
    setLocation(readLocation())
  }, [])

  const value = useMemo(() => ({ path: location.path, search: location.search, navigate }), [location, navigate])

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

export function useRouter(): RouterValue {
  const ctx = use(RouterContext)
  if (!ctx) throw new Error('useRouter вызван вне RouterProvider')
  return ctx
}

/** Параметры строки запроса текущего пути, например `?scoped=1`. */
export function useSearchParams(): URLSearchParams {
  const { search } = useRouter()
  return useMemo(() => new URLSearchParams(search), [search])
}

/** Сопоставляет путь с шаблоном вида `/snapshots/:id/rules`. */
export function matchPath(pattern: string, path: string): Record<string, string> | null {
  const patternParts = pattern.split('/').filter(Boolean)
  const pathParts = path.split('/').filter(Boolean)
  if (patternParts.length !== pathParts.length) return null
  const params: Record<string, string> = {}
  for (let i = 0; i < patternParts.length; i++) {
    const part = patternParts[i]
    if (part.startsWith(':')) {
      params[part.slice(1)] = decodeURIComponent(pathParts[i])
    } else if (part !== pathParts[i]) {
      return null
    }
  }
  return params
}

/**
 * Остальные атрибуты якоря (title, aria-current, aria-label) уходят в <a>
 * как есть: навигация должна быть доступной, а не только кликабельной.
 */
interface LinkProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href' | 'onClick'> {
  to: string
  children: ReactNode
  onNavigate?: () => void
}

export function Link({ to, children, onNavigate, ...rest }: LinkProps) {
  const { navigate } = useRouter()
  return (
    <a
      href={to}
      {...rest}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
        e.preventDefault()
        navigate(to)
        onNavigate?.()
      }}
    >
      {children}
    </a>
  )
}

/**
 * Переход как элемент дерева. Навигация — побочный эффект, поэтому в
 * useEffect, а не при отрисовке; кадр до перехода остаётся пустым.
 */
export function Redirect({ to }: { to: string }) {
  const { navigate } = useRouter()
  useEffect(() => {
    navigate(to, { replace: true })
  }, [to, navigate])
  return null
}
