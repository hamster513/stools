import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App.tsx'
import { applyTheme, readStoredTheme } from '@/lib/theme'
import './index.css'

// До первого кадра: иначе выбравший светлую тему видит вспышку тёмной,
// пока не ответит /api/auth/me.
applyTheme(readStoredTheme() ?? 'dark')

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      retry: 1,
    },
  },
})

/**
 * Бэкенда пока нет: в dev-режиме поднимаем MSW и отвечаем на /api/* по
 * контракту (docs/api-contract.md). Чтобы работать против настоящего
 * бэкенда, выставьте VITE_USE_MOCKS=false в .env — тогда воркер не
 * стартует и запросы уходят как есть.
 */
async function enableMocking() {
  if (import.meta.env.VITE_USE_MOCKS === 'false') return
  if (!import.meta.env.DEV) return
  const { worker } = await import('@/modules/siem/mocks/browser')
  await worker.start({ onUnhandledRequest: 'bypass' })
}

enableMocking().then(() => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  )
})
