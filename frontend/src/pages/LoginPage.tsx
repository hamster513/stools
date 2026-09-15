import { useState, type FormEvent } from 'react'
import { LogIn, Shield } from 'lucide-react'
import { useLogin, useOidcStatus } from '@/api/auth'
import { ApiRequestError } from '@/api/client'
import { useRouter, useSearchParams } from '@/lib/router'
import { Button } from '@/components/ui/Button'

/**
 * Коды отказа, с которыми провайдер возвращает человека на `/login`.
 * Незнакомый код — тоже отказ: показываем общий текст, а не пустоту.
 */
const OIDC_ERRORS: Record<string, string> = {
  oidc_unavailable: 'Провайдер входа недоступен',
  oidc_state: 'Сессия входа устарела, попробуйте снова',
  oidc_denied: 'Провайдер отклонил вход',
  oidc_token: 'Провайдер вернул недействительный ответ',
  oidc_no_role: 'Вашим группам не назначена роль в STools — обратитесь к администратору',
  oidc_login_taken: 'Локальная учётка с таким логином уже есть — обратитесь к администратору',
  blocked: 'Учётка заблокирована',
}

export function LoginPage() {
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const loginMutation = useLogin()
  const oidc = useOidcStatus()
  const params = useSearchParams()
  const { navigate } = useRouter()

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    loginMutation.mutate(
      { login, password },
      { onSuccess: () => navigate('/', { replace: true }) },
    )
  }

  const code = params.get('error')
  const formError =
    loginMutation.error instanceof ApiRequestError ? loginMutation.error.message : loginMutation.error ? 'Не удалось войти' : null

  // Отказ провайдера показывается там же, где отказ по паролю: одно место,
  // куда человек смотрит после неудачи. Свежая попытка по паролю важнее —
  // она объясняет, чем кончилось последнее действие, а не предыдущее.
  const error =
    formError ?? (code ? (OIDC_ERRORS[code] ?? 'Не удалось войти через провайдера') : null)

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-app-bg">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded border border-grid bg-surface p-6">
        <div className="mb-6 flex items-center gap-2">
          <Shield size={20} className="text-primary" aria-hidden />
          <span className="text-base font-semibold text-text">Security Tools</span>
        </div>

        {/* Пока состояние провайдера неизвестно, кнопки нет вовсе: мигнувшая
            неактивная кнопка хуже, чем её отсутствие. Ссылка обычная, не
            Link, — переход должен уйти на сервер, а не в роутер. */}
        {oidc.data?.enabled && (
          <div className="mb-4">
            <a
              href="/api/auth/oidc/start"
              className="inline-flex w-full items-center justify-center gap-1.5 rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-text hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2 focus-visible:ring-offset-app-bg"
            >
              <LogIn size={14} aria-hidden />
              Войти через {oidc.data.display_name}
            </a>
            <div className="mt-4 flex items-center gap-3">
              <span className="h-px flex-1 bg-grid" aria-hidden />
              <span className="text-xs text-text-secondary">или по паролю</span>
              <span className="h-px flex-1 bg-grid" aria-hidden />
            </div>
          </div>
        )}

        <div className="flex flex-col gap-4">
          <label className="flex flex-col gap-1.5">
            <span className="text-xs font-medium text-text-secondary">Логин</span>
            <input
              autoFocus
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              className="rounded border border-border bg-app-bg px-3 py-2 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              autoComplete="username"
              name="login"
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-xs font-medium text-text-secondary">Пароль</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded border border-border bg-app-bg px-3 py-2 text-sm text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              autoComplete="current-password"
              name="password"
            />
          </label>

          {error && (
            <p role="alert" className="text-xs text-kind-1">
              {error}
            </p>
          )}

          <Button type="submit" variant="primary" loading={loginMutation.isPending} disabled={!login || !password}>
            Войти
          </Button>
        </div>
      </form>
    </div>
  )
}
