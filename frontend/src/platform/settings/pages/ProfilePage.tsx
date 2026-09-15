import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, Moon, Save, Sun } from 'lucide-react'
import { useChangePassword, useMe, usePatchMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { cn } from '@/lib/cn'
import { useThemeChoice } from '@/lib/useThemeChoice'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { ROLE_TITLES } from '@/platform/settings/api/types'

const MIN_PASSWORD = 8

const THEMES = [
  { value: 'dark', label: 'Тёмная', icon: Moon },
  { value: 'light', label: 'Светлая', icon: Sun },
] as const

/**
 * Единственный раздел настроек, открытый всем ролям: имя, под которым
 * человека видят остальные, и собственный пароль. Роль здесь только
 * показана — меняет её администратор в разделе пользователей.
 */
export function ProfilePage() {
  const me = useMe()
  const patch = usePatchMe()
  const change = useChangePassword()
  const appearance = useThemeChoice()

  const [name, setName] = useState('')
  const [nameSaved, setNameSaved] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')

  // Начатая правка имени важнее свежих данных: запрос ['me'] общий на всю
  // оболочку и перечитывается сам — по возврату фокуса в окно, например, —
  // а поле под курсором от этого меняться не должно. Признак правки в
  // ref, а не в состоянии: иначе сброс после сохранения перерисовал бы
  // поле старым именем, пока не доедет ответ на перечитывание.
  const edited = useRef(false)

  useEffect(() => {
    if (me.data && !edited.current) setName(me.data.display_name ?? '')
  }, [me.data])

  if (me.isError) {
    return (
      <div className="p-6">
        <ErrorState
          message={me.error?.message ?? 'Не удалось загрузить профиль'}
          onRetry={() => me.refetch()}
        />
      </div>
    )
  }
  if (!me.data) return <FullPageSpinner />

  function editName(value: string) {
    edited.current = true
    setNameSaved(false)
    setName(value)
  }

  function saveName() {
    const trimmed = name.trim()
    patch.mutate(
      { display_name: trimmed === '' ? null : trimmed },
      {
        onSuccess: () => {
          edited.current = false
          setNameSaved(true)
        },
      },
    )
  }

  // Повтор ловит опечатку в пароле, который никто не увидит: ошибиться
  // в нём — значит остаться без входа.
  const passwordReady = next.length >= MIN_PASSWORD && next === repeat && current.length > 0

  function changePassword() {
    change.mutate(
      { current, new: next },
      {
        onSuccess: () => {
          setCurrent('')
          setNext('')
          setRepeat('')
        },
      },
    )
  }

  function editPassword(set: (value: string) => void, value: string) {
    change.reset()
    set(value)
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-text">Мой профиль</h1>
        <p className="font-mono text-xs text-text-secondary">
          {me.data.login} · {ROLE_TITLES[me.data.role]}
        </p>
      </div>

      <div className="grid max-w-4xl gap-5 lg:grid-cols-2">
        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Имя</h2>
          <p className="mb-4 text-xs text-text-secondary">
            Так вас подписывают в журнале действий и в изменениях разметки. Пусто — останется логин.
          </p>

          <div className="grid gap-3">
            <Field label="Имя">
              <input
                className={FIELD}
                value={name}
                onChange={(e) => editName(e.target.value)}
                placeholder="Иван Петров"
              />
            </Field>
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={saveName} loading={patch.isPending}>
                <Save size={14} aria-hidden />
                Сохранить
              </Button>
              {nameSaved && (
                <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                  <CheckCircle2 size={14} aria-hidden />
                  сохранено
                </span>
              )}
            </div>
            {patch.isError && (
              <p className="text-xs text-kind-1">{patch.error.message}</p>
            )}
          </div>
        </section>

        <section className="rounded border border-grid bg-surface p-4">
          <h2 className="mb-1 text-sm font-semibold text-text">Тема</h2>
          <p className="mb-4 text-xs text-text-secondary">
            Тёмная — для долгой работы за экраном, светлая — для яркого света и проектора.
            Выбор хранится в учётке и переезжает за вами в другой браузер.
          </p>

          <div className="flex items-center gap-2">
            {THEMES.map(({ value, label, icon: Icon }) => {
              const active = appearance.theme === value
              return (
                <button
                  key={value}
                  type="button"
                  aria-pressed={active}
                  onClick={() => appearance.choose(value)}
                  className={cn(
                    'inline-flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring',
                    active
                      ? 'border-primary bg-primary text-primary-text'
                      : 'border-border text-text hover:bg-row-hover',
                  )}
                >
                  <Icon size={14} aria-hidden />
                  {label}
                </button>
              )
            })}
          </div>
          {appearance.error && <p className="mt-3 text-xs text-kind-1">{appearance.error}</p>}
        </section>

        {/* У учётки провайдера пароля в STools нет: форма, которой сервер
            всегда отвечает отказом, обещает то, чего не бывает. */}
        {me.data.auth_source === 'oidc' ? (
          <section className="rounded border border-grid bg-surface p-4">
            <h2 className="mb-1 text-sm font-semibold text-text">Пароль</h2>
            <p className="text-xs text-text-secondary">Пароль задаётся в провайдере входа.</p>
          </section>
        ) : (
          <section className="rounded border border-grid bg-surface p-4">
            <h2 className="mb-1 text-sm font-semibold text-text">Смена пароля</h2>
            <p className="mb-4 text-xs text-text-secondary">
              Текущий пароль подтверждает, что за клавиатурой хозяин учётки. Новый — не короче{' '}
              {MIN_PASSWORD} символов.
            </p>

            <div className="grid gap-3">
              <Field label="Текущий пароль">
                <input
                  className={FIELD}
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => editPassword(setCurrent, e.target.value)}
                />
              </Field>
              <Field label="Новый пароль">
                <input
                  className={FIELD}
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  onChange={(e) => editPassword(setNext, e.target.value)}
                />
              </Field>
              <Field
                label="Повторите новый пароль"
                hint={repeat !== '' && next !== repeat ? 'Повтор не совпадает с новым паролем' : undefined}
              >
                <input
                  className={FIELD}
                  type="password"
                  autoComplete="new-password"
                  value={repeat}
                  onChange={(e) => editPassword(setRepeat, e.target.value)}
                />
              </Field>
              <div className="flex items-center gap-3">
                <Button
                  variant="primary"
                  onClick={changePassword}
                  loading={change.isPending}
                  disabled={!passwordReady}
                >
                  Сменить пароль
                </Button>
                {change.isSuccess && (
                  <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                    <CheckCircle2 size={14} aria-hidden />
                    пароль изменён
                  </span>
                )}
              </div>
              {change.isError && <p className="text-xs text-kind-1">{change.error.message}</p>}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
