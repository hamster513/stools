import { Fragment, useState } from 'react'
import { CheckCircle2, KeyRound, Lock, LockOpen, Trash2, UserPlus } from 'lucide-react'
import type { Role } from '@/api/auth'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import {
  useCreateUser,
  useDeleteUser,
  usePatchUser,
  useSetUserPassword,
  useUsers,
} from '@/platform/settings/api/queries'
import { MIN_PASSWORD, ROLE_TITLES, type UserRow } from '@/platform/settings/api/types'

const ROLES: Role[] = ['admin', 'analyst', 'auditor']

const OWN_ROW = 'Себя изменить нельзя'
const LAST_ADMIN = 'Последний администратор'
// Роль учётки провайдера пересчитывается из групп при каждом входе:
// выбранная здесь продержалась бы до следующего входа и пропала.
const FROM_PROVIDER = 'Роль задаётся группами провайдера'

const CELL = 'py-1.5 pr-3'

/**
 * Учётные записи платформы. Те же две защиты, что и на сервере, но
 * заранее: себя нельзя понизить, заблокировать и удалить, и нельзя
 * оставить систему без активного администратора. Сервер всё равно
 * ответит отказом — но кнопка, которая в ответ ругается, хуже кнопки,
 * которая объясняет, почему она серая.
 */
export function UsersPage() {
  const me = useMe()
  const users = useUsers()
  const create = useCreateUser()
  const patch = usePatchUser()
  const remove = useDeleteUser()
  const password = useSetUserPassword()

  const [adding, setAdding] = useState(false)
  const [login, setLogin] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [newPassword, setNewPassword] = useState('')

  // Сброс пароля раскрывается для одной строки: два открытых поля рядом —
  // верный способ задать пароль не тому человеку.
  const [resetFor, setResetFor] = useState<number | null>(null)
  const [resetValue, setResetValue] = useState('')
  const [resetDone, setResetDone] = useState<number | null>(null)

  if (users.isLoading) return <FullPageSpinner />
  if (users.isError || !users.data) {
    return (
      <div className="p-6">
        <ErrorState
          message={users.error?.message ?? 'Не удалось загрузить пользователей'}
          onRetry={() => users.refetch()}
        />
      </div>
    )
  }

  const rows = users.data
  const activeAdmins = rows.filter((u) => u.role === 'admin' && u.is_active).length

  /** Почему строку нельзя менять, или null, если можно. */
  function locked(row: UserRow): string | null {
    if (me.data?.login === row.login) return OWN_ROW
    if (row.role === 'admin' && row.is_active && activeAdmins === 1) return LAST_ADMIN
    return null
  }

  function addUser() {
    const trimmed = name.trim()
    create.mutate(
      { login: login.trim(), display_name: trimmed === '' ? null : trimmed, role, password: newPassword },
      {
        onSuccess: () => {
          setAdding(false)
          setLogin('')
          setName('')
          setRole('analyst')
          setNewPassword('')
        },
      },
    )
  }

  function openReset(id: number) {
    password.reset()
    setResetDone(null)
    setResetValue('')
    setResetFor(resetFor === id ? null : id)
  }

  function applyReset(id: number) {
    password.mutate(
      { id, password: resetValue },
      {
        onSuccess: () => {
          setResetFor(null)
          setResetValue('')
          setResetDone(id)
        },
      },
    )
  }

  function removeUser(row: UserRow) {
    const who = row.display_name ? `${row.display_name} (${row.login})` : row.login
    if (!window.confirm(`Удалить пользователя ${who}? Его сессии будут закрыты.`)) return
    remove.mutate(row.id)
  }

  // Отказы сервера (409: себя нельзя, последний администратор) — одной
  // строкой под таблицей: кнопки уже серые, сюда попадают только те
  // случаи, о которых на клиенте знать было неоткуда.
  const failure = [patch.error, remove.error, password.error].find((e) => e != null)

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-base font-semibold text-text">Пользователи</h1>
          <p className="max-w-2xl text-xs text-text-secondary">
            Администратор настраивает продукт и заводит учётки, аналитик работает с выгрузками и
            разметкой, аудитор всё видит и ничего не меняет.
          </p>
        </div>
        <Button variant="primary" onClick={() => setAdding((v) => !v)}>
          <UserPlus size={14} aria-hidden />
          Добавить пользователя
        </Button>
      </div>

      {adding && (
        <section className="mb-5 max-w-4xl rounded border border-grid bg-surface p-4">
          <h2 className="mb-4 text-sm font-semibold text-text">Новый пользователь</h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Логин">
              <input
                className={FIELD}
                value={login}
                onChange={(e) => setLogin(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
            <Field label="Имя" hint="Пусто — останется логин">
              <input
                className={FIELD}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Иван Петров"
              />
            </Field>
            <Field label="Роль">
              <select
                className={FIELD}
                value={role}
                onChange={(e) => setRole(e.target.value as Role)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {ROLE_TITLES[r]}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Пароль" hint={`Не короче ${MIN_PASSWORD} символов`}>
              <input
                className={FIELD}
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </Field>
          </div>
          <div className="mt-3 flex items-center gap-3">
            <Button
              variant="primary"
              onClick={addUser}
              loading={create.isPending}
              disabled={login.trim() === '' || newPassword.length < MIN_PASSWORD}
            >
              Добавить
            </Button>
            <Button onClick={() => setAdding(false)}>Отмена</Button>
            {create.isError && <span className="text-xs text-kind-1">{create.error.message}</span>}
          </div>
        </section>
      )}

      <table className="w-full max-w-5xl text-xs">
        <thead>
          <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
            <th className={`${CELL} font-medium`}>Логин</th>
            <th className={`${CELL} font-medium`}>Имя</th>
            <th className={`${CELL} font-medium`}>Роль</th>
            <th className={`${CELL} font-medium`}>Вход</th>
            <th className={`${CELL} font-medium`}>Состояние</th>
            <th className={`${CELL} font-medium`}>Последний вход</th>
            <th className="py-2 text-right font-medium">Действия</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const why = locked(row)
            const roleWhy = row.auth_source === 'oidc' ? FROM_PROVIDER : why
            return (
              <Fragment key={row.id}>
                <tr className="border-b border-grid hover:bg-row-hover">
                  <td className={`${CELL} font-mono text-text`}>{row.login}</td>
                  <td className={`${CELL} text-text`}>{row.display_name ?? '—'}</td>
                  <td className={CELL}>
                    <select
                      className="rounded border border-border bg-app-bg px-1.5 py-1 text-xs text-text disabled:cursor-not-allowed disabled:opacity-50"
                      value={row.role}
                      disabled={roleWhy !== null}
                      title={roleWhy ?? undefined}
                      aria-label={`Роль пользователя ${row.login}`}
                      onChange={(e) =>
                        patch.mutate({ id: row.id, patch: { role: e.target.value as Role } })
                      }
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {ROLE_TITLES[r]}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className={`${CELL} text-text-secondary`}>
                    {row.auth_source === 'oidc' ? 'FAM' : 'пароль'}
                  </td>
                  <td className={CELL}>
                    <span className={row.is_active ? 'text-kind-accepted' : 'text-kind-1'}>
                      {row.is_active ? 'активен' : 'заблокирован'}
                    </span>
                  </td>
                  <td className={`${CELL} tabular-nums text-text-secondary`}>
                    {row.last_login_at
                      ? new Date(row.last_login_at).toLocaleString('ru-RU')
                      : 'не входил'}
                  </td>
                  <td className="py-1.5">
                    <div className="flex items-center justify-end gap-1">
                      {/* У учётки провайдера пароля нет — сбрасывать нечего. */}
                      {row.auth_source === 'local' && (
                        <Button variant="ghost" onClick={() => openReset(row.id)}>
                          <KeyRound size={14} aria-hidden />
                          сбросить пароль
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        disabled={row.is_active && why !== null}
                        title={row.is_active ? (why ?? undefined) : undefined}
                        onClick={() =>
                          patch.mutate({ id: row.id, patch: { is_active: !row.is_active } })
                        }
                      >
                        {row.is_active ? <Lock size={14} aria-hidden /> : <LockOpen size={14} aria-hidden />}
                        {row.is_active ? 'заблокировать' : 'разблокировать'}
                      </Button>
                      <Button
                        variant="ghost"
                        disabled={why !== null}
                        title={why ?? undefined}
                        onClick={() => removeUser(row)}
                      >
                        <Trash2 size={14} aria-hidden />
                        удалить
                      </Button>
                    </div>
                  </td>
                </tr>
                {resetFor === row.id && (
                  <tr className="border-b border-grid bg-surface">
                    <td colSpan={7} className="px-1 py-2">
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <label className="text-xs text-text-secondary" htmlFor={`pw-${row.id}`}>
                          Новый пароль для {row.login}, не короче {MIN_PASSWORD} символов
                        </label>
                        <div className="w-56">
                          <input
                            id={`pw-${row.id}`}
                            className={FIELD}
                            type="password"
                            autoComplete="new-password"
                            value={resetValue}
                            onChange={(e) => setResetValue(e.target.value)}
                          />
                        </div>
                        <Button
                          variant="primary"
                          loading={password.isPending}
                          disabled={resetValue.length < MIN_PASSWORD}
                          onClick={() => applyReset(row.id)}
                        >
                          Задать
                        </Button>
                      </div>
                    </td>
                  </tr>
                )}
                {resetDone === row.id && (
                  <tr className="border-b border-grid">
                    <td colSpan={7} className="px-1 py-2 text-right">
                      <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                        <CheckCircle2 size={14} aria-hidden />
                        пароль задан, сессии пользователя закрыты
                      </span>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>

      {failure && <p className="mt-3 text-xs text-kind-1">{failure.message}</p>}
    </div>
  )
}
