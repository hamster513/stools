import { useState } from 'react'
import { CheckCircle2, KeyRound, Lock, LockOpen, Trash2, UserPlus, UsersRound } from 'lucide-react'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { Field, FIELD } from '@/components/ui/Field'
import { FullPageSpinner } from '@/components/ui/Spinner'
import { useCan } from '@/lib/can'
import { Link } from '@/lib/router'
import { LEVEL_TITLES, PLATFORM_LEVEL_TITLES, type Area } from '@/platform/access/types'
import { MODULES } from '@/platform/modules'
import { useGroups, type GroupRow } from '@/platform/settings/api/access'
import {
  useCreateUser,
  useDeleteUser,
  usePatchUser,
  useSetUserPassword,
  useUsers,
} from '@/platform/settings/api/queries'
import { MIN_PASSWORD, type UserRow } from '@/platform/settings/api/types'
import { ColGroup, ResizableHeader } from '@/platform/table/ResizableHeader'
import { useColumnWidths, type ColumnDef } from '@/platform/table/useColumnWidths'
import { ExportButton } from '@/platform/filters/ExportButton'

const OWN_ROW = 'Себя изменить нельзя'
const LAST_ADMIN = 'Последний администратор'

const CELL = 'py-1.5 pr-3 align-top'

const COLUMNS_BEFORE: ColumnDef[] = [
  { key: 'login', label: 'Логин', width: 112 },
  { key: 'name', label: 'Имя', width: 120, flex: true },
  { key: 'groups', label: 'Группы', width: 200 },
  { key: 'source', label: 'Вход', width: 64 },
  { key: 'state', label: 'Состояние', width: 104 },
  { key: 'last_login', label: 'Последний вход', width: 120 },
]

// Без права менять колонки с кнопками нет вовсе.
const COLUMNS: ColumnDef[] = [
  ...COLUMNS_BEFORE,
  { key: 'actions', label: 'Действия', width: 288, resizable: false, align: 'right' },
]

/** «SIEM: Аналитик · VM: Аудитор · Платформа: Администратор». Области без доступа пропущены. */
function accessLine(access: UserRow['access']): string {
  const title = (area: Area) => {
    const level = access[area]
    return area === 'platform' && level !== 'write' ? PLATFORM_LEVEL_TITLES[level] : LEVEL_TITLES[level]
  }
  const areas: Array<[Area, string]> = [
    ...MODULES.map((m) => [m.id as Area, m.code] as [Area, string]),
    ['platform', 'Платформа'],
  ]
  const parts = areas
    .filter(([area]) => access[area] !== undefined && access[area] !== 'deny')
    .map(([area, label]) => {
      const t = title(area)
      return `${label}: ${t.charAt(0).toUpperCase()}${t.slice(1)}`
    })
  return parts.length > 0 ? parts.join(' · ') : 'нет доступа'
}

/** Локальные группы чекбоксами; oidc сюда не попадают — их состав собирает вход. */
function GroupPicker({
  groups,
  selected,
  onChange,
}: {
  groups: GroupRow[] | undefined
  selected: number[]
  onChange: (ids: number[]) => void
}) {
  if (!groups) return <p className="text-xs text-text-secondary">Загрузка групп…</p>
  const local = groups.filter((g) => g.source === 'local')
  if (local.length === 0) {
    return (
      <p className="text-xs text-text-secondary">
        Локальных групп нет — создайте их в разделе{' '}
        <Link to="/settings/access/groups" className="text-primary hover:underline">
          Группы
        </Link>
        .
      </p>
    )
  }
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
      {local.map((g) => (
        <label key={g.id} className="flex items-center gap-1.5 text-xs text-text" title={`Роль: ${g.role_name}`}>
          <input
            type="checkbox"
            checked={selected.includes(g.id)}
            onChange={(e) => onChange(e.target.checked ? [...selected, g.id] : selected.filter((id) => id !== g.id))}
          />
          {g.name}
        </label>
      ))}
    </div>
  )
}

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
  const groups = useGroups()
  const admin = useCan().platform.admin

  const [adding, setAdding] = useState(false)
  const [login, setLogin] = useState('')
  const [name, setName] = useState('')
  const [groupIds, setGroupIds] = useState<number[]>([])
  const [newPassword, setNewPassword] = useState('')

  // Сброс пароля раскрывается для одной строки: два открытых поля рядом —
  // верный способ задать пароль не тому человеку.
  const [resetFor, setResetFor] = useState<number | null>(null)
  const [resetValue, setResetValue] = useState('')
  const [resetDone, setResetDone] = useState<number | null>(null)
  // Группы строки правятся в раскрытой под ней панели и уходят одним запросом: на каждый
  // щелчок по галочке сервер ответил бы отказом там, где правка в целом допустима.
  const [groupsFor, setGroupsFor] = useState<number | null>(null)
  const [groupsDraft, setGroupsDraft] = useState<number[]>([])
  const cols = useColumnWidths('settings-users-columns', admin ? COLUMNS : COLUMNS_BEFORE)
  const span = admin ? COLUMNS.length : COLUMNS_BEFORE.length

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
  const activeAdmins = rows.filter((u) => u.access.platform === 'admin' && u.is_active).length

  /** Почему строку нельзя менять, или null, если можно. */
  function locked(row: UserRow): string | null {
    if (me.data?.login === row.login) return OWN_ROW
    if (row.access.platform === 'admin' && row.is_active && activeAdmins === 1) return LAST_ADMIN
    return null
  }

  function addUser() {
    const trimmed = name.trim()
    create.mutate(
      { login: login.trim(), display_name: trimmed === '' ? null : trimmed, group_ids: groupIds, password: newPassword },
      {
        onSuccess: () => {
          setAdding(false)
          setLogin('')
          setName('')
          setGroupIds([])
          setNewPassword('')
        },
      },
    )
  }

  function openGroups(row: UserRow) {
    patch.reset()
    setResetFor(null)
    if (groupsFor === row.id) {
      setGroupsFor(null)
      return
    }
    setGroupsDraft(row.groups.filter((g) => g.source === 'local').map((g) => g.id))
    setGroupsFor(row.id)
  }

  function applyGroups(id: number) {
    patch.mutate({ id, patch: { group_ids: groupsDraft } }, { onSuccess: () => setGroupsFor(null) })
  }

  function openReset(id: number) {
    setGroupsFor(null)
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
  // Отказ по группам показан в самой панели, остальные — здесь.
  const failure = [groupsFor === null ? patch.error : null, remove.error, password.error].find((e) => e != null)

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-text">Пользователи</h1>
            <ExportButton href={(fmt) => `/api/settings/users/export?format=${fmt}`} total={users.data?.length} disabled={users.isLoading} />
          </div>
          <p className="max-w-2xl text-xs text-text-secondary">
            Права учётки складываются из ролей её групп: при нескольких группах побеждает старший
            уровень в каждом модуле. Сами группы и роли настраиваются в одноимённых разделах.
          </p>
        </div>
        {admin ? (
          <Button variant="primary" onClick={() => setAdding((v) => !v)}>
            <UserPlus size={14} aria-hidden />
            Добавить пользователя
          </Button>
        ) : (
          <span className="text-xs text-text-secondary">только чтение</span>
        )}
      </div>

      {admin && adding && (
        <section className="mb-5 max-w-4xl rounded border border-grid bg-surface p-4">
          <h2 className="mb-4 text-sm font-semibold text-text">Новый пользователь</h2>
          <div className="grid gap-3 sm:grid-cols-3">
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
          <div className="mt-3">
            <span className="mb-1 block text-xs font-medium text-text">Группы</span>
            <GroupPicker groups={groups.data} selected={groupIds} onChange={setGroupIds} />
            <span className="mt-1 block text-xs text-text-secondary">Без групп учётка войдёт, но доступа не получит</span>
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

      <div className="overflow-x-auto">
        <table className="w-full max-w-6xl text-xs" style={cols.tableStyle}>
          <ColGroup cols={cols} />
          <thead>
            <tr className="border-b border-grid text-left text-[11px] tracking-wide text-text-secondary uppercase">
              <ResizableHeader cols={cols} className="py-1.5 pr-3" />
            </tr>
          </thead>
          {rows.map((row) => {
            const why = locked(row)
            return (
              <tbody key={row.id} className="border-b border-grid hover:bg-row-hover">
                <tr>
                  <td className={`${CELL} font-mono break-all text-text`}>{row.login}</td>
                  <td className={`${CELL} break-words text-text`}>{row.display_name ?? '—'}</td>
                  <td className={CELL}>
                    {row.groups.length === 0 ? (
                      <span className="text-text-secondary">—</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {row.groups.map((g) => (
                          <span
                            key={g.id}
                            className="rounded border border-grid px-1.5 py-0.5 text-[11px] break-all text-text"
                            title={g.source === 'oidc' ? 'Группа из OIDC: состав обновляется при входе' : undefined}
                          >
                            {g.name}
                            {g.source === 'oidc' && <span className="ml-1 text-text-secondary">OIDC</span>}
                          </span>
                        ))}
                      </div>
                    )}
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
                  {admin && (
                    <td className="py-1.5 align-top">
                      <div className="flex flex-wrap items-center justify-end gap-1">
                        <Button variant="ghost" onClick={() => openGroups(row)}>
                          <UsersRound size={14} aria-hidden />
                          Группы…
                        </Button>
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
                  )}
                </tr>
                <tr>
                  <td colSpan={span} className="pr-3 pb-2 text-[11px] text-text-secondary">
                    <span className="font-medium">Итоговые права:</span> {accessLine(row.access)}
                  </td>
                </tr>
                {admin && groupsFor === row.id && (
                  <tr className="bg-surface">
                    <td colSpan={span} className="px-1 py-2">
                      <div className="mb-2 text-xs text-text-secondary">
                        Локальные группы {row.login}. Группы из OIDC здесь не меняются: их состав обновляется при входе.
                      </div>
                      <GroupPicker groups={groups.data} selected={groupsDraft} onChange={setGroupsDraft} />
                      <div className="mt-2 flex items-center gap-2">
                        <Button variant="primary" loading={patch.isPending} onClick={() => applyGroups(row.id)}>
                          Сохранить
                        </Button>
                        <Button onClick={() => setGroupsFor(null)}>Отмена</Button>
                        {patch.isError && <span className="text-xs text-kind-1">{patch.error.message}</span>}
                      </div>
                    </td>
                  </tr>
                )}
                {admin && resetFor === row.id && (
                  <tr className="bg-surface">
                    <td colSpan={span} className="px-1 py-2">
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
                  <tr>
                    <td colSpan={span} className="px-1 py-2 text-right">
                      <span className="inline-flex items-center gap-1.5 text-xs text-kind-accepted">
                        <CheckCircle2 size={14} aria-hidden />
                        пароль задан, сессии пользователя закрыты
                      </span>
                    </td>
                  </tr>
                )}
              </tbody>
            )
          })}
        </table>
      </div>

      {failure && <p className="mt-3 text-xs text-kind-1">{failure.message}</p>}
    </div>
  )
}
